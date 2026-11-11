package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

const (
	projectBatchStartMaxProjects      = 500
	projectSessionInstructionMaxRunes = 20000
)

const defaultProjectSessionInstruction = "请对当前项目授权范围内的全部资产进行自主渗透测试。先读取项目目标、授权资产、事实黑板、攻击路径和已有漏洞，制定计划后持续执行测试与证据验证，并及时写回事实、测试覆盖和漏洞证据。直到目标完成、证据充分或存在明确技术阻断再结束。"

type projectBatchStartRequest struct {
	ProjectIDs  []string `json:"projectIds"`
	Instruction string   `json:"instruction"`
	RoleID      string   `json:"roleId"`
}

type projectBatchStartItem struct {
	ProjectID      string `json:"projectId,omitempty"`
	ProjectName    string `json:"projectName,omitempty"`
	ConversationID string `json:"conversationId,omitempty"`
	CampaignID     string `json:"campaignId,omitempty"`
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
}

type projectBatchStartResponse struct {
	Created        int                     `json:"created"`
	Started        int                     `json:"started"`
	Queued         int                     `json:"queued"`
	Skipped        int                     `json:"skipped"`
	Failed         int                     `json:"failed"`
	MaxConcurrency int                     `json:"maxConcurrency"`
	Items          []projectBatchStartItem `json:"items"`
}

func (h *ChatHandler) StartProjectsBatch(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request projectBatchStartRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_request", "批量启动请求格式错误")
		return
	}
	projectIDs := uniqueProjectBatchIDs(request.ProjectIDs)
	if len(projectIDs) == 0 {
		badRequest(c, "project_ids_required", "请至少选择一个项目")
		return
	}
	if len(projectIDs) > projectBatchStartMaxProjects {
		badRequest(c, "project_limit", "单次最多启动 500 个项目会话")
		return
	}
	roleID := ""
	if strings.TrimSpace(request.RoleID) != "" {
		resolved, ok := h.resolveRoleID(c.Request.Context(), request.RoleID)
		if !ok {
			badRequest(c, "invalid_agent_role", "角色不存在或未启用")
			return
		}
		roleID = resolved
	}

	instruction := strings.TrimSpace(request.Instruction)
	if instruction == "" {
		instruction = defaultProjectSessionInstruction
	}
	if len([]rune(instruction)) > projectSessionInstructionMaxRunes {
		badRequest(c, "instruction_too_large", "任务要求不能超过 20000 个字符")
		return
	}

	maxConcurrency := 5
	if h.manager != nil {
		maxConcurrency = h.manager.MaxPerUser()
	}
	active := map[string]interface{}{}
	if h.manager != nil {
		for conversationID := range h.manager.ActiveConversations(user.ID) {
			active[conversationID] = struct{}{}
		}
	}
	runningProjects := map[string]bool{}
	for conversationID := range active {
		conversation, err := h.db.GetConversation(
			c.Request.Context(),
			conversationID,
			user.ID,
		)
		if err == nil {
			runningProjects[conversation.ProjectID] = true
		}
	}
	availableSlots := maxConcurrency - len(active)
	if schedulerSlots := h.campaignScheduler().availableUserRunSlots(user.ID); schedulerSlots < availableSlots {
		availableSlots = schedulerSlots
	}
	if availableSlots < 0 {
		availableSlots = 0
	}

	result := projectBatchStartResponse{
		MaxConcurrency: maxConcurrency,
		Items:          make([]projectBatchStartItem, 0, len(projectIDs)),
	}
	for _, projectID := range projectIDs {
		project, err := h.db.GetActiveProject(c.Request.Context(), projectID, user.ID)
		if err != nil {
			result.Skipped++
			reason := "项目不存在"
			if errors.Is(err, database.ErrProjectInactive) {
				reason = "项目已停用"
			}
			result.Items = append(result.Items, projectBatchStartItem{
				ProjectID: projectID,
				Status:    "skipped",
				Reason:    reason,
			})
			continue
		}
		if runningProjects[project.ID] {
			result.Skipped++
			result.Items = append(result.Items, projectBatchStartItem{
				ProjectID:   project.ID,
				ProjectName: project.Name,
				Status:      "skipped",
				Reason:      "已有运行中的会话",
			})
			continue
		}
		hasUnfinished, err := h.db.ProjectHasUnfinishedCampaign(
			c.Request.Context(),
			project.ID,
			user.ID,
		)
		if err != nil {
			internalError(c, "check_project_campaign_failed", "检查项目后台会话失败")
			return
		}
		if hasUnfinished {
			result.Skipped++
			result.Items = append(result.Items, projectBatchStartItem{
				ProjectID:   project.ID,
				ProjectName: project.Name,
				Status:      "skipped",
				Reason:      "已有未结束的后台会话",
			})
			continue
		}
		assets, err := h.db.ListProjectAssets(c.Request.Context(), project.ID, user.ID)
		if err != nil {
			internalError(c, "list_project_assets_failed", "读取项目资产失败")
			return
		}
		if len(assets) == 0 {
			result.Skipped++
			result.Items = append(result.Items, projectBatchStartItem{
				ProjectID:   project.ID,
				ProjectName: project.Name,
				Status:      "skipped",
				Reason:      "没有可执行资产",
			})
			continue
		}

		now := time.Now().UTC()
		conversationID := randomID()
		campaignID := randomID()
		batch := database.ConversationBatch{
			ID:                   campaignID,
			OwnerUserID:          user.ID,
			ProjectID:            project.ID,
			ParentConversationID: conversationID,
			Title:                truncateRunes(project.Name+" · 渗透测试", 100),
			Instruction:          instruction,
			Total:                1,
			CreatedAt:            now,
			UpdatedAt:            now,
		}
		conversation := database.Conversation{
			ID:          conversationID,
			OwnerUserID: user.ID,
			ProjectID:   project.ID,
			AgentRoleID: roleID,
			Title:       fmt.Sprintf("%s · 渗透测试 %s", project.Name, now.Format("01-02 15:04")),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := h.db.CreateProjectSessionCampaign(
			c.Request.Context(),
			batch,
			conversation,
			instruction,
		); err != nil {
			if errors.Is(err, database.ErrProjectCampaignActive) {
				result.Skipped++
				result.Items = append(result.Items, projectBatchStartItem{
					ProjectID:   project.ID,
					ProjectName: project.Name,
					Status:      "skipped",
					Reason:      "已有未结束的后台会话",
				})
				continue
			}
			if errors.Is(err, database.ErrNoActiveProjectAssets) {
				result.Skipped++
				result.Items = append(result.Items, projectBatchStartItem{
					ProjectID:   project.ID,
					ProjectName: project.Name,
					Status:      "skipped",
					Reason:      "没有启用的授权资产",
				})
				continue
			}
			log.Printf("create project session campaign failed: project=%s err=%v", project.ID, err)
			result.Failed++
			result.Items = append(result.Items, projectBatchStartItem{
				ProjectID:   project.ID,
				ProjectName: project.Name,
				Status:      "failed",
				Reason:      "创建后台会话失败",
			})
			continue
		}
		result.Created++
		if err := h.startCampaignRun(campaignID, user.ID); err != nil {
			log.Printf(
				"start project session campaign failed: project=%s campaign=%s err=%v",
				project.ID,
				campaignID,
				err,
			)
			if markErr := h.db.FailProjectSessionCampaign(
				c.Request.Context(),
				campaignID,
				user.ID,
				err.Error(),
			); markErr != nil {
				log.Printf(
					"mark project session campaign failed: campaign=%s err=%v",
					campaignID,
					markErr,
				)
			}
			result.Failed++
			result.Items = append(result.Items, projectBatchStartItem{
				ProjectID:      project.ID,
				ProjectName:    project.Name,
				ConversationID: conversationID,
				CampaignID:     campaignID,
				Status:         "failed",
				Reason:         "启动后台调度失败",
			})
			continue
		}
		result.Started++
		result.Items = append(result.Items, projectBatchStartItem{
			ProjectID:      project.ID,
			ProjectName:    project.Name,
			ConversationID: conversationID,
			CampaignID:     campaignID,
			Status:         "started",
		})
	}
	if result.Started > availableSlots {
		result.Queued = result.Started - availableSlots
	}

	status := http.StatusOK
	if result.Created > 0 {
		status = http.StatusCreated
	}
	c.JSON(status, result)
}

func uniqueProjectBatchIDs(ids []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, id)
	}
	return result
}
