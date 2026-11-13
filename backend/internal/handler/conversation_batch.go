package handler

import (
	"errors"
	"strings"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

func (h *ChatHandler) StartCampaign(c *gin.Context) {
	campaign, userID, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	if _, err := h.db.GetActiveProject(c.Request.Context(), campaign.ProjectID, userID); err != nil {
		if errors.Is(err, database.ErrProjectInactive) {
			c.JSON(409, gin.H{"code": "project_inactive", "message": err.Error()})
			return
		}
		badRequest(c, "invalid_project", "项目不存在")
		return
	}
	if err := h.startCampaignRun(campaign.ID, userID); err != nil {
		internalError(c, "start_campaign_failed", "启动批量任务失败")
		return
	}
	c.JSON(200, gin.H{"status": database.CampaignStatusRunning})
}

func (h *ChatHandler) PauseCampaign(c *gin.Context) {
	campaign, userID, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	if err := h.campaignScheduler().Pause(campaign.ID, userID); err != nil {
		internalError(c, "pause_campaign_failed", "暂停批量任务失败")
		return
	}
	c.JSON(200, gin.H{"status": database.CampaignStatusPaused})
}

func (h *ChatHandler) ResumeCampaign(c *gin.Context) {
	campaign, userID, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	if _, err := h.db.GetActiveProject(c.Request.Context(), campaign.ProjectID, userID); err != nil {
		if errors.Is(err, database.ErrProjectInactive) {
			c.JSON(409, gin.H{"code": "project_inactive", "message": err.Error()})
			return
		}
		badRequest(c, "invalid_project", "项目不存在")
		return
	}
	if err := h.campaignScheduler().Resume(campaign.ID, userID); err != nil {
		internalError(c, "resume_campaign_failed", "继续批量任务失败")
		return
	}
	c.JSON(200, gin.H{"status": database.CampaignStatusRunning})
}

func (h *ChatHandler) GetCampaignStatus(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	status, err := h.db.CampaignSummary(c.Request.Context(), campaign.ID)
	if err != nil {
		internalError(c, "campaign_status_failed", "读取批量任务状态失败")
		return
	}
	c.JSON(200, gin.H{"status": status})
}

func (h *ChatHandler) ListCampaignGroups(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	items, err := h.db.ListCampaignGroups(c.Request.Context(), campaign.ID)
	if err != nil {
		internalError(c, "campaign_groups_failed", "读取资产组失败")
		return
	}
	c.JSON(200, gin.H{"items": items})
}

func (h *ChatHandler) ListCampaignTasks(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	limit := clampQueryInt(c.Query("limit"), 100, 1, 500)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	items, total, err := h.db.ListCampaignTasks(
		c.Request.Context(),
		campaign.ID,
		strings.TrimSpace(c.Query("status")),
		limit,
		offset,
	)
	if err != nil {
		internalError(c, "campaign_tasks_failed", "读取批量任务明细失败")
		return
	}
	c.JSON(200, gin.H{
		"items":      items,
		"total":      total,
		"hasMore":    offset+len(items) < total,
		"nextOffset": offset + len(items),
	})
}

func (h *ChatHandler) ListCampaignEndpoints(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	limit := clampQueryInt(c.Query("limit"), 100, 1, 500)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	items, total, err := h.db.ListCampaignEndpoints(
		c.Request.Context(),
		campaign.ID,
		limit,
		offset,
	)
	if err != nil {
		internalError(c, "campaign_endpoints_failed", "读取 Endpoint 失败")
		return
	}
	c.JSON(200, gin.H{
		"items":      items,
		"total":      total,
		"hasMore":    offset+len(items) < total,
		"nextOffset": offset + len(items),
	})
}

func (h *ChatHandler) ListCampaignFrontier(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	limit := clampQueryInt(c.Query("limit"), 20, 1, 200)
	items, err := h.db.ListCampaignFrontier(c.Request.Context(), campaign.ID, limit)
	if err != nil {
		internalError(c, "campaign_frontier_failed", "读取 Campaign Frontier 失败")
		return
	}
	c.JSON(200, gin.H{"items": items})
}

func (h *ChatHandler) ListCampaignVerifications(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	limit := clampQueryInt(c.Query("limit"), 20, 1, 200)
	items, err := h.db.ListCampaignVerifications(
		c.Request.Context(),
		campaign.ID,
		strings.TrimSpace(c.Query("status")),
		limit,
	)
	if err != nil {
		internalError(c, "campaign_verifications_failed", "读取漏洞验证队列失败")
		return
	}
	c.JSON(200, gin.H{"items": items})
}

func (h *ChatHandler) ListCampaignLinks(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	limit := clampQueryInt(c.Query("limit"), 50, 1, 200)
	items, err := h.db.ListCampaignLinks(c.Request.Context(), campaign.ID, limit)
	if err != nil {
		internalError(c, "campaign_links_failed", "读取跨资产关系失败")
		return
	}
	c.JSON(200, gin.H{"items": items})
}

func (h *ChatHandler) RecomputeCampaignPriorities(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	ctx := c.Request.Context()
	if _, err := h.db.GenerateCampaignChains(ctx, campaign.ID); err != nil {
		internalError(c, "campaign_chain_failed", "生成攻击链失败")
		return
	}
	if err := h.db.RefreshCampaignMemory(ctx, campaign.ID); err != nil {
		internalError(c, "campaign_memory_failed", "刷新战役记忆失败")
		return
	}
	if err := h.db.RecomputeCampaignScheduling(ctx, campaign.ID); err != nil {
		internalError(c, "campaign_priority_failed", "重算任务优先级失败")
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}

func (h *ChatHandler) StopCampaign(c *gin.Context) {
	campaign, userID, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	if err := h.campaignScheduler().Stop(campaign.ID, userID); err != nil {
		internalError(c, "stop_campaign_failed", "停止持续战役失败")
		return
	}
	c.JSON(200, gin.H{"status": database.CampaignStatusStopped})
}

func (h *ChatHandler) SetCampaignGroupPriority(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	var request struct {
		BusinessSystem   string `json:"businessSystem"`
		BusinessPriority int    `json:"businessPriority"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_request", "优先级参数格式错误")
		return
	}
	priority := request.BusinessPriority
	if priority <= 0 {
		priority = 50
	}
	if priority > 100 {
		badRequest(c, "invalid_priority", "业务优先级必须在 1-100 之间")
		return
	}
	group, err := h.db.SetCampaignGroupPriority(
		c.Request.Context(),
		campaign.ID,
		strings.TrimSpace(c.Param("groupId")),
		strings.TrimSpace(request.BusinessSystem),
		priority,
	)
	if err != nil {
		internalError(c, "group_priority_failed", "更新资产组优先级失败")
		return
	}
	_ = h.db.RecomputeCampaignScheduling(c.Request.Context(), campaign.ID)
	c.JSON(200, gin.H{"group": group})
}

func (h *ChatHandler) ListCampaignChains(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	limit := clampQueryInt(c.Query("limit"), 20, 1, 200)
	items, err := h.db.ListCampaignChains(c.Request.Context(), campaign.ID, limit)
	if err != nil {
		internalError(c, "campaign_chains_failed", "读取攻击链失败")
		return
	}
	c.JSON(200, gin.H{"items": items})
}

func (h *ChatHandler) QueryCampaignMemory(c *gin.Context) {
	campaign, _, ok := h.campaignForRequest(c)
	if !ok {
		return
	}
	limit := clampQueryInt(c.Query("limit"), 50, 1, 200)
	keyword := strings.TrimSpace(c.Query("keyword"))
	var items []database.CampaignMemoryDigest
	var err error
	if keyword != "" {
		items, err = h.db.QueryCampaignMemory(
			c.Request.Context(),
			campaign.ID,
			keyword,
			limit,
		)
	} else {
		items, err = h.db.ListCampaignMemoryDigests(
			c.Request.Context(),
			campaign.ID,
			strings.TrimSpace(c.Query("tier")),
			limit,
		)
	}
	if err != nil {
		internalError(c, "campaign_memory_failed", "读取战役记忆失败")
		return
	}
	c.JSON(200, gin.H{"items": items})
}

func (h *ChatHandler) campaignForRequest(
	c *gin.Context,
) (*database.ConversationBatch, string, bool) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return nil, "", false
	}
	campaignID := strings.TrimSpace(c.Param("id"))
	campaign, err := h.db.GetCampaign(c.Request.Context(), campaignID, user.ID)
	if err != nil {
		c.JSON(404, gin.H{"code": "campaign_not_found", "message": "批量任务不存在"})
		return nil, "", false
	}
	return campaign, user.ID, true
}

func (h *ChatHandler) campaignScheduler() *CampaignScheduler {
	if h.campaigns == nil {
		h.campaigns = NewCampaignScheduler(h.db, h)
	}
	return h.campaigns
}

func (h *ChatHandler) startCampaignRun(campaignID, userID string) error {
	if h.campaignStarter != nil {
		return h.campaignStarter(campaignID, userID)
	}
	return h.campaignScheduler().Start(campaignID, userID)
}
