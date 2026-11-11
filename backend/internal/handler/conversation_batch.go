package handler

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

const (
	conversationBatchMaxAssets = 500
	conversationBatchMaxSource = 1 << 20
)

type conversationBatchRequest struct {
	ProjectID              string `json:"projectId"`
	Title                  string `json:"title"`
	Instruction            string `json:"instruction"`
	RoleID                 string `json:"roleId"`
	Assets                 string `json:"assets"`
	MaxConcurrency         int    `json:"maxConcurrency"`
	MaxAttemptsPerTask     int    `json:"maxAttemptsPerTask"`
	MaxSegmentsPerTask     int    `json:"maxSegmentsPerTask"`
	MaxToolCallsPerTask    int    `json:"maxToolCallsPerTask"`
	CampaignMode           string `json:"campaignMode"`
	MaxRounds              int    `json:"maxRounds"`
	CampaignToolCallBudget int    `json:"campaignToolCallBudget"`
}

type batchAssetCandidate struct {
	Kind  string
	Value string
}

func (h *ChatHandler) CreateConversationBatch(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request conversationBatchRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_request", "批量请求格式错误")
		return
	}
	projectID := strings.TrimSpace(request.ProjectID)
	if projectID == "" {
		badRequest(c, "project_required", "批量新建必须选择项目")
		return
	}
	project, err := h.db.GetActiveProject(c.Request.Context(), projectID, user.ID)
	if err != nil {
		if errors.Is(err, database.ErrProjectInactive) {
			c.JSON(409, gin.H{
				"code":    "project_inactive",
				"message": "项目当前状态不允许创建批量任务",
			})
			return
		}
		badRequest(c, "invalid_project", "项目不存在")
		return
	}

	rawAssets := strings.TrimSpace(request.Assets)
	if rawAssets == "" {
		badRequest(c, "assets_required", "资产列表不能为空")
		return
	}
	if len(rawAssets) > conversationBatchMaxSource {
		badRequest(c, "assets_too_large", "资产列表不能超过 1MB")
		return
	}
	candidates, invalid, duplicate := parseConversationBatchAssets(rawAssets)
	if len(candidates) == 0 {
		badRequest(c, "assets_invalid", "没有可识别的 URL、IP 或域名")
		return
	}
	if len(candidates) > conversationBatchMaxAssets {
		badRequest(c, "assets_limit", "单次最多创建 500 个资产对话")
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

	now := time.Now().UTC()
	parentID := randomID()
	batchID := randomID()
	title := strings.TrimSpace(request.Title)
	if title == "" {
		title = "批量任务 " + now.Format("2006-01-02 15:04")
	}
	title = truncateRunes(title, 100)
	instruction := strings.TrimSpace(request.Instruction)
	if instruction == "" {
		instruction = "请对该资产进行安全测试，记录事实、测试结果和漏洞证据。"
	}
	instruction = truncateRunes(instruction, 20000)

	items := make([]database.ConversationBatchItem, 0, len(candidates))
	for _, candidate := range candidates {
		assetID := randomID()
		items = append(items, database.ConversationBatchItem{
			Asset: database.Asset{
				ID:          assetID,
				ProjectID:   project.ID,
				OwnerUserID: user.ID,
				Name:        truncateRunes(candidate.Value, 200),
				Kind:        candidate.Kind,
				Value:       candidate.Value,
				Status:      "active",
				Criticality: "medium",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
			Conversation: database.Conversation{
				ID:          randomID(),
				OwnerUserID: user.ID,
				ProjectID:   project.ID,
				AssetID:     assetID,
				AgentRoleID: roleID,
				Title:       truncateRunes(candidate.Value, 120),
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		})
	}
	parent := database.Conversation{
		ID:          parentID,
		OwnerUserID: user.ID,
		ProjectID:   project.ID,
		AgentRoleID: roleID,
		Title:       title,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	campaignMode := strings.ToLower(strings.TrimSpace(request.CampaignMode))
	if campaignMode == "" {
		campaignMode = database.CampaignModeSingle
	}
	if campaignMode != database.CampaignModeSingle &&
		campaignMode != database.CampaignModeContinuous {
		badRequest(c, "invalid_campaign_mode", "战役模式必须是 single 或 continuous")
		return
	}
	maxRounds := request.MaxRounds
	if maxRounds <= 0 {
		maxRounds = 3
	}
	if maxRounds > 20 {
		maxRounds = 20
	}
	campaignBudget := request.CampaignToolCallBudget
	if campaignBudget <= 0 {
		campaignBudget = 600
	}
	if campaignBudget < 50 {
		campaignBudget = 50
	}
	if campaignBudget > 100000 {
		campaignBudget = 100000
	}
	batch := database.ConversationBatch{
		ID:                     batchID,
		OwnerUserID:            user.ID,
		ProjectID:              project.ID,
		ParentConversationID:   parentID,
		Title:                  title,
		Instruction:            instruction,
		SourceText:             rawAssets,
		Total:                  len(items),
		Status:                 database.CampaignStatusDraft,
		MaxConcurrency:         request.MaxConcurrency,
		MaxAttemptsPerTask:     request.MaxAttemptsPerTask,
		MaxSegmentsPerTask:     request.MaxSegmentsPerTask,
		MaxToolCallsPerTask:    request.MaxToolCallsPerTask,
		CampaignMode:           campaignMode,
		MaxRounds:              maxRounds,
		CampaignToolCallBudget: campaignBudget,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if batch.MaxConcurrency <= 0 {
		batch.MaxConcurrency = 3
	}
	if batch.MaxAttemptsPerTask <= 0 {
		batch.MaxAttemptsPerTask = 2
	}
	if batch.MaxSegmentsPerTask <= 0 {
		batch.MaxSegmentsPerTask = 6
	}
	if batch.MaxToolCallsPerTask <= 0 {
		batch.MaxToolCallsPerTask = 60
	}
	parentMessage := fmt.Sprintf(
		"批量任务已创建\n资产对话：%d\n无效项：%d\n重复项：%d\n任务要求：%s\n状态：未自动执行，请进入对应资产子对话启动测试。",
		len(items),
		invalid,
		duplicate,
		instruction,
	)
	created, reused, err := h.db.CreateConversationBatch(
		c.Request.Context(),
		batch,
		parent,
		items,
		parentMessage,
	)
	if err != nil {
		internalError(c, "create_conversation_batch_failed", "创建批量对话失败")
		return
	}
	parent.Kind = "batch_parent"
	parent.BatchID = batch.ID
	parent.ChildCount = len(items)
	batch.CreatedAt = now
	batch.UpdatedAt = now
	preview := make([]gin.H, 0, minInt(len(items), 20))
	for index, item := range items {
		if index >= 20 {
			break
		}
		preview = append(preview, gin.H{
			"conversationId": item.Conversation.ID,
			"assetId":        item.Conversation.AssetID,
			"target":         item.Asset.Value,
		})
	}
	c.JSON(201, gin.H{
		"parent":  conversationResponse(parent),
		"batch":   batch,
		"created": created,
		"reused":  reused,
		"invalid": invalid,
		"items":   preview,
	})
}

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

func parseConversationBatchAssets(raw string) ([]batchAssetCandidate, int, int) {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';'
	})
	result := make([]batchAssetCandidate, 0, len(parts))
	seen := map[string]bool{}
	invalid := 0
	duplicate := 0
	for _, part := range parts {
		kind, value, ok := normalizeBatchAsset(part)
		if !ok {
			if strings.TrimSpace(part) != "" {
				invalid++
			}
			continue
		}
		key := batchAssetKey(kind, value)
		if seen[key] {
			duplicate++
			continue
		}
		seen[key] = true
		result = append(result, batchAssetCandidate{Kind: kind, Value: value})
	}
	return result, invalid, duplicate
}

func normalizeBatchAsset(raw string) (string, string, bool) {
	value := strings.TrimSpace(raw)
	value = strings.Trim(value, `"'`)
	value = strings.TrimLeft(value, "-* ")
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return "", "", false
		}
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)
		return "url", parsed.String(), true
	}
	hostValue := strings.Trim(value, "[]")
	if host, port, err := net.SplitHostPort(hostValue); err == nil {
		host = strings.Trim(host, "[]")
		kind := "domain"
		if net.ParseIP(host) != nil {
			kind = "ip"
		}
		return kind, net.JoinHostPort(strings.ToLower(host), port), true
	}
	if net.ParseIP(hostValue) != nil {
		return "ip", hostValue, true
	}
	parsed, err := url.Parse("http://" + hostValue)
	if err != nil || parsed.Hostname() == "" || strings.ContainsAny(parsed.Hostname(), " /") {
		return "", "", false
	}
	return "domain", strings.ToLower(parsed.Host), true
}

func batchAssetKey(kind, value string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + "\x00" + strings.ToLower(strings.TrimSpace(value))
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
