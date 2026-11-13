package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	agentpkg "sophon/internal/agent"
	"sophon/internal/database"
	"sophon/internal/middleware"
	storagepkg "sophon/internal/storage"
	"sophon/internal/task"
	zhizipkg "sophon/internal/zhizi"

	"github.com/gin-gonic/gin"
)

type ChatHandler struct {
	db         *database.DB
	agent      *agentpkg.Service
	manager    *task.Manager
	uploadsDir string
	storage    *storagepkg.Service
	campaigns  *CampaignScheduler

	campaignStarter func(campaignID, userID string) error
}

var errInvalidAgentRole = errors.New("invalid agent role")

type chatRequest struct {
	ConversationID string   `json:"conversationId"`
	ProjectID      string   `json:"projectId"`
	AssetID        string   `json:"assetId,omitempty"`
	RoleID         *string  `json:"roleId"`
	Message        string   `json:"message"`
	Title          string   `json:"title,omitempty"`
	EditMessageID  string   `json:"editMessageId,omitempty"`
	AttachmentIDs  []string `json:"attachmentIds,omitempty"`
	AgentMode      string   `json:"agentMode,omitempty"`
}

func optionalAgentMode(c *gin.Context) (string, bool, error) {
	if c.Request.Body == nil || c.Request.ContentLength == 0 {
		return "", false, nil
	}
	var request struct {
		AgentMode *string `json:"agentMode,omitempty"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		if errors.Is(err, io.EOF) {
			return "", false, nil
		}
		return "", false, err
	}
	if request.AgentMode == nil {
		return "", false, nil
	}
	mode, err := agentpkg.ParseAgentMode(*request.AgentMode)
	if err != nil {
		return "", true, err
	}
	return mode, true, nil
}

func NewChatHandler(
	db *database.DB,
	agentService *agentpkg.Service,
	manager *task.Manager,
	uploadsDir string,
	storageService *storagepkg.Service,
) *ChatHandler {
	handler := &ChatHandler{
		db:         db,
		agent:      agentService,
		manager:    manager,
		uploadsDir: filepath.Clean(uploadsDir),
		storage:    storageService,
	}
	handler.campaigns = NewCampaignScheduler(db, handler)
	handler.campaignStarter = handler.campaigns.Start
	return handler
}

func (h *ChatHandler) CreateConversation(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}

	var request struct {
		Title     string `json:"title"`
		ProjectID string `json:"projectId"`
		AssetID   string `json:"assetId"`
		RoleID    string `json:"roleId"`
	}
	if err := c.ShouldBindJSON(&request); err != nil && !errors.Is(err, io.EOF) {
		badRequest(c, "invalid_request", "请求格式错误")
		return
	}

	title := strings.TrimSpace(request.Title)
	if title == "" {
		title = "新对话"
	}
	title = truncateRunes(title, 80)
	projectID := strings.TrimSpace(request.ProjectID)
	if projectID == "" {
		badRequest(c, "project_required", "新建对话必须绑定项目")
		return
	}
	if _, err := h.db.GetActiveProject(c.Request.Context(), projectID, user.ID); err != nil {
		if errors.Is(err, database.ErrProjectInactive) {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "project_inactive",
				"message": "项目当前状态不允许新建对话或执行 Agent 工作",
			})
			return
		}
		badRequest(c, "invalid_project", "项目不存在")
		return
	}
	now := time.Now().UTC()
	conversation := database.Conversation{
		ID:          randomID(),
		OwnerUserID: user.ID,
		ProjectID:   projectID,
		AssetID:     strings.TrimSpace(request.AssetID),
		Title:       title,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if conversation.AssetID != "" {
		valid, err := h.validateConversationAsset(c.Request.Context(), projectID, user.ID, conversation.AssetID)
		if err != nil {
			badRequest(c, "invalid_asset", "资产不存在或不属于当前项目")
			return
		}
		conversation.AssetID = valid
	}
	if roleID := strings.TrimSpace(request.RoleID); roleID != "" {
		resolved, ok := h.resolveRoleID(c.Request.Context(), roleID)
		if !ok {
			badRequest(c, "invalid_agent_role", "角色不存在或未启用")
			return
		}
		conversation.AgentRoleID = resolved
	}
	if err := h.db.CreateConversation(c.Request.Context(), conversation); err != nil {
		internalError(c, "create_conversation_failed", "创建对话失败")
		return
	}
	c.JSON(http.StatusCreated, conversationResponse(conversation))
}

func (h *ChatHandler) ListConversations(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	limit := 100
	if rawLimit := strings.TrimSpace(c.Query("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			badRequest(c, "invalid_limit", "limit 参数不合法")
			return
		}
		if parsed < limit {
			limit = parsed
		}
	}
	before := strings.TrimSpace(c.Query("before"))
	if len(before) > 128 {
		badRequest(c, "invalid_cursor", "对话游标不合法")
		return
	}
	conversations, hasMore, err := h.db.ListConversationsPage(
		c.Request.Context(),
		user.ID,
		limit,
		before,
	)
	if err != nil {
		internalError(c, "list_conversations_failed", "读取对话失败")
		return
	}
	active := h.manager.ActiveConversations(user.ID)
	pending, err := h.db.PendingHITLConversationIDs(c.Request.Context(), user.ID)
	if err != nil {
		pending = map[string]bool{}
	}
	conversationIDs := make([]string, 0, len(conversations))
	for _, conversation := range conversations {
		conversationIDs = append(conversationIDs, conversation.ID)
	}
	queued, err := h.db.QueuedCampaignConversationIDs(
		c.Request.Context(),
		user.ID,
		conversationIDs,
	)
	if err != nil {
		queued = map[string]bool{}
	}
	result := make([]gin.H, 0, len(conversations))
	for _, conversation := range conversations {
		status := "idle"
		if queued[conversation.ID] {
			status = "queued"
		}
		if active[conversation.ID] == task.StatusRunning {
			status = "running"
			if pending[conversation.ID] {
				status = "waiting"
			}
		}
		item := conversationResponse(conversation)
		item["status"] = status
		result = append(result, item)
	}
	nextCursor := ""
	if hasMore && len(conversations) > 0 {
		nextCursor = conversations[len(conversations)-1].ID
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      result,
		"hasMore":    hasMore,
		"nextCursor": nextCursor,
	})
}

func (h *ChatHandler) GetConversation(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, conversationResponse(*conversation))
}

func (h *ChatHandler) ListConversationChildren(c *gin.Context) {
	parent, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	limit := clampQueryInt(c.Query("limit"), 200, 1, 500)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	items, total, err := h.db.ListConversationChildren(
		c.Request.Context(),
		parent.ID,
		user.ID,
		limit,
		offset,
	)
	if err != nil {
		internalError(c, "list_conversation_children_failed", "读取子对话失败")
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, conversationResponse(item))
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      result,
		"total":      total,
		"hasMore":    offset+len(items) < total,
		"nextOffset": offset + len(items),
	})
}

func (h *ChatHandler) GetResumableRun(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	run, err := h.db.GetResumableAgentRun(c.Request.Context(), conversation.ID)
	if err != nil {
		internalError(c, "load_resumable_run_failed", "读取可恢复任务失败")
		return
	}
	if run == nil {
		c.JSON(http.StatusOK, gin.H{"run": nil})
		return
	}
	c.JSON(http.StatusOK, gin.H{"run": run})
}

func (h *ChatHandler) GetConversationAgentSettings(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	autoContinue, err := h.db.GetConversationAutoContinue(
		c.Request.Context(),
		conversation.ID,
	)
	if err != nil {
		internalError(c, "load_agent_settings_failed", "读取会话设置失败")
		return
	}
	assetRestriction, err := h.db.GetConversationAssetRestriction(
		c.Request.Context(),
		conversation.ID,
	)
	if err != nil {
		internalError(c, "load_agent_settings_failed", "读取会话设置失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"autoContinue":            autoContinue,
		"assetRestrictionEnabled": assetRestriction,
	})
}

func (h *ChatHandler) SetConversationAgentSettings(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	var request struct {
		AutoContinue            *bool `json:"autoContinue"`
		AssetRestrictionEnabled *bool `json:"assetRestrictionEnabled"`
	}
	if err := c.ShouldBindJSON(&request); err != nil ||
		(request.AutoContinue == nil && request.AssetRestrictionEnabled == nil) {
		badRequest(c, "invalid_request", "至少提供一个有效的会话设置")
		return
	}
	if request.AutoContinue != nil {
		if err := h.db.SetConversationAutoContinue(
			c.Request.Context(),
			conversation.ID,
			*request.AutoContinue,
		); err != nil {
			internalError(c, "save_agent_settings_failed", "保存会话设置失败")
			return
		}
	}
	if request.AssetRestrictionEnabled != nil {
		if err := h.db.SetConversationAssetRestriction(
			c.Request.Context(),
			conversation.ID,
			*request.AssetRestrictionEnabled,
		); err != nil {
			internalError(c, "save_agent_settings_failed", "保存会话设置失败")
			return
		}
	}
	autoContinue, err := h.db.GetConversationAutoContinue(c.Request.Context(), conversation.ID)
	if err != nil {
		internalError(c, "load_agent_settings_failed", "读取会话设置失败")
		return
	}
	assetRestriction, err := h.db.GetConversationAssetRestriction(c.Request.Context(), conversation.ID)
	if err != nil {
		internalError(c, "load_agent_settings_failed", "读取会话设置失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"autoContinue":            autoContinue,
		"assetRestrictionEnabled": assetRestriction,
	})
}

func (h *ChatHandler) StopConversation(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	cancelled := h.manager.CancelConversation(conversation.ID, conversation.OwnerUserID)
	campaignStopped := false
	if conversation.Kind == "batch_child" &&
		strings.TrimSpace(conversation.ParentConversationID) == "" &&
		strings.TrimSpace(conversation.BatchID) != "" {
		if err := h.campaignScheduler().Stop(conversation.BatchID, conversation.OwnerUserID); err != nil {
			internalError(c, "stop_project_session_failed", "停止项目会话失败")
			return
		}
		campaignStopped = true
	}
	c.JSON(http.StatusOK, gin.H{
		"cancelled":       cancelled,
		"campaignStopped": campaignStopped,
	})
}

func (h *ChatHandler) Resume(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	requestedMode, modeProvided, err := optionalAgentMode(c)
	if err != nil {
		badRequest(c, "invalid_agent_mode", err.Error())
		return
	}
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	if strings.TrimSpace(conversation.ProjectID) == "" {
		badRequest(c, "project_required", "请先为对话绑定项目")
		return
	}
	if strings.TrimSpace(conversation.Kind) == "batch_parent" {
		c.JSON(http.StatusConflict, gin.H{
			"code":    "batch_parent_read_only",
			"message": "批量任务父对话只用于汇总，请进入资产子对话执行",
		})
		return
	}
	if _, err := h.db.GetActiveProject(
		c.Request.Context(),
		conversation.ProjectID,
		user.ID,
	); err != nil {
		if errors.Is(err, database.ErrProjectInactive) {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "project_inactive",
				"message": err.Error(),
			})
			return
		}
		badRequest(c, "invalid_project", "项目不存在")
		return
	}
	run, err := h.db.GetResumableAgentRun(c.Request.Context(), conversation.ID)
	if err != nil {
		internalError(c, "load_resumable_run_failed", "读取可恢复任务失败")
		return
	}
	if run == nil {
		c.JSON(http.StatusConflict, gin.H{
			"code":    "no_resumable_run",
			"message": "当前对话没有可恢复的中断任务",
		})
		return
	}
	agentMode := run.AgentMode
	if modeProvided {
		agentMode = requestedMode
	}
	agentMode, err = agentpkg.ParseAgentMode(agentMode)
	if err != nil {
		internalError(c, "invalid_resumable_agent_mode", "可恢复任务的 Agent 模式不合法")
		return
	}
	taskItem, occupiedTaskID, err := h.manager.CreateIfIdle(conversation.ID, user.ID)
	if err != nil {
		if errors.Is(err, task.ErrUserTaskLimit) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":    "agent_concurrency_limit",
				"message": "当前用户同时运行的 Agent 任务已达上限，请等待任务完成",
			})
			return
		}
		c.JSON(http.StatusConflict, gin.H{
			"code":    "conversation_busy",
			"message": "该对话已有任务在运行，请先停止或等待完成",
			"taskId":  occupiedTaskID,
		})
		return
	}
	now := time.Now().UTC()
	assistantMessage := database.Message{
		ID:             randomID(),
		ConversationID: conversation.ID,
		Role:           "assistant",
		Content:        "",
		CreatedAt:      now,
	}
	if err := h.db.AddMessage(c.Request.Context(), assistantMessage); err != nil {
		taskItem.Cancel()
		internalError(c, "save_message_failed", "创建助手消息失败")
		return
	}
	go h.runWithOptions(
		taskItem,
		conversation.ID,
		user.ID,
		assistantMessage.ID,
		agentpkg.RunOptions{ResumeOf: run.ID, AgentMode: agentMode},
		nil,
	)
	h.streamTask(c, taskItem, conversation.ID, assistantMessage.ID)
}

func (h *ChatHandler) ListMessages(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	limit := 50
	if rawLimit := strings.TrimSpace(c.Query("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			badRequest(c, "invalid_limit", "limit 参数不合法")
			return
		}
		limit = parsed
		if limit > 100 {
			limit = 100
		}
	}
	before := strings.TrimSpace(c.Query("before"))
	if len(before) > 128 {
		badRequest(c, "invalid_cursor", "消息游标不合法")
		return
	}
	after := strings.TrimSpace(c.Query("after"))
	if len(after) > 128 {
		badRequest(c, "invalid_cursor", "消息游标不合法")
		return
	}
	if before != "" && after != "" {
		badRequest(c, "invalid_cursor", "before 和 after 不能同时使用")
		return
	}

	var messages []database.Message
	var hasMore bool
	var err error
	if after != "" {
		messages, hasMore, err = h.db.GetMessagePageAfter(
			c.Request.Context(),
			conversation.ID,
			after,
			limit,
		)
	} else {
		messages, hasMore, err = h.db.GetMessagePage(
			c.Request.Context(),
			conversation.ID,
			before,
			limit,
		)
	}
	if err != nil {
		internalError(c, "list_messages_failed", "读取消息失败")
		return
	}
	items := make([]gin.H, 0, len(messages))
	messageIDs := make([]string, 0, len(messages))
	for _, message := range messages {
		messageIDs = append(messageIDs, message.ID)
	}
	detailCounts, _ := h.db.CountProcessDetailsByMessageIDs(
		c.Request.Context(),
		conversation.ID,
		messageIDs,
	)
	reasoningMode := strings.TrimSpace(c.Query("includeReasoning"))
	includeReasoning := reasoningMode == "1" || reasoningMode == "summary"
	for _, message := range messages {
		reasoning := ""
		reasoningTruncated := false
		if includeReasoning {
			reasoning = message.ReasoningContent
			if reasoningMode == "summary" {
				reasoning, reasoningTruncated = summarizeReasoning(reasoning, 12000)
			}
		}
		items = append(items, gin.H{
			"id":                 message.ID,
			"conversationId":     message.ConversationID,
			"role":               message.Role,
			"content":            message.Content,
			"reasoningContent":   reasoning,
			"reasoningTruncated": reasoningTruncated,
			"processDetailCount": detailCounts[message.ID],
			"createdAt":          message.CreatedAt,
		})
	}
	nextCursor := ""
	if hasMore && len(messages) > 0 {
		if after != "" {
			nextCursor = messages[len(messages)-1].ID
		} else {
			nextCursor = messages[0].ID
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"hasMore":    hasMore,
		"nextCursor": nextCursor,
	})
}

func (h *ChatHandler) ListProcessDetails(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	messageIDs := make([]string, 0)
	seen := make(map[string]struct{})
	for _, raw := range c.QueryArray("messageId") {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if len(id) > 128 {
			badRequest(c, "invalid_message_id", "messageId 参数不合法")
			return
		}
		if _, ok := seen[id]; ok {
			continue
		}
		if len(messageIDs) >= 50 {
			badRequest(c, "too_many_message_ids", "单次最多查询 50 条消息的过程详情")
			return
		}
		seen[id] = struct{}{}
		messageIDs = append(messageIDs, id)
	}

	var details []database.ProcessDetail
	total := 0
	hasMore := false
	limit := clampQueryInt(c.Query("limit"), 200, 1, 500)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	var err error
	if len(messageIDs) > 0 {
		details, total, hasMore, err = h.db.ListProcessDetailsByMessageIDsPage(
			c.Request.Context(),
			conversation.ID,
			messageIDs,
			limit,
			offset,
		)
	} else {
		details, err = h.db.ListProcessDetails(c.Request.Context(), conversation.ID, limit)
		total = len(details)
	}
	if err != nil {
		internalError(c, "list_process_details_failed", "读取过程详情失败")
		return
	}
	const maxProcessDetailResponseBytes = 512 << 10
	items := make([]gin.H, 0, len(details))
	responseBytes := 0
	truncated := false
	for _, detail := range details {
		dataBytes, _ := json.Marshal(detail.Data)
		itemBytes := len(detail.Message) + len(dataBytes) + 256
		if len(items) > 0 && responseBytes+itemBytes > maxProcessDetailResponseBytes {
			truncated = true
			break
		}
		responseBytes += itemBytes
		items = append(items, gin.H{
			"id":             detail.ID,
			"eventType":      detail.EventType,
			"message":        detail.Message,
			"data":           detail.Data,
			"messageId":      detail.MessageID,
			"conversationId": detail.ConversationID,
			"createdAt":      detail.CreatedAt,
		})
	}
	nextOffset := offset + len(items)
	agentSummary := gin.H(nil)
	if lifecycle, lifecycleErr := h.db.ListAgentLifecycleDetails(
		c.Request.Context(),
		conversation.ID,
		messageIDs,
	); lifecycleErr == nil {
		agentSummary = buildAgentTraceSummary(lifecycle)
	}
	c.JSON(http.StatusOK, gin.H{
		"items":        items,
		"total":        total,
		"hasMore":      hasMore || truncated,
		"nextOffset":   nextOffset,
		"truncated":    truncated,
		"agentSummary": agentSummary,
	})
}

type agentTraceEntry struct {
	AgentID       string   `json:"agentId"`
	AgentName     string   `json:"agentName"`
	AgentKind     string   `json:"agentKind"`
	WorkerFocus   string   `json:"workerFocus"`
	AllowedSkills []string `json:"allowedSkills"`
	Task          string   `json:"task"`
	Status        string   `json:"status"`
	DurationMS    int64    `json:"durationMs"`
	Result        string   `json:"result"`
	Error         string   `json:"error"`
}

func buildAgentTraceSummary(details []database.ProcessDetail) gin.H {
	agents := make(map[string]*agentTraceEntry)
	order := make([]string, 0)
	for _, detail := range details {
		agentID := traceText(detail.Data["agentId"])
		if agentID == "" {
			continue
		}
		entry := agents[agentID]
		if entry == nil {
			entry = &agentTraceEntry{AgentID: agentID, AllowedSkills: []string{}}
			agents[agentID] = entry
			order = append(order, agentID)
		}
		if value := traceText(detail.Data["agentName"]); value != "" {
			entry.AgentName = value
		}
		if value := traceText(detail.Data["agentKind"]); value != "" {
			entry.AgentKind = value
		}
		if value := traceText(detail.Data["workerFocus"]); value != "" {
			entry.WorkerFocus = value
		}
		if value := traceText(detail.Data["task"]); value != "" {
			entry.Task = value
		}
		if values := traceStrings(detail.Data["allowedSkills"]); len(values) > 0 {
			entry.AllowedSkills = values
		}
		if value := traceInt64(detail.Data["durationMs"]); value > 0 {
			entry.DurationMS = value
		}
		if value := traceText(detail.Data["result"]); value != "" {
			entry.Result = value
		}
		if value := traceText(detail.Data["error"]); value != "" {
			entry.Error = value
		}
		switch detail.EventType {
		case "subagent.started":
			if entry.Status == "" {
				entry.Status = "running"
			}
		case "subagent.completed":
			entry.Status = "completed"
		case "subagent.failed":
			entry.Status = "failed"
		}
	}
	counts := map[string]int{"planner": 0, "worker": 0, "subagent": 0}
	list := make([]agentTraceEntry, 0, min(len(order), 200))
	for _, agentID := range order {
		entry := agents[agentID]
		if _, ok := counts[entry.AgentKind]; ok {
			counts[entry.AgentKind]++
		}
		if len(list) < 200 {
			list = append(list, *entry)
		}
	}
	return gin.H{
		"main":            1,
		"planner":         counts["planner"],
		"worker":          counts["worker"],
		"subagent":        counts["subagent"],
		"agents":          list,
		"agentsTruncated": len(order) > len(list),
	}
}

func traceText(value interface{}) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func traceStrings(value interface{}) []string {
	switch items := value.(type) {
	case []interface{}:
		result := make([]string, 0, len(items))
		for _, item := range items {
			if text := traceText(item); text != "" {
				result = append(result, text)
			}
		}
		return result
	case []string:
		return append([]string(nil), items...)
	default:
		return nil
	}
}

func traceInt64(value interface{}) int64 {
	switch number := value.(type) {
	case float64:
		return int64(number)
	case int64:
		return number
	case int:
		return int64(number)
	default:
		return 0
	}
}

func (h *ChatHandler) GetConversationHITL(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	override, err := h.db.GetConversationHITLOverride(c.Request.Context(), conversation.ID)
	if err != nil {
		internalError(c, "get_conversation_hitl_failed", "读取会话审批设置失败")
		return
	}
	enabled := h.agent.HITLDefaultEnabled()
	if override != nil {
		enabled = *override
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled":    enabled,
		"overridden": override != nil,
	})
}

func (h *ChatHandler) UpdateConversationHITL(c *gin.Context) {
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.Enabled == nil {
		badRequest(c, "invalid_hitl_setting", "enabled 参数不合法")
		return
	}
	if err := h.db.SetConversationHITLOverride(
		c.Request.Context(),
		conversation.ID,
		*request.Enabled,
	); err != nil {
		internalError(c, "update_conversation_hitl_failed", "保存会话审批设置失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled":    *request.Enabled,
		"overridden": true,
	})
}

func (h *ChatHandler) Stream(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}

	var request chatRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_request", "请求格式错误")
		return
	}
	request.Message = strings.TrimSpace(request.Message)
	if request.Message == "" || len(request.Message) > 64*1024 {
		badRequest(c, "invalid_message", "消息不能为空且不能超过 64KB")
		return
	}
	agentMode, err := agentpkg.ParseAgentMode(request.AgentMode)
	if err != nil {
		badRequest(c, "invalid_agent_mode", err.Error())
		return
	}

	conversation, err := h.resolveConversation(c.Request.Context(), user.ID, request)
	if err != nil {
		if errors.Is(err, database.ErrProjectInactive) {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "project_inactive",
				"message": err.Error(),
			})
			return
		}
		badRequest(c, "invalid_conversation", err.Error())
		return
	}
	if strings.TrimSpace(conversation.ProjectID) == "" {
		badRequest(c, "project_required", "请先为对话绑定项目")
		return
	}
	if strings.TrimSpace(conversation.Kind) == "batch_parent" {
		c.JSON(http.StatusConflict, gin.H{
			"code":    "batch_parent_read_only",
			"message": "批量任务父对话只用于汇总，请进入资产子对话执行",
		})
		return
	}
	taskItem, occupiedTaskID, err := h.manager.CreateIfIdle(conversation.ID, user.ID)
	if err != nil {
		if errors.Is(err, task.ErrUserTaskLimit) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":    "agent_concurrency_limit",
				"message": "当前用户同时运行的 Agent 任务已达上限，请等待任务完成",
			})
			return
		}
		c.JSON(http.StatusConflict, gin.H{
			"code":    "conversation_busy",
			"message": "该对话已有任务在运行，请先停止或等待完成",
			"taskId":  occupiedTaskID,
		})
		return
	}
	if err := h.ensureZhiziLease(c.Request.Context(), conversation.ID, user.ID); err != nil {
		taskItem.Cancel()
		if errors.Is(err, database.ErrZhiziNoCapacity) {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "zhizi_no_capacity",
				"message": "当前没有可用的智子分身容量",
			})
			return
		}
		internalError(c, "zhizi_lease_failed", "获取智子分身失败")
		return
	}
	releaseZhiziOnReturn := true
	defer func() {
		if !releaseZhiziOnReturn {
			return
		}
		releaseCtx, cancel := context.WithTimeout(
			context.WithoutCancel(c.Request.Context()),
			5*time.Second,
		)
		defer cancel()
		_ = h.db.ReleaseZhiziLeaseByConversation(releaseCtx, conversation.ID)
	}()
	if err := h.applyConversationRole(
		c.Request.Context(),
		conversation,
		user.ID,
		request.RoleID,
	); err != nil {
		taskItem.Cancel()
		if errors.Is(err, errInvalidAgentRole) {
			badRequest(c, "invalid_agent_role", "角色不存在或未启用")
		} else {
			internalError(c, "update_agent_role_failed", "设置角色失败")
		}
		return
	}

	now := time.Now().UTC()
	userMessageID := strings.TrimSpace(request.EditMessageID)
	if editMessageID := strings.TrimSpace(request.EditMessageID); editMessageID != "" {
		removedPaths, _ := h.db.ListAttachmentStoragePathsAfterMessage(
			c.Request.Context(),
			conversation.ID,
			editMessageID,
		)
		if err := h.db.EditLastUserMessage(
			c.Request.Context(),
			conversation.ID,
			editMessageID,
			request.Message,
		); err != nil {
			taskItem.Cancel()
			if errors.Is(err, database.ErrNotLastUserMessage) {
				badRequest(c, "invalid_edit_target", "只能编辑该对话最后一条用户消息")
				return
			}
			internalError(c, "edit_message_failed", "编辑消息失败")
			return
		}
		h.removeAttachmentFiles(removedPaths)
	} else {
		userMessage := database.Message{
			ID:             randomID(),
			ConversationID: conversation.ID,
			Role:           "user",
			Content:        request.Message,
			CreatedAt:      now,
		}
		if err := h.db.AddMessage(c.Request.Context(), userMessage); err != nil {
			taskItem.Cancel()
			internalError(c, "save_message_failed", "保存用户消息失败")
			return
		}
		userMessageID = userMessage.ID
	}
	if ids := normalizeIDList(request.AttachmentIDs); len(ids) > 0 {
		if _, err := h.db.LinkAttachments(
			c.Request.Context(),
			conversation.ID,
			userMessageID,
			ids,
		); err != nil {
			taskItem.Cancel()
			internalError(c, "link_attachments_failed", "关联附件失败")
			return
		}
	}
	h.autoTitleConversation(c.Request.Context(), conversation.ID, request.Message)

	assistantMessage := database.Message{
		ID:             randomID(),
		ConversationID: conversation.ID,
		Role:           "assistant",
		Content:        "",
		CreatedAt:      now.Add(time.Millisecond),
	}
	if err := h.db.AddMessage(c.Request.Context(), assistantMessage); err != nil {
		taskItem.Cancel()
		internalError(c, "save_message_failed", "创建助手消息失败")
		return
	}

	releaseZhiziOnReturn = false
	go h.runWithOptions(
		taskItem,
		conversation.ID,
		user.ID,
		assistantMessage.ID,
		agentpkg.RunOptions{AgentMode: agentMode},
		nil,
	)
	h.streamTask(c, taskItem, conversation.ID, assistantMessage.ID)
}

// Regenerate 重新生成最后一条助手回复，复用与 Stream 相同的事件协议。
func (h *ChatHandler) Regenerate(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	requestedMode, modeProvided, err := optionalAgentMode(c)
	if err != nil {
		badRequest(c, "invalid_agent_mode", err.Error())
		return
	}
	conversation, ok := h.conversationForRequest(c)
	if !ok {
		return
	}
	if strings.TrimSpace(conversation.ProjectID) == "" {
		badRequest(c, "project_required", "请先为对话绑定项目")
		return
	}
	if strings.TrimSpace(conversation.Kind) == "batch_parent" {
		c.JSON(http.StatusConflict, gin.H{
			"code":    "batch_parent_read_only",
			"message": "批量任务父对话只用于汇总，请进入资产子对话执行",
		})
		return
	}
	if _, err := h.db.GetActiveProject(
		c.Request.Context(),
		conversation.ProjectID,
		user.ID,
	); err != nil {
		if errors.Is(err, database.ErrProjectInactive) {
			c.JSON(http.StatusConflict, gin.H{
				"code":    "project_inactive",
				"message": err.Error(),
			})
			return
		}
		badRequest(c, "invalid_project", "项目不存在")
		return
	}
	messages, err := h.db.GetMessages(c.Request.Context(), conversation.ID, 2)
	if err != nil {
		internalError(c, "load_messages_failed", "读取消息失败")
		return
	}
	if len(messages) < 2 {
		badRequest(c, "nothing_to_regenerate", "没有可重新生成的助手回复")
		return
	}
	assistant := messages[len(messages)-1]
	previous := messages[len(messages)-2]
	if !strings.EqualFold(assistant.Role, "assistant") || !strings.EqualFold(previous.Role, "user") {
		badRequest(c, "nothing_to_regenerate", "没有可重新生成的助手回复")
		return
	}
	agentMode := requestedMode
	if !modeProvided {
		previousRun, runErr := h.db.GetLatestAgentRun(c.Request.Context(), conversation.ID)
		if runErr != nil {
			internalError(c, "load_previous_agent_mode_failed", "读取上一轮 Agent 模式失败")
			return
		}
		if previousRun != nil {
			agentMode = previousRun.AgentMode
		}
	}
	agentMode, err = agentpkg.ParseAgentMode(agentMode)
	if err != nil {
		internalError(c, "invalid_previous_agent_mode", "上一轮 Agent 模式不合法")
		return
	}

	taskItem, occupiedTaskID, err := h.manager.CreateIfIdle(conversation.ID, user.ID)
	if err != nil {
		if errors.Is(err, task.ErrUserTaskLimit) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":    "agent_concurrency_limit",
				"message": "当前用户同时运行的 Agent 任务已达上限，请等待任务完成",
			})
			return
		}
		c.JSON(http.StatusConflict, gin.H{
			"code":    "conversation_busy",
			"message": "该对话已有任务在运行，请先停止或等待完成",
			"taskId":  occupiedTaskID,
		})
		return
	}
	if err := h.db.ResetAssistantMessage(c.Request.Context(), assistant.ID); err != nil {
		taskItem.Cancel()
		internalError(c, "reset_message_failed", "重置回复失败")
		return
	}
	go h.runWithOptions(
		taskItem,
		conversation.ID,
		user.ID,
		assistant.ID,
		agentpkg.RunOptions{AgentMode: agentMode},
		nil,
	)
	h.streamTask(c, taskItem, conversation.ID, assistant.ID)
}

func (h *ChatHandler) streamTask(
	c *gin.Context,
	taskItem *task.Task,
	conversationID string,
	assistantMessageID string,
) {
	c.Header("Content-Type", "text/event-stream; charset=utf-8")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	initial := task.Event{
		Type:    "conversation",
		Message: "会话已准备",
		Data: map[string]interface{}{
			"conversationId": conversationID,
			"taskId":         taskItem.ID(),
			"messageId":      assistantMessageID,
		},
		Timestamp: time.Now().UTC(),
	}
	if !writeSSE(c, initial) {
		taskItem.Detach()
		return
	}

	done := task.Event{
		Type:      "done",
		Message:   "",
		Data:      map[string]interface{}{"taskId": taskItem.ID()},
		Timestamp: time.Now().UTC(),
	}
	// 10 秒心跳：长时间无工具输出的推理阶段也不让 nginx/代理把 SSE 连接判为空闲。
	heartbeat := time.NewTicker(10 * time.Second)
	defer heartbeat.Stop()
	events := taskItem.Events()
	for {
		select {
		case event := <-events:
			if !writeSSE(c, event) {
				taskItem.Detach()
				return
			}
		case <-c.Request.Context().Done():
			taskItem.Detach()
			return
		case <-taskItem.Done():
			for {
				select {
				case event := <-events:
					if !writeSSE(c, event) {
						taskItem.Detach()
						return
					}
				default:
					writeSSE(c, done)
					return
				}
			}
		case <-heartbeat.C:
			if !writeSSE(c, task.Event{Type: "heartbeat", Timestamp: time.Now().UTC()}) {
				taskItem.Detach()
				return
			}
		}
	}
}

// autoTitleConversation 在会话仍是默认标题时，用首条消息生成简短标题（best-effort）。
func (h *ChatHandler) autoTitleConversation(ctx context.Context, conversationID, message string) {
	title := conversationTitleFromMessage(message)
	if title == "" {
		return
	}
	_ = h.db.SetConversationTitleIfDefault(ctx, conversationID, title)
}

func conversationTitleFromMessage(message string) string {
	firstLine := strings.TrimSpace(strings.SplitN(strings.TrimSpace(message), "\n", 2)[0])
	firstLine = strings.Join(strings.Fields(firstLine), " ")
	if firstLine == "" {
		return ""
	}
	return truncateRunes(firstLine, 24)
}

func (h *ChatHandler) GetTask(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	snapshot, ok := h.manager.Get(c.Param("taskId"), user.ID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    "task_not_found",
			"message": "任务不存在",
		})
		return
	}
	c.JSON(http.StatusOK, snapshot)
}

func (h *ChatHandler) CancelTask(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	if !h.manager.Cancel(c.Param("taskId"), user.ID) {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    "task_not_found",
			"message": "任务不存在",
		})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *ChatHandler) DeleteConversation(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	conversationID := strings.TrimSpace(c.Param("id"))
	if _, err := h.db.GetConversation(c.Request.Context(), conversationID, user.ID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    "conversation_not_found",
			"message": "对话不存在",
		})
		return
	}
	h.manager.CancelConversation(conversationID, user.ID)
	_ = h.db.ReleaseZhiziLeaseByConversation(c.Request.Context(), conversationID)
	deleted, err := h.db.DeleteConversations(
		c.Request.Context(),
		[]string{conversationID},
		user.ID,
	)
	if err != nil {
		internalError(c, "delete_conversation_failed", "删除对话失败")
		return
	}
	if deleted == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    "conversation_not_found",
			"message": "对话不存在",
		})
		return
	}
	h.removeConversationFiles(conversationID)
	h.removeConversationWorkspace(conversationID)
	h.manager.CancelConversation(conversationID, user.ID)
	c.Status(http.StatusNoContent)
}

func (h *ChatHandler) BatchDeleteConversations(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_batch_request", "批量请求格式错误")
		return
	}
	ids := normalizeIDList(request.IDs)
	if len(ids) == 0 {
		badRequest(c, "invalid_batch_request", "请至少选择一条对话")
		return
	}
	ownedIDs := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := h.db.GetConversation(c.Request.Context(), id, user.ID); err != nil {
			continue
		}
		ownedIDs = append(ownedIDs, id)
		h.manager.CancelConversation(id, user.ID)
	}
	if len(ownedIDs) == 0 {
		c.JSON(http.StatusOK, gin.H{"deleted": 0})
		return
	}
	deleted, err := h.db.DeleteConversations(c.Request.Context(), ownedIDs, user.ID)
	if err != nil {
		internalError(c, "batch_delete_conversations_failed", "批量删除对话失败")
		return
	}
	for _, id := range ownedIDs {
		h.manager.CancelConversation(id, user.ID)
		_ = h.db.ReleaseZhiziLeaseByConversation(c.Request.Context(), id)
		h.removeConversationFiles(id)
		h.removeConversationWorkspace(id)
	}
	c.JSON(http.StatusOK, gin.H{"deleted": deleted})
}

func (h *ChatHandler) ensureZhiziLease(ctx context.Context, conversationID, userID string) error {
	state, err := h.db.GetZhiziConversationState(ctx, conversationID, userID)
	if err != nil {
		return err
	}
	if !state.Enabled || state.Lease != nil {
		return nil
	}
	_, err = h.db.AcquireZhiziLease(ctx, conversationID, userID, zhizipkg.DefaultTTL)
	return err
}

func (h *ChatHandler) removeConversationFiles(conversationID string) {
	if strings.TrimSpace(h.uploadsDir) == "" || strings.TrimSpace(conversationID) == "" {
		return
	}
	target := filepath.Join(h.uploadsDir, conversationID)
	if !pathWithin(h.uploadsDir, target) {
		return
	}
	_ = os.RemoveAll(target)
}

// removeConversationWorkspace 清理会话的工作区、输出缓存与产物目录，
// 避免删除对话后工作空间页仍显示该会话目录。
func (h *ChatHandler) removeConversationWorkspace(conversationID string) {
	conversationID = strings.TrimSpace(conversationID)
	if h == nil || h.storage == nil || conversationID == "" {
		return
	}
	h.storage.RemoveConversationDirs([]string{conversationID})
}

func (h *ChatHandler) removeAttachmentFiles(paths []string) {
	if strings.TrimSpace(h.uploadsDir) == "" {
		return
	}
	for _, relativePath := range paths {
		target := filepath.Join(h.uploadsDir, relativePath)
		if !pathWithin(h.uploadsDir, target) {
			continue
		}
		_ = os.Remove(target)
	}
}

func (h *ChatHandler) run(
	taskItem *task.Task,
	conversationID string,
	userID string,
	assistantMessageID string,
) {
	h.runWithOptions(
		taskItem,
		conversationID,
		userID,
		assistantMessageID,
		agentpkg.RunOptions{},
		nil,
	)
}

func (h *ChatHandler) runWithCompletion(
	taskItem *task.Task,
	conversationID string,
	userID string,
	assistantMessageID string,
	completion func(error),
) {
	h.runWithOptions(
		taskItem,
		conversationID,
		userID,
		assistantMessageID,
		agentpkg.RunOptions{},
		completion,
	)
}

func (h *ChatHandler) runWithOptions(
	taskItem *task.Task,
	conversationID string,
	userID string,
	assistantMessageID string,
	options agentpkg.RunOptions,
	completion func(error),
) {
	_, err := h.agent.RunWithOptions(
		taskItem.Context(),
		conversationID,
		userID,
		assistantMessageID,
		func(event agentpkg.Event) error {
			taskItem.Publish(task.Event{
				Type:    event.Type,
				Message: event.Message,
				Data:    event.Data,
			})
			return nil
		},
		options,
	)
	if err != nil {
		errorMessage := err.Error()
		if strings.Contains(strings.ToLower(errorMessage), "llm_gateway") ||
			strings.Contains(errorMessage, "模型网关") ||
			strings.Contains(strings.ToLower(errorMessage), "bad gateway") {
			notice := "模型网关暂时不可用，自动重试后仍失败。任务进度已保留，可点击“继续执行”。"
			_ = h.db.UpdateMessageContent(
				context.Background(),
				assistantMessageID,
				notice,
				"",
			)
			errorMessage = notice
			taskItem.Publish(task.Event{
				Type:    "response",
				Message: notice,
				Data: map[string]interface{}{
					"finalized":     false,
					"stoppedReason": "llm_gateway_unavailable",
				},
			})
		} else if messages, loadErr := h.db.GetMessages(context.Background(), conversationID, 500); loadErr == nil {
			// Agent 异常退出时兜底写入可见错误，避免界面留下空回复。
			hasAssistantContent := false
			for _, message := range messages {
				if message.ID == assistantMessageID && strings.TrimSpace(message.Content) != "" {
					hasAssistantContent = true
					break
				}
			}
			if !hasAssistantContent {
				notice := "本轮执行中断，未生成最终结论。\n\n任务进度已保留，可回复“继续”从未完成处继续执行。"
				_ = h.db.UpdateMessageContent(
					context.Background(),
					assistantMessageID,
					notice,
					"",
				)
				errorMessage = notice
				taskItem.Publish(task.Event{
					Type:    "response",
					Message: notice,
					Data: map[string]interface{}{
						"finalized":     false,
						"stoppedReason": "run_failed_without_output",
					},
				})
			}
		}
		taskItem.Publish(task.Event{
			Type:    "error",
			Message: errorMessage,
			Data: map[string]interface{}{
				"conversationId": conversationID,
				"messageId":      assistantMessageID,
			},
		})
		taskItem.Fail(err)
		if completion != nil {
			completion(err)
		}
		return
	}
	taskItem.Complete()
	if completion != nil {
		completion(nil)
	}
}

func (h *ChatHandler) resolveConversation(
	ctx context.Context,
	userID string,
	request chatRequest,
) (*database.Conversation, error) {
	if conversationID := strings.TrimSpace(request.ConversationID); conversationID != "" {
		conversation, err := h.db.GetConversation(ctx, conversationID, userID)
		if err != nil {
			return nil, fmt.Errorf("对话不存在")
		}
		if strings.TrimSpace(conversation.ProjectID) == "" {
			return nil, fmt.Errorf("请先为对话绑定项目")
		}
		if requestedProjectID := strings.TrimSpace(request.ProjectID); requestedProjectID != "" &&
			requestedProjectID != conversation.ProjectID {
			return nil, fmt.Errorf("对话已绑定其他项目，请新建对话后再切换项目")
		}
		if requestedAssetID := strings.TrimSpace(request.AssetID); requestedAssetID != "" &&
			requestedAssetID != conversation.AssetID {
			return nil, fmt.Errorf("对话已绑定其他资产，请新建对话后再切换资产")
		}
		if _, err := h.db.GetActiveProject(ctx, conversation.ProjectID, userID); err != nil {
			if errors.Is(err, database.ErrProjectInactive) {
				return nil, err
			}
			return nil, fmt.Errorf("项目不存在")
		}
		return conversation, nil
	}

	projectID := strings.TrimSpace(request.ProjectID)
	if projectID == "" {
		return nil, fmt.Errorf("新建对话必须绑定项目")
	}
	if _, err := h.db.GetActiveProject(ctx, projectID, userID); err != nil {
		if errors.Is(err, database.ErrProjectInactive) {
			return nil, err
		}
		return nil, fmt.Errorf("项目不存在")
	}

	title := truncateRunes(request.Message, 40)
	now := time.Now().UTC()
	conversation := database.Conversation{
		ID:          randomID(),
		OwnerUserID: userID,
		ProjectID:   projectID,
		AssetID:     strings.TrimSpace(request.AssetID),
		Title:       title,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if conversation.AssetID != "" {
		valid, err := h.validateConversationAsset(ctx, projectID, userID, conversation.AssetID)
		if err != nil {
			return nil, fmt.Errorf("资产不存在或不属于当前项目")
		}
		conversation.AssetID = valid
	}
	if request.RoleID != nil {
		roleID := strings.TrimSpace(*request.RoleID)
		resolved, ok := h.resolveRoleID(ctx, roleID)
		if !ok {
			return nil, fmt.Errorf("角色不存在或未启用")
		}
		conversation.AgentRoleID = resolved
	}
	if err := h.db.CreateConversation(ctx, conversation); err != nil {
		return nil, err
	}
	return &conversation, nil
}

func (h *ChatHandler) conversationForRequest(c *gin.Context) (*database.Conversation, bool) {
	return resolveOwnedConversation(c, h.db)
}

func resolveOwnedConversation(c *gin.Context, db *database.DB) (*database.Conversation, bool) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return nil, false
	}
	conversation, err := db.GetConversation(c.Request.Context(), c.Param("id"), user.ID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    "conversation_not_found",
			"message": "对话不存在",
		})
		return nil, false
	}
	return conversation, true
}

func writeSSE(c *gin.Context, event task.Event) bool {
	payload, err := json.Marshal(event)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(c.Writer, "data: %s\n\n", payload); err != nil {
		return false
	}
	c.Writer.Flush()
	return true
}

func conversationResponse(conversation database.Conversation) gin.H {
	return gin.H{
		"id":                   conversation.ID,
		"projectId":            conversation.ProjectID,
		"assetId":              conversation.AssetID,
		"kind":                 conversation.Kind,
		"parentConversationId": conversation.ParentConversationID,
		"batchId":              conversation.BatchID,
		"childCount":           conversation.ChildCount,
		"agentRoleId":          conversation.AgentRoleID,
		"title":                conversation.Title,
		"lastUserMessage":      conversation.LastUserMessage,
		"createdAt":            conversation.CreatedAt,
		"updatedAt":            conversation.UpdatedAt,
	}
}

func (h *ChatHandler) validateConversationAsset(
	ctx context.Context,
	projectID string,
	userID string,
	assetID string,
) (string, error) {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return "", nil
	}
	assets, err := h.db.ListProjectAssets(ctx, projectID, userID)
	if err != nil {
		return "", err
	}
	for _, asset := range assets {
		if asset.ID == assetID {
			return asset.ID, nil
		}
	}
	return "", fmt.Errorf("资产不存在或不属于当前项目")
}

func (h *ChatHandler) resolveRoleID(ctx context.Context, roleID string) (string, bool) {
	roleID = strings.TrimSpace(roleID)
	if roleID == "" {
		return "", true
	}
	role, err := h.db.GetAgentRole(ctx, roleID)
	if err != nil || !role.Enabled {
		return "", false
	}
	return role.ID, true
}

func (h *ChatHandler) applyConversationRole(
	ctx context.Context,
	conversation *database.Conversation,
	userID string,
	roleID *string,
) error {
	if roleID == nil {
		return nil
	}
	resolved, ok := h.resolveRoleID(ctx, strings.TrimSpace(*roleID))
	if !ok {
		return errInvalidAgentRole
	}
	if conversation.AgentRoleID == resolved {
		return nil
	}
	if err := h.db.SetConversationAgentRole(ctx, conversation.ID, userID, resolved); err != nil {
		return err
	}
	conversation.AgentRoleID = resolved
	return nil
}

func truncateRunes(value string, max int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) <= max {
		return string(runes)
	}
	return string(runes[:max])
}

func summarizeReasoning(value string, max int) (string, bool) {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) <= max {
		return string(runes), false
	}
	head := max * 2 / 3
	tail := max - head
	return string(runes[:head]) + "\n\n[...]\n\n" + string(runes[len(runes)-tail:]), true
}

func randomID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("id_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

func unauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"code":    "unauthorized",
		"message": "未登录或会话已失效",
	})
}

func badRequest(c *gin.Context, code, message string) {
	c.JSON(http.StatusBadRequest, gin.H{
		"code":    code,
		"message": message,
	})
}

func internalError(c *gin.Context, code, message string) {
	c.JSON(http.StatusInternalServerError, gin.H{
		"code":    code,
		"message": message,
	})
}
