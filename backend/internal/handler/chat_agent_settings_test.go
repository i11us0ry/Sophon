package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/task"

	"github.com/gin-gonic/gin"
)

func TestConversationAgentSettingsAndStop(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "chat-agent-settings.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-agent-settings", OwnerUserID: "user-1", Name: "设置测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conv-agent-settings", OwnerUserID: "user-1",
		ProjectID: "project-agent-settings", Title: "设置测试",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	manager := task.NewManagerWithLimit(1)
	handler := &ChatHandler{db: db, manager: manager}
	call := func(method, path, body string, run func(*gin.Context)) *httptest.ResponseRecorder {
		gin.SetMode(gin.TestMode)
		recorder := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(recorder)
		ginCtx.Request = httptest.NewRequest(method, path, strings.NewReader(body))
		ginCtx.Request.Header.Set("Content-Type", "application/json")
		ginCtx.Params = gin.Params{{Key: "id", Value: "conv-agent-settings"}}
		ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
		run(ginCtx)
		return recorder
	}

	settings := call(
		http.MethodGet,
		"/api/conversations/conv-agent-settings/agent-settings",
		"",
		handler.GetConversationAgentSettings,
	)
	if settings.Code != http.StatusOK ||
		!strings.Contains(settings.Body.String(), `"autoContinue":true`) ||
		!strings.Contains(settings.Body.String(), `"agentMode":""`) ||
		!strings.Contains(settings.Body.String(), `"assetRestrictionEnabled":true`) {
		t.Fatalf("默认会话设置异常: status=%d body=%s", settings.Code, settings.Body.String())
	}
	invalid := call(
		http.MethodPut,
		"/api/conversations/conv-agent-settings/agent-settings",
		`{}`,
		handler.SetConversationAgentSettings,
	)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("空设置请求应被拒绝: status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	invalid = call(
		http.MethodPut,
		"/api/conversations/conv-agent-settings/agent-settings",
		`{"agentMode":"turbo"}`,
		handler.SetConversationAgentSettings,
	)
	if invalid.Code != http.StatusBadRequest ||
		!strings.Contains(invalid.Body.String(), `"code":"invalid_agent_mode"`) {
		t.Fatalf("非法 Agent 模式应被拒绝: status=%d body=%s", invalid.Code, invalid.Body.String())
	}
	update := call(
		http.MethodPut,
		"/api/conversations/conv-agent-settings/agent-settings",
		`{"autoContinue":false}`,
		handler.SetConversationAgentSettings,
	)
	if update.Code != http.StatusOK {
		t.Fatalf("更新设置失败: status=%d body=%s", update.Code, update.Body.String())
	}
	enabled, err := db.GetConversationAutoContinue(ctx, "conv-agent-settings")
	if err != nil || enabled {
		t.Fatalf("设置未持久化: enabled=%v err=%v", enabled, err)
	}
	assetRestriction, err := db.GetConversationAssetRestriction(ctx, "conv-agent-settings")
	if err != nil || !assetRestriction {
		t.Fatalf("更新自动继续不应覆盖资产限制: enabled=%v err=%v", assetRestriction, err)
	}
	update = call(
		http.MethodPut,
		"/api/conversations/conv-agent-settings/agent-settings",
		`{"assetRestrictionEnabled":false}`,
		handler.SetConversationAgentSettings,
	)
	if update.Code != http.StatusOK ||
		!strings.Contains(update.Body.String(), `"autoContinue":false`) ||
		!strings.Contains(update.Body.String(), `"assetRestrictionEnabled":false`) {
		t.Fatalf("更新资产限制失败: status=%d body=%s", update.Code, update.Body.String())
	}
	assetRestriction, err = db.GetConversationAssetRestriction(ctx, "conv-agent-settings")
	if err != nil || assetRestriction {
		t.Fatalf("资产限制设置未持久化: enabled=%v err=%v", assetRestriction, err)
	}
	update = call(
		http.MethodPut,
		"/api/conversations/conv-agent-settings/agent-settings",
		`{"agentMode":"FAST"}`,
		handler.SetConversationAgentSettings,
	)
	if update.Code != http.StatusOK ||
		!strings.Contains(update.Body.String(), `"agentMode":"fast"`) {
		t.Fatalf("更新 Agent 模式失败: status=%d body=%s", update.Code, update.Body.String())
	}
	if mode, err := db.GetConversationAgentMode(ctx, "conv-agent-settings"); err != nil || mode != "fast" {
		t.Fatalf("Agent 模式未持久化: mode=%q err=%v", mode, err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE conversations SET execution_lane = ? WHERE id = ?`,
		database.ConversationLaneFast,
		"conv-agent-settings",
	); err != nil {
		t.Fatalf("设置固定执行通道失败: %v", err)
	}
	locked := call(
		http.MethodPut,
		"/api/conversations/conv-agent-settings/agent-settings",
		`{"agentMode":"deep"}`,
		handler.SetConversationAgentSettings,
	)
	if locked.Code != http.StatusBadRequest ||
		!strings.Contains(locked.Body.String(), `"code":"agent_mode_locked"`) {
		t.Fatalf("固定执行通道不能切换模式: status=%d body=%s", locked.Code, locked.Body.String())
	}

	taskItem, _, err := manager.CreateIfIdle("conv-agent-settings", "user-1")
	if err != nil {
		t.Fatalf("创建运行任务失败: %v", err)
	}
	stop := call(
		http.MethodPost,
		"/api/conversations/conv-agent-settings/stop",
		"{}",
		handler.StopConversation,
	)
	if stop.Code != http.StatusOK ||
		!strings.Contains(stop.Body.String(), `"cancelled":1`) {
		t.Fatalf("停止后台任务失败: status=%d body=%s", stop.Code, stop.Body.String())
	}
	if taskItem.Snapshot().Status != task.StatusCancelled {
		t.Fatalf("后台任务应被取消: %+v", taskItem.Snapshot())
	}
}

func TestResolveConversationAgentModePriority(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "chat-agent-mode-priority.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-mode-priority", OwnerUserID: "user-1", Name: "模式优先级",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conv-mode-priority", OwnerUserID: "user-1",
		ProjectID: "project-mode-priority", Title: "模式优先级",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	handler := &ChatHandler{db: db}

	if mode, err := handler.resolveConversationAgentMode(ctx, "conv-mode-priority", "", ""); err != nil ||
		mode != "deep" {
		t.Fatalf("未保存模式时应默认协调模式: mode=%q err=%v", mode, err)
	}
	if err := db.SetConversationAgentMode(ctx, "conv-mode-priority", "fast"); err != nil {
		t.Fatalf("保存会话模式失败: %v", err)
	}
	if mode, err := handler.resolveConversationAgentMode(ctx, "conv-mode-priority", "", ""); err != nil ||
		mode != "fast" {
		t.Fatalf("请求未指定模式时应使用会话保存值: mode=%q err=%v", mode, err)
	}
	if mode, err := handler.resolveConversationAgentMode(ctx, "conv-mode-priority", "", "deep"); err != nil ||
		mode != "deep" {
		t.Fatalf("显式请求模式应覆盖会话保存值: mode=%q err=%v", mode, err)
	}
	if mode, err := handler.resolveConversationAgentMode(ctx, "conv-mode-priority", "", "AUTO"); err != nil ||
		mode != "deep" {
		t.Fatalf("旧 auto 值应兼容为协调模式: mode=%q err=%v", mode, err)
	}
	if mode, err := handler.resolveConversationAgentMode(
		ctx,
		"conv-mode-priority",
		database.ConversationLaneCoordinated,
		"fast",
	); err != nil || mode != "deep" {
		t.Fatalf("协调通道必须忽略请求中的 Fast 模式: mode=%q err=%v", mode, err)
	}
	if mode, err := handler.resolveConversationAgentMode(
		ctx,
		"conv-mode-priority",
		database.ConversationLaneFast,
		"deep",
	); err != nil || mode != "fast" {
		t.Fatalf("Fast 通道必须忽略请求中的协调模式: mode=%q err=%v", mode, err)
	}
}
