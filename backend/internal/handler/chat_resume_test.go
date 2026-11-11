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

func TestGetResumableRun(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "chat-resume.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-resume", OwnerUserID: "user-1", Name: "恢复测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conv-resume", OwnerUserID: "user-1", ProjectID: "project-resume",
		Title: "恢复测试", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	if err := db.CreateAgentRun(ctx, database.AgentRun{
		ID: "run-resume", ConversationID: "conv-resume",
		AssistantMessageID: "assistant-resume", Status: database.AgentRunStatusInterrupted,
		AgentMode: database.AgentRunModeFast, SegmentCount: 155, StartedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建中断任务失败: %v", err)
	}

	handler := &ChatHandler{db: db, manager: task.NewManagerWithLimit(3)}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	requestCtx, _ := gin.CreateTestContext(recorder)
	requestCtx.Request = httptest.NewRequest(http.MethodGet, "/api/conversations/conv-resume/resumable-run", nil)
	requestCtx.Params = gin.Params{{Key: "id", Value: "conv-resume"}}
	requestCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler.GetResumableRun(requestCtx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("读取可恢复任务失败: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"id":"run-resume"`) {
		t.Fatalf("响应缺少恢复任务: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"agentMode":"fast"`) {
		t.Fatalf("响应缺少恢复任务模式: %s", recorder.Body.String())
	}
}

func TestOptionalAgentModeValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name     string
		body     string
		wantMode string
		provided bool
		wantErr  bool
	}{
		{name: "absent", wantMode: "", provided: false},
		{name: "auto", body: `{"agentMode":"AUTO"}`, wantMode: "auto", provided: true},
		{name: "fast", body: `{"agentMode":"FAST"}`, wantMode: "fast", provided: true},
		{name: "deep", body: `{"agentMode":"deep"}`, wantMode: "deep", provided: true},
		{name: "invalid enum", body: `{"agentMode":"turbo"}`, provided: true, wantErr: true},
		{name: "invalid json", body: `{"agentMode":`, provided: false, wantErr: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			var body *strings.Reader
			if test.body != "" {
				body = strings.NewReader(test.body)
			}
			if body == nil {
				ctx.Request = httptest.NewRequest(http.MethodPost, "/resume", nil)
			} else {
				ctx.Request = httptest.NewRequest(http.MethodPost, "/resume", body)
				ctx.Request.Header.Set("Content-Type", "application/json")
			}
			mode, provided, err := optionalAgentMode(ctx)
			if (err != nil) != test.wantErr {
				t.Fatalf("错误结果不符: mode=%q provided=%v err=%v", mode, provided, err)
			}
			if mode != test.wantMode || provided != test.provided {
				t.Fatalf("解析结果不符: mode=%q provided=%v", mode, provided)
			}
		})
	}
}
