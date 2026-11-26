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

	"github.com/gin-gonic/gin"
)

func TestAgentSessionDetailsUsesSessionOwnerConversation(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "agent-session-details.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-session-details",
		OwnerUserID: "user-1",
		Name:        "Worker 详情测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, conversation := range []database.Conversation{
		{
			ID: "conv-session-coordinated", OwnerUserID: "user-1",
			ProjectID: "project-session-details", ExecutionLane: database.ConversationLaneCoordinated,
			Title: "协调", CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "conv-session-fast", OwnerUserID: "user-1",
			ProjectID: "project-session-details", ExecutionLane: database.ConversationLaneFast,
			Title: "不协调", CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := db.CreateConversation(ctx, conversation); err != nil {
			t.Fatalf("创建会话失败: %v", err)
		}
	}
	workerSessionID := "worker:conv-session-coordinated:hypothesis-1"
	if err := db.AddProcessDetail(ctx, database.ProcessDetail{
		ID:             "worker-detail-1",
		ConversationID: "conv-session-coordinated",
		SessionID:      workerSessionID,
		EventType:      "tool_result",
		Message:        "http-request",
		Data:           map[string]interface{}{"toolCallId": "call-1", "result": "HTTP 200"},
		CreatedAt:      now,
	}); err != nil {
		t.Fatalf("写入 Worker 活动失败: %v", err)
	}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(
		http.MethodGet,
		"/conversations/conv-session-coordinated/agent-session-details?sessionId="+workerSessionID,
		nil,
	)
	ginCtx.Params = gin.Params{{Key: "id", Value: "conv-session-coordinated"}}
	ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler := &ChatHandler{db: db}
	handler.ListAgentSessionDetails(ginCtx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("读取 Worker 详情失败: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"id":"worker-detail-1"`) ||
		!strings.Contains(body, `"total":1`) {
		t.Fatalf("Worker 详情响应不完整: %s", body)
	}
}
