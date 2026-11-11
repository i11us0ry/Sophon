package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/task"

	"github.com/gin-gonic/gin"
)

func TestBuildAgentTraceSummaryCountsUniqueAgents(t *testing.T) {
	details := []database.ProcessDetail{
		{
			EventType: "subagent.started",
			Data: map[string]interface{}{
				"agentId": "worker-1", "agentName": "上传 Worker", "agentKind": "worker",
				"workerFocus": "文件上传", "allowedSkills": []interface{}{"dotnet-file-audit"},
				"task": "审计上传链路",
			},
		},
		{
			EventType: "subagent.completed",
			Data: map[string]interface{}{
				"agentId": "worker-1", "agentKind": "worker", "status": "completed",
				"durationMs": float64(1500), "result": "发现候选漏洞",
			},
		},
		{
			EventType: "subagent.started",
			Data: map[string]interface{}{
				"agentId": "planner-1", "agentKind": "planner", "task": "规划审计",
			},
		},
	}
	summary := buildAgentTraceSummary(details)
	if summary["worker"] != 1 || summary["planner"] != 1 || summary["main"] != 1 {
		t.Fatalf("Agent 数量统计错误: %+v", summary)
	}
	agents, ok := summary["agents"].([]agentTraceEntry)
	if !ok || len(agents) != 2 {
		t.Fatalf("Agent 汇总列表错误: %#v", summary["agents"])
	}
	if agents[0].Status != "completed" || agents[0].DurationMS != 1500 ||
		len(agents[0].AllowedSkills) != 1 || agents[0].AllowedSkills[0] != "dotnet-file-audit" {
		t.Fatalf("Worker 生命周期合并错误: %+v", agents[0])
	}
}

func TestBatchDeleteCancelsRunningTasks(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "chat-delete.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	if err := db.CreateConversation(context.Background(), database.Conversation{
		ID:          "conv-delete",
		OwnerUserID: "user-1",
		ProjectID:   "project-1",
		Title:       "删除测试",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	manager := task.NewManagerWithLimit(3)
	taskItem, _, err := manager.CreateIfIdle("conv-delete", "user-1")
	if err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}
	uploadsDir := t.TempDir()
	conversationDir := filepath.Join(uploadsDir, "conv-delete")
	if err := os.MkdirAll(conversationDir, 0o700); err != nil {
		t.Fatalf("创建附件目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(conversationDir, "test.txt"), []byte("test"), 0o600); err != nil {
		t.Fatalf("创建附件文件失败: %v", err)
	}
	handler := &ChatHandler{db: db, manager: manager, uploadsDir: uploadsDir}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodPost,
		"/api/conversations/batch-delete",
		strings.NewReader(`{"ids":["conv-delete"]}`),
	)
	ctx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler.BatchDeleteConversations(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("批量删除失败: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if taskItem.Snapshot().Status != task.StatusCancelled {
		t.Fatalf("运行中任务应被取消: %+v", taskItem.Snapshot())
	}
	if _, err := db.GetConversation(context.Background(), "conv-delete", "user-1"); err == nil {
		t.Fatalf("对话应被删除")
	}
	if _, err := os.Stat(conversationDir); !os.IsNotExist(err) {
		t.Fatalf("对话附件目录应被清理: %v", err)
	}
}

func TestStreamTaskDetachesOnClientDisconnect(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "chat-stream.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	manager := task.NewManagerWithLimit(1)
	taskItem, _, err := manager.CreateIfIdle("conv-stream", "user-1")
	if err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}
	handler := &ChatHandler{db: db, manager: manager}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	requestCtx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodPost,
		"/api/chat/stream",
		nil,
	).WithContext(requestCtx)
	handler.streamTask(ctx, taskItem, "conv-stream", "assistant-1")

	if taskItem.Snapshot().Status != task.StatusRunning {
		t.Fatalf("客户端断开后后台任务应继续运行: %+v", taskItem.Snapshot())
	}
	taskItem.Cancel()
}
