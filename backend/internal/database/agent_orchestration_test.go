package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentOrchestrationPersistenceAndRecoveryQuery(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "agent-orchestration.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-orchestration", OwnerUserID: "user-1", Name: "编排",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-orchestration", OwnerUserID: "user-1",
		ProjectID: "project-orchestration", Title: "编排恢复",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if err := db.UpsertAgentOrchestration(ctx, AgentOrchestration{
		ConversationID: "conv-orchestration",
		ProjectID:      "project-orchestration",
		OwnerUserID:    "user-1",
		Status:         AgentOrchestrationRunning,
		PlanJSON:       `{"mode":"agent","coordinated":true}`,
		Phase:          "general",
		AgentMode:      "deep",
		RunID:          "run-1",
		MessageID:      "message-1",
		CampaignID:     "campaign-1",
		CampaignTaskID: "task-1",
		Feedback:       []string{"优先检查上传入口"},
		StartedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("写入编排失败: %v", err)
	}
	items, err := db.ListRecoverableAgentOrchestrations(ctx)
	if err != nil {
		t.Fatalf("查询恢复编排失败: %v", err)
	}
	if len(items) != 1 || items[0].ConversationID != "conv-orchestration" ||
		items[0].CampaignTaskID != "task-1" || items[0].RunID != "run-1" ||
		items[0].MessageID != "message-1" ||
		len(items[0].Feedback) != 1 {
		t.Fatalf("恢复数据错误: %+v", items)
	}
	if err := db.UpdateAgentOrchestrationState(
		ctx,
		"conv-orchestration",
		AgentOrchestrationPaused,
		"用户暂停",
		nil,
	); err != nil {
		t.Fatalf("更新编排状态失败: %v", err)
	}
	items, err = db.ListRecoverableAgentOrchestrations(ctx)
	if err != nil {
		t.Fatalf("再次查询恢复编排失败: %v", err)
	}
	if len(items) != 1 || items[0].Status != AgentOrchestrationPaused ||
		items[0].LastError != "用户暂停" || len(items[0].Feedback) != 0 {
		t.Fatalf("暂停状态错误: %+v", items)
	}
}
