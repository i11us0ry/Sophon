package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentTriggerDedupeClaimCompleteAndRecovery(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "agent-triggers.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-trigger", OwnerUserID: "user-1", Name: "Trigger",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-trigger", OwnerUserID: "user-1", ProjectID: "project-trigger",
		Title: "Trigger", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	item := AgentTrigger{
		ConversationID: "conv-trigger",
		ProjectID:      "project-trigger",
		Kind:           AgentTriggerFinding,
		IntentID:       "intent-1",
		Payload:        map[string]interface{}{"summary": "confirmed"},
		DedupeKey:      "finding:1",
		CreatedAt:      now,
	}
	if _, err := db.EnqueueAgentTrigger(ctx, item); err != nil {
		t.Fatalf("写入 Trigger 失败: %v", err)
	}
	if duplicate, err := db.EnqueueAgentTrigger(ctx, item); err != nil || duplicate != nil {
		t.Fatalf("重复 Trigger 应被去重: item=%+v err=%v", duplicate, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE projects SET status = 'paused' WHERE id = ?`, "project-trigger"); err != nil {
		t.Fatalf("暂停项目失败: %v", err)
	}
	if claimed, err := db.DrainPendingAgentTriggers(ctx, "conv-trigger", 10); err != nil || len(claimed) != 0 {
		t.Fatalf("暂停项目不应消费 Trigger: %+v err=%v", claimed, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE projects SET status = 'active' WHERE id = ?`, "project-trigger"); err != nil {
		t.Fatalf("恢复项目失败: %v", err)
	}
	claimed, err := db.DrainPendingAgentTriggers(ctx, "conv-trigger", 10)
	if err != nil || len(claimed) != 1 || claimed[0].Status != AgentTriggerProcessing {
		t.Fatalf("领取 Trigger 失败: %+v err=%v", claimed, err)
	}
	if err := db.ReleaseAgentTriggers(ctx, []string{claimed[0].ID}); err != nil {
		t.Fatalf("释放 Trigger 失败: %v", err)
	}
	claimed, err = db.DrainPendingAgentTriggers(ctx, "conv-trigger", 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("重新领取 Trigger 失败: %+v err=%v", claimed, err)
	}
	if err := db.CompleteAgentTriggers(ctx, []string{claimed[0].ID}); err != nil {
		t.Fatalf("完成 Trigger 失败: %v", err)
	}
	if pending, err := db.CountPendingAgentTriggers(ctx, "conv-trigger"); err != nil || pending != 0 {
		t.Fatalf("消费后仍有 pending Trigger: pending=%d err=%v", pending, err)
	}
	if _, err := db.EnqueueAgentTrigger(ctx, AgentTrigger{
		ConversationID: "conv-trigger",
		Kind:           AgentTriggerDone,
		DedupeKey:      "done:2",
	}); err != nil {
		t.Fatalf("写入恢复 Trigger 失败: %v", err)
	}
	if _, err := db.DrainPendingAgentTriggers(ctx, "conv-trigger", 10); err != nil {
		t.Fatalf("领取恢复 Trigger 失败: %v", err)
	}
	if affected, err := db.RecoverProcessingAgentTriggers(ctx); err != nil || affected != 1 {
		t.Fatalf("恢复 processing Trigger 失败: affected=%d err=%v", affected, err)
	}
}

func TestPlannerTodoReplaceAndList(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "planner-todos.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-todo", OwnerUserID: "user-1", Name: "Todo",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-todo", OwnerUserID: "user-1", ProjectID: "project-todo",
		Title: "Todo", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	items, err := db.ReplaceAgentPlannerTodos(ctx, "conv-todo", "project-todo", []AgentPlannerTodo{
		{Content: "获取低权会话", Status: "completed"},
		{Content: "验证文件上传", Status: "in_progress"},
	})
	if err != nil || len(items) != 2 || items[1].Status != PlannerTodoInProgress {
		t.Fatalf("写入 Planner Todo 失败: %+v err=%v", items, err)
	}
	items, err = db.ReplaceAgentPlannerTodos(ctx, "conv-todo", "project-todo", []AgentPlannerTodo{
		{Content: "验证文件上传", Status: "completed"},
	})
	if err != nil || len(items) != 1 || items[0].Status != PlannerTodoCompleted {
		t.Fatalf("替换 Planner Todo 失败: %+v err=%v", items, err)
	}
}
