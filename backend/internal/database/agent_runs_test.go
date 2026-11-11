package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentRunInterruptionAndResumeState(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "agent-runs.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-agent-run", OwnerUserID: "user-1", Name: "运行状态",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-agent-run", OwnerUserID: "user-1", ProjectID: "project-agent-run",
		Title: "运行状态测试", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	if err := db.CreateAgentRun(ctx, AgentRun{
		ID: "run-1", ConversationID: "conv-agent-run",
		AssistantMessageID: "assistant-1", Status: AgentRunStatusRunning,
		AgentMode: AgentRunModeFast, SegmentCount: 1,
		ProgressJSON: `{"facts":2}`, StartedAt: now,
	}); err != nil {
		t.Fatalf("创建运行记录失败: %v", err)
	}
	if err := db.UpdateAgentRunProgress(ctx, "run-1", 7, `{"facts":9}`); err != nil {
		t.Fatalf("更新运行进度失败: %v", err)
	}
	interrupted, err := db.MarkStaleAgentRunsInterrupted(ctx, "服务重启中断")
	if err != nil {
		t.Fatalf("标记中断失败: %v", err)
	}
	if len(interrupted) != 1 || interrupted[0].SegmentCount != 7 {
		t.Fatalf("中断任务状态错误: %+v", interrupted)
	}
	resumable, err := db.GetResumableAgentRun(ctx, "conv-agent-run")
	if err != nil || resumable == nil {
		t.Fatalf("读取可恢复任务失败: %+v, err=%v", resumable, err)
	}
	if resumable.Status != AgentRunStatusInterrupted ||
		resumable.ProgressJSON != `{"facts":9}` ||
		resumable.AgentMode != AgentRunModeFast {
		t.Fatalf("可恢复任务内容错误: %+v", resumable)
	}
	if err := db.CreateAgentRun(ctx, AgentRun{
		ID: "run-2", ConversationID: "conv-agent-run",
		AssistantMessageID: "assistant-2", ResumeOf: "run-1",
		Status: AgentRunStatusRunning, SegmentCount: 2,
		ProgressJSON: `{"facts":10}`, StartedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("创建恢复运行失败: %v", err)
	}
	if err := db.FinishAgentRun(
		ctx,
		"run-2",
		AgentRunStatusInterrupted,
		"",
		"再次中断",
	); err != nil {
		t.Fatalf("标记恢复运行中断失败: %v", err)
	}
	resumable, err = db.GetResumableAgentRun(ctx, "conv-agent-run")
	if err != nil || resumable == nil || resumable.ID != "run-2" {
		t.Fatalf("应返回最新未被恢复的中断任务: %+v, err=%v", resumable, err)
	}
	if err := db.CreateAgentRun(ctx, AgentRun{
		ID: "run-3", ConversationID: "conv-agent-run",
		AssistantMessageID: "assistant-3", ResumeOf: "run-2",
		Status: AgentRunStatusRunning, StartedAt: now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("创建第三次运行失败: %v", err)
	}
	if err := db.FinishAgentRun(
		ctx,
		"run-3",
		AgentRunStatusCompleted,
		"",
		"",
	); err != nil {
		t.Fatalf("完成最新运行失败: %v", err)
	}
	resumable, err = db.GetResumableAgentRun(ctx, "conv-agent-run")
	if err != nil || resumable != nil {
		t.Fatalf("最新运行完成后不应返回历史中断记录: %+v, err=%v", resumable, err)
	}
}
