package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestContextRuntimeStoresDirectiveSnapshotAndSections(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "context-runtime.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-context", OwnerUserID: "user-1", Name: "上下文测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-context", OwnerUserID: "user-1", ProjectID: "project-context",
		Title: "上下文测试", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	directive, err := db.CreateConversationTurnDirective(ctx, ConversationTurnDirective{
		ConversationID:  "conv-context",
		ProjectID:       "project-context",
		UserMessageID:   "msg-context",
		RunID:           "run-context",
		Kind:            "continue",
		MissionMode:     "agent",
		Objective:       "继续上下文测试",
		CapabilityMode:  "analyze",
		Confidence:      95,
		ResolverVersion: "test-v1",
	})
	if err != nil {
		t.Fatalf("创建 TurnDirective 失败: %v", err)
	}
	if _, err := db.CreateConversationTurnDirective(ctx, ConversationTurnDirective{
		ConversationID: "conv-context",
		ProjectID:      "project-context",
		Kind:           "unknown",
		CapabilityMode: "analyze",
	}); err == nil {
		t.Fatal("未知指令类型应被拒绝")
	}
	snapshot, err := db.CreateContextSnapshot(ctx, ContextSnapshot{
		RunID:          "run-context",
		ConversationID: "conv-context",
		ProjectID:      "project-context",
		DirectiveID:    directive.ID,
		Mode:           AgentRunModeDeep,
		CapabilityMode: "analyze",
		Model:          "test-model",
		ToolSchemaHash: "tool-hash",
		SummaryVersion: 2,
		TotalTokens:    321,
		Sections: []ContextSnapshotSection{
			{
				SectionName:   "turn_directive",
				SourceType:    "user_message",
				SourceIDsJSON: `["msg-context"]`,
				ContentHash:   "hash-directive",
				TokenEstimate: 20,
				TrustLevel:    "user_directive",
				Included:      true,
			},
			{
				SectionName:   "historical_summary",
				SourceType:    "conversation_summary",
				SourceIDsJSON: `["summary-v2"]`,
				ContentHash:   "hash-summary",
				TokenEstimate: 100,
				TrustLevel:    "untrusted_data",
				Included:      false,
				OmittedReason: "shadow_default_excludes_summary",
			},
		},
	})
	if err != nil {
		t.Fatalf("创建 ContextSnapshot 失败: %v", err)
	}
	stored, err := db.GetContextSnapshot(ctx, snapshot.RunID)
	if err != nil {
		t.Fatalf("读取 ContextSnapshot 失败: %v", err)
	}
	if stored.DirectiveID != directive.ID ||
		stored.TotalTokens != 321 ||
		stored.SummaryVersion != 2 ||
		len(stored.Sections) != 2 {
		t.Fatalf("ContextSnapshot 内容错误: %+v", stored)
	}
	if stored.Sections[0].SectionName != "turn_directive" ||
		!stored.Sections[0].Included ||
		stored.Sections[1].Included ||
		stored.Sections[1].OmittedReason == "" {
		t.Fatalf("ContextSnapshot 分节错误: %+v", stored.Sections)
	}
	if _, err := db.CreateContextSnapshot(ctx, ContextSnapshot{
		RunID:          "run-context",
		ConversationID: "conv-context",
		ProjectID:      "project-context",
	}); err == nil {
		t.Fatal("同一运行不应保存多个上下文快照")
	}
	if _, err := db.DeleteConversations(ctx, []string{"conv-context"}, "user-1"); err != nil {
		t.Fatalf("删除会话失败: %v", err)
	}
	if _, err := db.GetContextSnapshot(ctx, "run-context"); !NoRows(err) {
		t.Fatalf("上下文快照应随会话级联删除: %v", err)
	}
}
