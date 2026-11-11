package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestTokenUsageForMessage(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "token-turn.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-1", OwnerUserID: "user-1", Name: "项目一", Status: "active",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "c1", OwnerUserID: "user-1", ProjectID: "project-1", Title: "测试",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	for _, item := range []TokenUsage{
		{ID: "u1", ConversationID: "c1", UserID: "user-1", MessageID: "m1", PromptTokens: 100, CompletionTokens: 20, TotalTokens: 120, Kind: "chat", CreatedAt: now},
		{ID: "u2", ConversationID: "c1", UserID: "user-1", MessageID: "m1", PromptTokens: 200, CompletionTokens: 30, TotalTokens: 230, Kind: "chat", CreatedAt: now},
		{ID: "u3", ConversationID: "c1", UserID: "user-1", MessageID: "m2", PromptTokens: 900, CompletionTokens: 90, TotalTokens: 990, Kind: "chat", CreatedAt: now},
		{ID: "u4", ConversationID: "c1", UserID: "user-1", MessageID: "m1", PromptTokens: 300, CompletionTokens: 40, TotalTokens: 340, Kind: "subagent", CreatedAt: now},
	} {
		if err := db.AddTokenUsage(ctx, item); err != nil {
			t.Fatalf("写入 token 用量失败: %v", err)
		}
	}
	total, err := db.TokenUsageForMessage(ctx, "m1")
	if err != nil {
		t.Fatalf("读取 token 用量失败: %v", err)
	}
	if total != 690 {
		t.Fatalf("同一助手消息累计 token 应包含 subagent，期望 690，实际 %d", total)
	}
	var projectID string
	if err := db.QueryRowContext(
		ctx,
		`SELECT project_id FROM token_usage WHERE id = 'u1'`,
	).Scan(&projectID); err != nil {
		t.Fatalf("读取 Token 项目归属失败: %v", err)
	}
	if projectID != "project-1" {
		t.Fatalf("Token 项目归属错误，期望 project-1，实际 %s", projectID)
	}
	if err := db.AddTokenUsage(ctx, TokenUsage{
		ID: "u5", ConversationID: "c1", UserID: "user-2", MessageID: "m1",
		PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15, Kind: "chat", CreatedAt: now,
	}); err == nil {
		t.Fatal("跨用户写入 Token 应被拒绝")
	}
}

func TestOpenBackfillsTokenUsageProjectID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-token.db")
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("打开旧数据库失败: %v", err)
	}
	now := time.Now().UTC().Unix()
	for _, statement := range []string{
		`CREATE TABLE conversations (
			id TEXT PRIMARY KEY,
			owner_user_id TEXT NOT NULL,
			project_id TEXT NOT NULL DEFAULT '',
			asset_id TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL DEFAULT 'normal',
			parent_conversation_id TEXT NOT NULL DEFAULT '',
			batch_id TEXT NOT NULL DEFAULT '',
			title TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE token_usage (
			id TEXT PRIMARY KEY,
			conversation_id TEXT NOT NULL DEFAULT '',
			user_id TEXT NOT NULL,
			message_id TEXT NOT NULL DEFAULT '',
			prompt_tokens INTEGER NOT NULL DEFAULT 0,
			completion_tokens INTEGER NOT NULL DEFAULT 0,
			total_tokens INTEGER NOT NULL DEFAULT 0,
			estimated INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		)`,
	} {
		if _, err := raw.Exec(statement); err != nil {
			_ = raw.Close()
			t.Fatalf("创建旧表失败: %v", err)
		}
	}
	if _, err := raw.Exec(
		`INSERT INTO conversations (
			id, owner_user_id, project_id, title, created_at, updated_at
		) VALUES ('c-legacy', 'user-1', 'project-1', '旧会话', ?, ?)`,
		now,
		now,
	); err != nil {
		_ = raw.Close()
		t.Fatalf("创建旧会话失败: %v", err)
	}
	if _, err := raw.Exec(
		`INSERT INTO token_usage (
			id, conversation_id, user_id, total_tokens, created_at
		) VALUES ('u-legacy', 'c-legacy', 'user-1', 42, ?)`,
		now,
	); err != nil {
		_ = raw.Close()
		t.Fatalf("创建旧 Token 记录失败: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("关闭旧数据库失败: %v", err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatalf("迁移旧数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var projectID string
	if err := db.QueryRow(
		`SELECT project_id FROM token_usage WHERE id = 'u-legacy'`,
	).Scan(&projectID); err != nil {
		t.Fatalf("读取回填结果失败: %v", err)
	}
	if projectID != "project-1" {
		t.Fatalf("旧 Token 项目归属未回填，实际 %q", projectID)
	}
}
