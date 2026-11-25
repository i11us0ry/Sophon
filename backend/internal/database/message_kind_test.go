package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestMessageKindAndProactiveBackfill(t *testing.T) {
	path := filepath.Join(t.TempDir(), "message-kind.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateUser(ctx, User{
		ID: "user-1", Username: "user-1", DisplayName: "User",
		PasswordHash: "hash", Role: "admin", Enabled: true, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-1", OwnerUserID: "user-1", Title: "Message kind",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddMessage(ctx, Message{
		ID: "chat-1", ConversationID: "conv-1", Role: "user",
		Content: "正常对话", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddMessage(ctx, Message{
		ID: "proactive-1", ConversationID: "conv-1", Role: "assistant",
		MessageKind: "proactive", Content: "后台进展\n测试", CreatedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatal(err)
	}
	all, err := db.GetMessages(ctx, "conv-1", 10)
	if err != nil || len(all) != 2 || all[0].MessageKind != "chat" || all[1].MessageKind != "proactive" {
		t.Fatalf("消息类型读取错误: %+v err=%v", all, err)
	}
	contextMessages, err := db.GetContextMessages(ctx, "conv-1", 10)
	if err != nil || len(contextMessages) != 1 || contextMessages[0].ID != "chat-1" {
		t.Fatalf("上下文消息过滤错误: %+v err=%v", contextMessages, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE messages SET message_kind='chat' WHERE id='proactive-1'`); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveConversationSummary(ctx, ConversationSummary{
		ConversationID:   "conv-1",
		Summary:          "assistant: 后台进展\n已发现漏洞",
		ThroughMessageID: "proactive-1",
		UpdatedAt:        now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var kind string
	if err := db.QueryRowContext(ctx, `SELECT message_kind FROM messages WHERE id='proactive-1'`).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "proactive" {
		t.Fatalf("历史后台进展未回填: %q", kind)
	}
	if summary, err := db.GetConversationSummary(ctx, "conv-1"); err != nil || summary != nil {
		t.Fatalf("含后台进展的派生摘要应被清除: summary=%+v err=%v", summary, err)
	}
}
