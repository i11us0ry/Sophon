package database

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openConversationTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "conversation.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func addTestConversation(t *testing.T, db *DB, id, title string) {
	t.Helper()
	now := time.Now().UTC()
	if err := db.CreateConversation(context.Background(), Conversation{
		ID:          id,
		OwnerUserID: "user-1",
		Title:       title,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
}

func addTestMessage(t *testing.T, db *DB, id, conversationID, role, content string) {
	t.Helper()
	if err := db.AddMessage(context.Background(), Message{
		ID:             id,
		ConversationID: conversationID,
		Role:           role,
		Content:        content,
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入消息失败: %v", err)
	}
}

func TestSetConversationTitleIfDefault(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-default", "新对话")
	addTestConversation(t, db, "conv-custom", "用户命名")

	if err := db.SetConversationTitleIfDefault(ctx, "conv-default", "扫描 10.0.0.1"); err != nil {
		t.Fatalf("改写默认标题失败: %v", err)
	}
	if err := db.SetConversationTitleIfDefault(ctx, "conv-custom", "不应覆盖"); err != nil {
		t.Fatalf("自定义标题处理失败: %v", err)
	}

	updated, err := db.GetConversation(ctx, "conv-default", "user-1")
	if err != nil || updated.Title != "扫描 10.0.0.1" {
		t.Fatalf("默认标题应被改写: %+v, err=%v", updated, err)
	}
	custom, err := db.GetConversation(ctx, "conv-custom", "user-1")
	if err != nil || custom.Title != "用户命名" {
		t.Fatalf("自定义标题不应被改写: %+v, err=%v", custom, err)
	}
}

func TestResetAssistantMessageClearsContentAndDetails(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-reset", "新对话")
	addTestMessage(t, db, "msg-reset", "conv-reset", "assistant", "旧回复")
	if err := db.AddProcessDetail(ctx, ProcessDetail{
		ID: "pd-reset", ConversationID: "conv-reset", MessageID: "msg-reset",
		EventType: "tool_call", Message: "exec",
		Data:      map[string]interface{}{"toolCallId": "call-1"},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入过程明细失败: %v", err)
	}

	if err := db.ResetAssistantMessage(ctx, "msg-reset"); err != nil {
		t.Fatalf("重置助手消息失败: %v", err)
	}
	messages, err := db.GetMessages(ctx, "conv-reset", 10)
	if err != nil || len(messages) != 1 || messages[0].Content != "" {
		t.Fatalf("助手消息内容应被清空: %+v, err=%v", messages, err)
	}
	details, err := db.ListProcessDetails(ctx, "conv-reset", 10)
	if err != nil || len(details) != 0 {
		t.Fatalf("过程明细应被清空: %+v, err=%v", details, err)
	}
}

func TestEditLastUserMessageTruncatesSubsequentReplies(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-edit", "新对话")
	addTestMessage(t, db, "msg-u1", "conv-edit", "user", "第一条")
	addTestMessage(t, db, "msg-a1", "conv-edit", "assistant", "第一条回复")
	addTestMessage(t, db, "msg-u2", "conv-edit", "user", "第二条")
	addTestMessage(t, db, "msg-a2", "conv-edit", "assistant", "第二条回复")

	if err := db.AddProcessDetail(ctx, ProcessDetail{
		ID: "pd-a2", ConversationID: "conv-edit", MessageID: "msg-a2",
		EventType: "tool_call", Message: "exec",
		Data:      map[string]interface{}{"toolCallId": "call-2"},
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入过程明细失败: %v", err)
	}
	if err := db.AddTokenUsage(ctx, TokenUsage{
		ID: "tu-a2", ConversationID: "conv-edit", UserID: "user-1", MessageID: "msg-a2",
		PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入 Token 用量失败: %v", err)
	}

	if err := db.EditLastUserMessage(ctx, "conv-edit", "msg-u2", "第二条（已编辑）"); err != nil {
		t.Fatalf("编辑最后一条用户消息失败: %v", err)
	}
	messages, err := db.GetMessages(ctx, "conv-edit", 10)
	if err != nil || len(messages) != 3 {
		t.Fatalf("编辑后应保留 3 条消息: %+v, err=%v", messages, err)
	}
	if messages[2].Content != "第二条（已编辑）" {
		t.Fatalf("用户消息内容未更新: %+v", messages[2])
	}
	details, err := db.ListProcessDetails(ctx, "conv-edit", 10)
	if err != nil || len(details) != 0 {
		t.Fatalf("被截断回复的过程明细应删除: %+v, err=%v", details, err)
	}
	count, err := db.CountRows(ctx, "token_usage", "conversation_id = 'conv-edit'")
	if err != nil || count != 0 {
		t.Fatalf("被截断回复的 Token 用量应删除: %d, err=%v", count, err)
	}

	if err := db.EditLastUserMessage(ctx, "conv-edit", "msg-u1", "改第一条"); !errors.Is(err, ErrNotLastUserMessage) {
		t.Fatalf("非最后一条用户消息应被拒绝: %v", err)
	}
}
