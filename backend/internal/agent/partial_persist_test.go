package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestSaveAssistantContentPersistsAfterCancel(t *testing.T) {
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "partial.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateConversation(ctx, database.Conversation{
		ID:          "conv-partial",
		OwnerUserID: "user-1",
		Title:       "partial",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	if err := db.AddMessage(ctx, database.Message{
		ID:             "msg-partial",
		ConversationID: "conv-partial",
		Role:           "assistant",
		CreatedAt:      now,
	}); err != nil {
		t.Fatalf("创建助手消息失败: %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()

	service := &Service{db: db, cfg: config.Config{}}
	if err := service.saveAssistantContent(
		canceled,
		"msg-partial",
		"已生成的部分内容",
		"",
	); err != nil {
		t.Fatalf("取消态落盘失败: %v", err)
	}

	service.savePartialAssistantContent(canceled, "msg-partial", &runCapture{})
	messages, err := db.GetMessages(ctx, "conv-partial", 10)
	if err != nil {
		t.Fatalf("读取消息失败: %v", err)
	}
	if len(messages) != 1 || messages[0].Content != "已生成的部分内容" {
		t.Fatalf("部分内容未正确保留: %+v", messages)
	}
}
