package handler

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestResolveConversationRejectsInactiveProject(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "chat-project-status.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	for _, item := range []database.Project{
		{
			ID:          "project-active",
			OwnerUserID: "user-1",
			Name:        "进行中项目",
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "project-paused",
			OwnerUserID: "user-1",
			Name:        "暂停项目",
			Status:      "paused",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		{
			ID:          "project-other",
			OwnerUserID: "user-1",
			Name:        "其他项目",
			Status:      "active",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
	} {
		if err := db.CreateProject(ctx, item); err != nil {
			t.Fatalf("创建项目 %s 失败: %v", item.ID, err)
		}
	}

	handler := &ChatHandler{db: db}
	if _, err := handler.resolveConversation(ctx, "user-1", chatRequest{
		ProjectID: "project-paused",
		Message:   "继续测试",
	}); !errors.Is(err, database.ErrProjectInactive) {
		t.Fatalf("暂停项目不应创建或继续对话，实际: %v", err)
	}

	conversation, err := handler.resolveConversation(ctx, "user-1", chatRequest{
		ProjectID: "project-active",
		Message:   "开始测试",
	})
	if err != nil || conversation.ProjectID != "project-active" {
		t.Fatalf("进行中项目应允许创建对话: conversation=%+v err=%v", conversation, err)
	}
	if _, err := handler.resolveConversation(ctx, "user-1", chatRequest{
		ConversationID: conversation.ID,
		ProjectID:      "project-other",
		Message:        "错误切换项目",
	}); err == nil {
		t.Fatalf("已有对话不应接受不同的项目绑定")
	}
}
