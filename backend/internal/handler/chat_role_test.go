package handler

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestApplyConversationRoleCanClearAndRejectsDeletedRole(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "chat-role.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "chat-role-project",
		OwnerUserID: "user-1",
		Name:        "角色测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	role := database.AgentRole{
		ID:          "chat-role",
		Name:        "聊天角色",
		Description: "测试",
		Prompt:      "角色提示词",
		Skills:      []string{},
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateAgentRole(ctx, role); err != nil {
		t.Fatalf("创建角色失败: %v", err)
	}
	conversation := database.Conversation{
		ID:          "chat-role-conversation",
		OwnerUserID: "user-1",
		ProjectID:   "chat-role-project",
		AgentRoleID: role.ID,
		Title:       "角色对话",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateConversation(ctx, conversation); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}

	handler := &ChatHandler{db: db}
	empty := ""
	if err := handler.applyConversationRole(ctx, &conversation, "user-1", &empty); err != nil {
		t.Fatalf("清空角色失败: %v", err)
	}
	if conversation.AgentRoleID != "" {
		t.Fatalf("显式空 roleId 应清空对话角色: %+v", conversation)
	}
	stored, err := db.GetConversation(ctx, conversation.ID, "user-1")
	if err != nil || stored.AgentRoleID != "" {
		t.Fatalf("数据库中的对话角色应被清空: %+v err=%v", stored, err)
	}

	deletedRoleID := role.ID
	if err := handler.applyConversationRole(ctx, &conversation, "user-1", &deletedRoleID); err != nil {
		t.Fatalf("重新设置有效角色失败: %v", err)
	}
	if err := db.DeleteAgentRole(ctx, role.ID); err != nil {
		t.Fatalf("软删除角色失败: %v", err)
	}
	if err := handler.applyConversationRole(ctx, &conversation, "user-1", &deletedRoleID); !errors.Is(err, errInvalidAgentRole) {
		t.Fatalf("软删除角色不应可设置，实际 %v", err)
	}
}
