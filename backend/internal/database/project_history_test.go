package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSearchProjectHistoryRespectsProjectBoundary(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-history.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	for _, project := range []Project{
		{ID: "project-main", OwnerUserID: "user-1", Name: "主项目", Status: "active", CreatedAt: now, UpdatedAt: now},
		{ID: "project-other", OwnerUserID: "user-1", Name: "其他项目", Status: "active", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.CreateProject(ctx, project); err != nil {
			t.Fatalf("创建项目失败: %v", err)
		}
	}
	for _, conversation := range []Conversation{
		{ID: "conv-main", OwnerUserID: "user-1", ProjectID: "project-main", Title: "源码审计", CreatedAt: now, UpdatedAt: now},
		{ID: "conv-other", OwnerUserID: "user-1", ProjectID: "project-other", Title: "其他任务", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.CreateConversation(ctx, conversation); err != nil {
			t.Fatalf("创建对话失败: %v", err)
		}
	}
	for _, message := range []Message{
		{ID: "msg-main", ConversationID: "conv-main", Role: "user", Content: "源码就在 WebSite.zip 里", CreatedAt: now},
		{ID: "msg-other", ConversationID: "conv-other", Role: "user", Content: "其他项目源码", CreatedAt: now.Add(time.Second)},
	} {
		if err := db.AddMessage(ctx, message); err != nil {
			t.Fatalf("创建消息失败: %v", err)
		}
	}
	hits, total, err := db.SearchProjectHistory(ctx, "project-main", "user-1", "WebSite.zip", 20, 0)
	if err != nil {
		t.Fatalf("搜索历史失败: %v", err)
	}
	if total != 1 || len(hits) != 1 || hits[0].ConversationID != "conv-main" {
		t.Fatalf("项目历史搜索范围不正确: total=%d hits=%+v", total, hits)
	}
}
