package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func addTestAttachment(t *testing.T, db *DB, id, conversationID, fileName, text string) {
	t.Helper()
	if err := db.AddAttachment(context.Background(), Attachment{
		ID:             id,
		ConversationID: conversationID,
		FileName:       fileName,
		MimeType:       "text/plain",
		SizeBytes:      int64(len(text)),
		StoragePath:    filepath.Join(conversationID, id+"_"+fileName),
		TextContent:    text,
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入附件失败: %v", err)
	}
}

func TestAttachmentLinkAndCascadeOnMessageDelete(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-attach", "新对话")
	addTestMessage(t, db, "msg-attach", "conv-attach", "user", "看附件")
	addTestAttachment(t, db, "att-1", "conv-attach", "report.txt", "hello")

	pending, err := db.CountPendingAttachments(ctx, "conv-attach")
	if err != nil || pending != 1 {
		t.Fatalf("待发送附件应为 1: %d, err=%v", pending, err)
	}
	linked, err := db.LinkAttachments(ctx, "conv-attach", "msg-attach", []string{"att-1"})
	if err != nil || linked != 1 {
		t.Fatalf("附件关联失败: %d, err=%v", linked, err)
	}
	item, err := db.GetAttachment(ctx, "att-1")
	if err != nil || item.MessageID != "msg-attach" {
		t.Fatalf("附件未关联到消息: %+v, err=%v", item, err)
	}
	pending, err = db.CountPendingAttachments(ctx, "conv-attach")
	if err != nil || pending != 0 {
		t.Fatalf("关联后不应再有待发送附件: %d, err=%v", pending, err)
	}

	if _, err := db.ExecContext(ctx, `DELETE FROM messages WHERE id = ?`, "msg-attach"); err != nil {
		t.Fatalf("删除消息失败: %v", err)
	}
	if _, err := db.GetAttachment(ctx, "att-1"); err == nil {
		t.Fatalf("附件应随消息级联删除")
	}
}

func TestAttachmentCascadeOnConversationDelete(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-cascade", "新对话")
	addTestAttachment(t, db, "att-2", "conv-cascade", "note.md", "# note")

	if _, err := db.DeleteConversations(ctx, []string{"conv-cascade"}, "user-1"); err != nil {
		t.Fatalf("删除对话失败: %v", err)
	}
	items, err := db.ListAttachments(ctx, "conv-cascade")
	if err != nil || len(items) != 0 {
		t.Fatalf("附件应随对话级联删除: %+v, err=%v", items, err)
	}
}

func TestListRecentAttachmentsReturnsNewestLast(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	addTestConversation(t, db, "conv-recent", "新对话")
	for index, id := range []string{"att-a", "att-b", "att-c"} {
		if err := db.AddAttachment(ctx, Attachment{
			ID:             id,
			ConversationID: "conv-recent",
			FileName:       id + ".txt",
			MimeType:       "text/plain",
			StoragePath:    filepath.Join("conv-recent", id),
			CreatedAt:      time.Now().UTC().Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatalf("写入附件失败: %v", err)
		}
	}
	items, err := db.ListRecentAttachments(ctx, "conv-recent", 2)
	if err != nil || len(items) != 2 {
		t.Fatalf("应返回最近 2 个附件: %+v, err=%v", items, err)
	}
	if items[0].ID != "att-b" || items[1].ID != "att-c" {
		t.Fatalf("最近附件应按时间正序返回: %+v", items)
	}
}

func TestListRecentProjectAttachmentsIncludesSameProjectConversations(t *testing.T) {
	db := openConversationTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, project := range []Project{
		{ID: "project-uploads", OwnerUserID: "user-1", Name: "上传项目", Status: "active", CreatedAt: now, UpdatedAt: now},
		{ID: "project-other", OwnerUserID: "user-1", Name: "其他项目", Status: "active", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.CreateProject(ctx, project); err != nil {
			t.Fatalf("创建项目失败: %v", err)
		}
	}
	for _, conversation := range []Conversation{
		{ID: "conv-upload-a", OwnerUserID: "user-1", ProjectID: "project-uploads", Title: "A", CreatedAt: now, UpdatedAt: now},
		{ID: "conv-upload-b", OwnerUserID: "user-1", ProjectID: "project-uploads", Title: "B", CreatedAt: now, UpdatedAt: now},
		{ID: "conv-upload-other", OwnerUserID: "user-1", ProjectID: "project-other", Title: "C", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.CreateConversation(ctx, conversation); err != nil {
			t.Fatalf("创建对话失败: %v", err)
		}
	}
	for index, item := range []struct {
		id             string
		conversationID string
	}{
		{"att-project-a", "conv-upload-a"},
		{"att-project-b", "conv-upload-b"},
		{"att-other", "conv-upload-other"},
	} {
		if err := db.AddAttachment(ctx, Attachment{
			ID: item.id, ConversationID: item.conversationID, FileName: item.id + ".zip",
			StoragePath: filepath.Join(item.conversationID, item.id+".zip"),
			CreatedAt:   now.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatalf("写入附件失败: %v", err)
		}
	}
	items, err := db.ListRecentProjectAttachments(ctx, "project-uploads", "user-1", 10)
	if err != nil {
		t.Fatalf("读取项目附件失败: %v", err)
	}
	if len(items) != 2 || items[0].ID != "att-project-a" || items[1].ID != "att-project-b" {
		t.Fatalf("项目附件范围错误: %+v", items)
	}
}
