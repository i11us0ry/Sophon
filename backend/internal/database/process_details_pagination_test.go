package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessDetailsPagination(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "process-details-page.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-details", OwnerUserID: "user-1", Title: "过程详情分页",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	for index := 0; index < 5; index++ {
		if err := db.AddProcessDetail(ctx, ProcessDetail{
			ID: newID(), ConversationID: "conv-details", MessageID: "message-1",
			EventType: "tool_call", Message: "exec",
			Data:      map[string]interface{}{"index": index},
			CreatedAt: now.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatalf("写入过程详情失败: %v", err)
		}
	}
	counts, err := db.CountProcessDetailsByMessageIDs(
		ctx,
		"conv-details",
		[]string{"message-1"},
	)
	if err != nil || counts["message-1"] != 5 {
		t.Fatalf("过程详情计数错误: %+v, err=%v", counts, err)
	}
	items, total, hasMore, err := db.ListProcessDetailsByMessageIDsPage(
		ctx,
		"conv-details",
		[]string{"message-1"},
		2,
		0,
	)
	if err != nil || total != 5 || !hasMore || len(items) != 2 {
		t.Fatalf("第一页错误: total=%d hasMore=%v len=%d err=%v", total, hasMore, len(items), err)
	}
	items, total, hasMore, err = db.ListProcessDetailsByMessageIDsPage(
		ctx,
		"conv-details",
		[]string{"message-1"},
		2,
		4,
	)
	if err != nil || total != 5 || hasMore || len(items) != 1 {
		t.Fatalf("末页错误: total=%d hasMore=%v len=%d err=%v", total, hasMore, len(items), err)
	}
}
