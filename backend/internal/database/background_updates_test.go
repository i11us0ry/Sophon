package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestBackgroundUpdateLifecycleAndDedupe(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "background-updates.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-update", OwnerUserID: "user-1", Name: "Update",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-update", OwnerUserID: "user-1", ProjectID: "project-update",
		Title: "Update", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	event := BackgroundUpdateEvent{
		ID:             "update-1",
		ConversationID: "conv-update",
		ProjectID:      "project-update",
		OwnerUserID:    "user-1",
		Kind:           "finding_created",
		Priority:       100,
		DedupeKey:      "finding:1",
		PayloadJSON:    `{"summary":"finding"}`,
		NotBefore:      now.Add(-time.Second),
		CreatedAt:      now,
	}
	if err := db.EnqueueBackgroundUpdate(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueueBackgroundUpdate(ctx, event); err != nil {
		t.Fatal(err)
	}
	conversations, err := db.ListPendingBackgroundUpdateConversations(ctx, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(conversations) != 1 || conversations[0] != "conv-update" {
		t.Fatalf("待处理会话错误: %+v", conversations)
	}
	items, err := db.ClaimBackgroundUpdatesForConversation(ctx, "conv-update", now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Status != BackgroundUpdateProcessing || items[0].Attempts != 1 {
		t.Fatalf("领取事件错误: %+v", items)
	}
	if err := db.ReleaseBackgroundUpdates(ctx, []string{event.ID}, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	items, err = db.ClaimBackgroundUpdatesForConversation(ctx, "conv-update", now, 10)
	if err != nil || len(items) != 1 || items[0].Attempts != 2 {
		t.Fatalf("释放后重新领取错误: %+v err=%v", items, err)
	}
	if err := db.CompleteBackgroundUpdates(ctx, []string{event.ID}, BackgroundUpdateDelivered); err != nil {
		t.Fatal(err)
	}
	if count, err := db.CountPendingBackgroundUpdates(ctx, "conv-update"); err != nil || count != 0 {
		t.Fatalf("完成后仍有 pending: count=%d err=%v", count, err)
	}
}

func TestRecoverProcessingBackgroundUpdates(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "background-update-recovery.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, item := range []Project{
		{ID: "project-recover", OwnerUserID: "user-1", Name: "Recover", Status: "active", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.CreateProject(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-recover", OwnerUserID: "user-1", ProjectID: "project-recover",
		Title: "Recover", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueueBackgroundUpdate(ctx, BackgroundUpdateEvent{
		ID: "update-recover", ConversationID: "conv-recover", ProjectID: "project-recover",
		OwnerUserID: "user-1", Kind: "worker_result", Priority: 50,
		DedupeKey: "worker:1", PayloadJSON: "{}", NotBefore: now.Add(-time.Second), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ClaimBackgroundUpdatesForConversation(ctx, "conv-recover", now, 10); err != nil {
		t.Fatal(err)
	}
	affected, err := db.RecoverProcessingBackgroundUpdates(ctx)
	if err != nil || affected != 1 {
		t.Fatalf("恢复 processing 事件失败: affected=%d err=%v", affected, err)
	}
	if count, err := db.CountPendingBackgroundUpdates(ctx, "conv-recover"); err != nil || count != 1 {
		t.Fatalf("恢复后应重新变为 pending: count=%d err=%v", count, err)
	}
}
