package database

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestGetActiveProjectRejectsInactiveProject(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-status.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	for _, item := range []Project{
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
	} {
		if err := db.CreateProject(ctx, item); err != nil {
			t.Fatalf("创建项目 %s 失败: %v", item.ID, err)
		}
	}

	if _, err := db.GetActiveProject(ctx, "project-active", "user-1"); err != nil {
		t.Fatalf("进行中项目应允许 Agent 工作: %v", err)
	}
	if _, err := db.GetActiveProject(ctx, "project-paused", "user-1"); !errors.Is(err, ErrProjectInactive) {
		t.Fatalf("暂停项目应返回 ErrProjectInactive，实际: %v", err)
	}
}
