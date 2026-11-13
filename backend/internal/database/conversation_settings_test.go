package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestConversationAutoContinueSetting(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "conversation-settings.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-settings", OwnerUserID: "user-1", Name: "设置测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-settings", OwnerUserID: "user-1", ProjectID: "project-settings",
		Title: "设置测试", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	enabled, err := db.GetConversationAutoContinue(ctx, "conv-settings")
	if err != nil || !enabled {
		t.Fatalf("默认应自动继续: enabled=%v err=%v", enabled, err)
	}
	if err := db.SetConversationAutoContinue(ctx, "conv-settings", false); err != nil {
		t.Fatalf("保存设置失败: %v", err)
	}
	enabled, err = db.GetConversationAutoContinue(ctx, "conv-settings")
	if err != nil || enabled {
		t.Fatalf("应持久化为遇到问题暂停: enabled=%v err=%v", enabled, err)
	}
	assetRestriction, err := db.GetConversationAssetRestriction(ctx, "conv-settings")
	if err != nil || !assetRestriction {
		t.Fatalf("默认应开启资产限制: enabled=%v err=%v", assetRestriction, err)
	}
	if err := db.SetConversationAssetRestriction(ctx, "conv-settings", false); err != nil {
		t.Fatalf("保存资产限制失败: %v", err)
	}
	assetRestriction, err = db.GetConversationAssetRestriction(ctx, "conv-settings")
	if err != nil || assetRestriction {
		t.Fatalf("资产限制应持久化为关闭: enabled=%v err=%v", assetRestriction, err)
	}
	enabled, err = db.GetConversationAutoContinue(ctx, "conv-settings")
	if err != nil || enabled {
		t.Fatalf("更新资产限制不应覆盖自动继续设置: enabled=%v err=%v", enabled, err)
	}
}

func TestCountProjectHypothesesOnlyCountsActive(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "active-hypotheses.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-active-hypotheses", OwnerUserID: "user-1", Name: "假设计数",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for index, status := range []string{
		"untested", "running", "suspicious", "tested_clean", "confirmed", "blocked",
	} {
		if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
			ProjectID: "project-active-hypotheses",
			Dimension: "dimension-" + status,
			Status:    status,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			t.Fatalf("写入第 %d 条测试结果失败: %v", index, err)
		}
	}
	count, err := db.CountProjectHypotheses(ctx, "project-active-hypotheses")
	if err != nil {
		t.Fatalf("统计活跃假设失败: %v", err)
	}
	if count != 3 {
		t.Fatalf("只应统计 untested/running/suspicious，实际 %d", count)
	}
}
