package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestProjectDetailPagination(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-detail-page.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	project := Project{
		ID:          "project-detail-page",
		OwnerUserID: "user-1",
		Name:        "分页测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}

	for i := 0; i < 5; i++ {
		createdAt := now.Add(-time.Duration(i) * time.Minute)
		if _, err := db.UpsertProjectFact(ctx, ProjectFact{
			ID:         newID(),
			ProjectID:  project.ID,
			FactType:   "test",
			Key:        "fact-" + string(rune('a'+i)),
			Value:      "fact-value",
			Confidence: 100,
			CreatedAt:  createdAt,
			UpdatedAt:  createdAt,
		}); err != nil {
			t.Fatalf("创建事实失败: %v", err)
		}
		if err := db.CreateAsset(ctx, Asset{
			ID:          newID(),
			ProjectID:   project.ID,
			OwnerUserID: project.OwnerUserID,
			Name:        "asset-" + string(rune('a'+i)),
			Kind:        "ip",
			Value:       "10.0.0." + string(rune('1'+i)),
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   createdAt,
			UpdatedAt:   createdAt,
		}); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
		if err := db.CreateConversation(ctx, Conversation{
			ID:          newID(),
			OwnerUserID: project.OwnerUserID,
			ProjectID:   project.ID,
			AgentRoleID: "role-1",
			Title:       "conversation-" + string(rune('a'+i)),
			CreatedAt:   createdAt,
			UpdatedAt:   createdAt,
		}); err != nil {
			t.Fatalf("创建对话失败: %v", err)
		}
	}

	facts, total, err := db.ListProjectFactsPage(ctx, project.ID, 2, 0)
	if err != nil || total != 5 || len(facts) != 2 {
		t.Fatalf("事实首页分页错误: total=%d len=%d err=%v", total, len(facts), err)
	}
	facts, total, err = db.ListProjectFactsPage(ctx, project.ID, 2, 4)
	if err != nil || total != 5 || len(facts) != 1 {
		t.Fatalf("事实末页分页错误: total=%d len=%d err=%v", total, len(facts), err)
	}

	assets, total, err := db.ListProjectAssetsPage(ctx, project.ID, project.OwnerUserID, 2, 0)
	if err != nil || total != 5 || len(assets) != 2 {
		t.Fatalf("资产首页分页错误: total=%d len=%d err=%v", total, len(assets), err)
	}
	assets, total, err = db.ListProjectAssetsPage(ctx, project.ID, project.OwnerUserID, 2, 4)
	if err != nil || total != 5 || len(assets) != 1 {
		t.Fatalf("资产末页分页错误: total=%d len=%d err=%v", total, len(assets), err)
	}
	assets, total, err = db.ListProjectAssetsPage(ctx, project.ID, "user-2", 10, 0)
	if err != nil || total != 0 || len(assets) != 0 {
		t.Fatalf("资产查询应隔离其他用户: total=%d len=%d err=%v", total, len(assets), err)
	}

	conversations, total, err := db.ListProjectConversationsPage(
		ctx,
		project.ID,
		project.OwnerUserID,
		2,
		0,
	)
	if err != nil || total != 5 || len(conversations) != 2 {
		t.Fatalf("对话首页分页错误: total=%d len=%d err=%v", total, len(conversations), err)
	}
	conversations, total, err = db.ListProjectConversationsPage(
		ctx,
		project.ID,
		project.OwnerUserID,
		2,
		4,
	)
	if err != nil || total != 5 || len(conversations) != 1 {
		t.Fatalf("对话末页分页错误: total=%d len=%d err=%v", total, len(conversations), err)
	}
}
