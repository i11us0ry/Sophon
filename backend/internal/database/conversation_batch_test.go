package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateConversationBatchReusesAssetsAndHidesChildren(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "conversation-batch.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "batch-project",
		OwnerUserID: "user-1",
		Name:        "批量对话测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID:          "asset-existing",
		ProjectID:   project.ID,
		OwnerUserID: project.OwnerUserID,
		Name:        "https://a.example.com",
		Kind:        "url",
		Value:       "https://a.example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建已有资产失败: %v", err)
	}

	parent := Conversation{
		ID:          "batch-parent",
		OwnerUserID: project.OwnerUserID,
		ProjectID:   project.ID,
		Title:       "批量资产测试",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	batch := ConversationBatch{
		ID:                   "batch-1",
		OwnerUserID:          project.OwnerUserID,
		ProjectID:            project.ID,
		ParentConversationID: parent.ID,
		Title:                parent.Title,
		Instruction:          "测试并记录证据",
		SourceText:           "https://a.example.com\nhttps://b.example.com",
		Total:                2,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	items := []ConversationBatchItem{
		{
			Asset: Asset{
				ID: newID(), ProjectID: project.ID, OwnerUserID: project.OwnerUserID,
				Name: "a", Kind: "url", Value: "https://a.example.com",
				Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
			},
			Conversation: Conversation{
				ID: "child-a", OwnerUserID: project.OwnerUserID, ProjectID: project.ID,
				Title: "https://a.example.com", CreatedAt: now, UpdatedAt: now,
			},
		},
		{
			Asset: Asset{
				ID: "asset-new", ProjectID: project.ID, OwnerUserID: project.OwnerUserID,
				Name: "b", Kind: "url", Value: "https://b.example.com",
				Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
			},
			Conversation: Conversation{
				ID: "child-b", OwnerUserID: project.OwnerUserID, ProjectID: project.ID,
				Title: "https://b.example.com", CreatedAt: now, UpdatedAt: now,
			},
		},
	}
	created, reused, err := db.CreateConversationBatch(
		ctx,
		batch,
		parent,
		items,
		"批量任务摘要",
		false,
	)
	if err != nil {
		t.Fatalf("创建批量对话失败: %v", err)
	}
	if created != 1 || reused != 1 {
		t.Fatalf("资产复用统计错误: created=%d reused=%d", created, reused)
	}

	storedParent, err := db.GetConversation(ctx, parent.ID, project.OwnerUserID)
	if err != nil || storedParent.Kind != "batch_parent" || storedParent.ChildCount != 2 {
		t.Fatalf("父对话状态错误: %+v, err=%v", storedParent, err)
	}
	children, total, err := db.ListConversationChildren(
		ctx,
		parent.ID,
		project.OwnerUserID,
		20,
		0,
	)
	if err != nil || total != 2 || len(children) != 2 {
		t.Fatalf("子对话查询错误: total=%d len=%d err=%v", total, len(children), err)
	}
	childA, err := db.GetConversation(ctx, "child-a", project.OwnerUserID)
	if err != nil || childA.AssetID != "asset-existing" || childA.Kind != "batch_child" {
		t.Fatalf("已有资产应被复用: %+v, err=%v", childA, err)
	}

	topLevel, _, err := db.ListConversationsPage(ctx, project.OwnerUserID, 20, "")
	if err != nil {
		t.Fatalf("读取顶层对话失败: %v", err)
	}
	if len(topLevel) != 1 || topLevel[0].ID != parent.ID {
		t.Fatalf("主列表不应显示批量子对话: %+v", topLevel)
	}
	storedBatch, err := db.GetConversationBatchByChildConversation(
		ctx,
		"child-b",
		project.OwnerUserID,
	)
	if err != nil || storedBatch == nil || storedBatch.Instruction != "测试并记录证据" {
		t.Fatalf("批次上下文读取错误: %+v, err=%v", storedBatch, err)
	}
	storedCampaign, err := db.GetCampaign(ctx, "batch-1", project.OwnerUserID)
	if err != nil || storedCampaign.Status != CampaignStatusDraft {
		t.Fatalf("Campaign 状态错误: %+v, err=%v", storedCampaign, err)
	}
	groups, err := db.ListCampaignGroups(ctx, storedCampaign.ID)
	if err != nil || len(groups) != 2 {
		t.Fatalf("资产分组错误: %+v, err=%v", groups, err)
	}
	tasks, totalTasks, err := db.ListCampaignTasks(ctx, storedCampaign.ID, "", 20, 0)
	if err != nil || totalTasks != 2 || len(tasks) != 2 {
		t.Fatalf("Campaign 任务错误: total=%d len=%d err=%v", totalTasks, len(tasks), err)
	}
	endpoints, totalEndpoints, err := db.ListCampaignEndpoints(ctx, storedCampaign.ID, 20, 0)
	if err != nil || totalEndpoints != 2 || len(endpoints) != 2 {
		t.Fatalf("Campaign Endpoint 错误: total=%d len=%d err=%v", totalEndpoints, len(endpoints), err)
	}
	summary, err := db.CampaignSummary(ctx, storedCampaign.ID)
	if err != nil || summary.TotalAssets != 2 || summary.QueuedTasks != 2 {
		t.Fatalf("Campaign 汇总错误: %+v, err=%v", summary, err)
	}
}
