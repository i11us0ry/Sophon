package policy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestProjectSessionCampaignScopeUsesProjectAssets(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-session-policy.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	const projectID = "project-session-policy"
	if err := db.CreateProject(ctx, database.Project{
		ID:          projectID,
		OwnerUserID: "user-1",
		Name:        "项目会话授权",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, asset := range []database.Asset{
		{
			ID: "session-asset-http", ProjectID: projectID, OwnerUserID: "user-1",
			Name: "HTTP", Kind: "url", Value: "http://fengwogy.cn",
			Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "session-asset-domain", ProjectID: projectID, OwnerUserID: "user-1",
			Name: "域名", Kind: "domain", Value: "fengwogy.cn",
			Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "session-asset-https", ProjectID: projectID, OwnerUserID: "user-1",
			Name: "HTTPS", Kind: "url", Value: "https://fengwogy.cn",
			Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := db.CreateAsset(ctx, asset); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}

	const campaignID = "project-session-campaign-policy"
	if err := db.CreateProjectSessionCampaign(
		ctx,
		database.ConversationBatch{
			ID: campaignID, OwnerUserID: "user-1", ProjectID: projectID,
			Title: "项目会话", Instruction: "执行授权范围内的渗透测试",
			CreatedAt: now, UpdatedAt: now,
		},
		database.Conversation{
			ID: "project-session-conversation-policy", OwnerUserID: "user-1",
			ProjectID: projectID, Title: "项目会话", CreatedAt: now, UpdatedAt: now,
		},
		"执行授权范围内的渗透测试",
	); err != nil {
		t.Fatalf("创建项目会话 Campaign 失败: %v", err)
	}

	assets, err := db.ListCampaignAssets(ctx, campaignID, "user-1")
	if err != nil {
		t.Fatalf("读取 Campaign 授权资产失败: %v", err)
	}
	scope := newScope(assets)
	for _, target := range []string{"fengwogy.cn", "api.fengwogy.cn"} {
		if !scope.Allows(target) {
			t.Fatalf("Campaign 应允许项目授权目标 %s", target)
		}
	}
	if scope.Allows("evil.example.com") {
		t.Fatalf("Campaign 不应允许项目范围外目标")
	}
}
