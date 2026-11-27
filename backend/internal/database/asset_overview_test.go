package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestListProjectAssetOverviewMergesInventoryAndWorkState(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-overview.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-overview",
		OwnerUserID: "user-1",
		Name:        "资产总览",
		Scope:       "example.com",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, asset := range []Asset{
		{
			ID: "asset-overview-valid", ProjectID: "project-overview", OwnerUserID: "user-1",
			Name: "主站", Kind: "url", Value: "https://example.com", Status: "active",
			Source: AssetSourceManual, Criticality: "high", RiskScore: 70, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "asset-overview-host", ProjectID: "project-overview", OwnerUserID: "user-1",
			Name: "历史主机", Kind: "host", Value: "legacy.internal", Status: "active",
			Source: AssetSourceAgent, Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := db.CreateAsset(ctx, asset); err != nil {
			// 历史 host 不通过新资产校验，直接模拟迁移前数据。
			if asset.Kind == "host" {
				if _, sqlErr := db.ExecContext(
					ctx,
					`INSERT INTO assets (
						id, project_id, owner_user_id, name, kind, value,
						normalized_value, quality_status, status, source,
						criticality, risk_score, created_at, updated_at
					) VALUES (?, ?, ?, ?, ?, ?, '', ?, 'active', ?, 'medium', 0, ?, ?)`,
					asset.ID,
					asset.ProjectID,
					asset.OwnerUserID,
					asset.Name,
					asset.Kind,
					asset.Value,
					AssetQualityLegacyUnsupported,
					asset.Source,
					now.Unix(),
					now.Unix(),
				); sqlErr != nil {
					t.Fatalf("写入历史 host 失败: %v", sqlErr)
				}
				continue
			}
			t.Fatalf("创建资产失败: %v", err)
		}
	}
	items, total, err := db.ListProjectAssetOverview(
		ctx,
		"project-overview",
		"user-1",
		AssetOverviewFilter{State: "all", Limit: 20},
	)
	if err != nil {
		t.Fatalf("读取资产总览失败: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("资产总览数量错误: total=%d items=%+v", total, items)
	}
	byID := map[string]AssetOverview{}
	for _, item := range items {
		byID[item.ID] = item
	}
	if byID["asset-overview-valid"].AuthorizationState != AssetAuthorizationAuthorized ||
		byID["asset-overview-valid"].WorkState != AssetWorkQueued {
		t.Fatalf("授权资产工作状态错误: %+v", byID["asset-overview-valid"])
	}
	if byID["asset-overview-host"].WorkState != AssetWorkBlocked {
		t.Fatalf("历史 host 应显示为阻塞而不是可测试队列: %+v", byID["asset-overview-host"])
	}
	pending, pendingTotal, err := db.ListProjectAssetOverview(
		ctx,
		"project-overview",
		"user-1",
		AssetOverviewFilter{State: "pending", Limit: 20},
	)
	if err != nil {
		t.Fatalf("读取待处理资产失败: %v", err)
	}
	if pendingTotal != 1 || len(pending) != 1 || pending[0].ID != "asset-overview-valid" {
		t.Fatalf("待处理过滤错误: total=%d items=%+v", pendingTotal, pending)
	}
}
