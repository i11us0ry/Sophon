package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestProjectFactsAreScopedByAsset(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-fact-scope.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "project-fact-scope",
		OwnerUserID: "user-1",
		Name:        "事实隔离测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, assetID := range []string{"asset-a", "asset-b"} {
		if err := db.CreateAsset(ctx, Asset{
			ID:          assetID,
			ProjectID:   project.ID,
			OwnerUserID: project.OwnerUserID,
			Name:        assetID,
			Kind:        "url",
			Value:       "https://" + assetID + ".example.com",
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("创建资产 %s 失败: %v", assetID, err)
		}
	}

	for _, item := range []ProjectFact{
		{
			ID: "fact-a", ProjectID: project.ID, AssetID: "asset-a",
			FactType: "service", Key: "service.fingerprint", Value: "nginx 1.18",
			Confidence: 90, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "fact-b", ProjectID: project.ID, AssetID: "asset-b",
			FactType: "service", Key: "service.fingerprint", Value: "nginx 1.24",
			Confidence: 90, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "fact-global", ProjectID: project.ID,
			FactType: "scope", Key: "scope.authorized", Value: "仅测试授权资产",
			Confidence: 100, CreatedAt: now, UpdatedAt: now,
		},
	} {
		if _, err := db.UpsertProjectFact(ctx, item); err != nil {
			t.Fatalf("写入事实 %s 失败: %v", item.ID, err)
		}
	}

	assetAFacts, err := db.ListProjectFactsByAsset(ctx, project.ID, "asset-a")
	if err != nil {
		t.Fatalf("读取资产 A 事实失败: %v", err)
	}
	if len(assetAFacts) != 2 {
		t.Fatalf("资产 A 应只看到自身事实和项目级事实，实际 %d: %+v", len(assetAFacts), assetAFacts)
	}
	for _, item := range assetAFacts {
		if item.AssetID == "asset-b" {
			t.Fatalf("资产 A 不应读取资产 B 的事实: %+v", item)
		}
	}

	factA, err := db.GetProjectFactByKey(ctx, project.ID, "asset-a", "service.fingerprint")
	if err != nil || factA == nil || factA.Value != "nginx 1.18" {
		t.Fatalf("资产 A 同 key 事实错误: %+v, err=%v", factA, err)
	}
	factB, err := db.GetProjectFactByKey(ctx, project.ID, "asset-b", "service.fingerprint")
	if err != nil || factB == nil || factB.Value != "nginx 1.24" {
		t.Fatalf("资产 B 同 key 事实错误: %+v, err=%v", factB, err)
	}
	projectFact, err := db.GetProjectFactByKey(ctx, project.ID, "", "service.fingerprint")
	if err != nil || projectFact != nil {
		t.Fatalf("项目级作用域不应命中资产事实: %+v, err=%v", projectFact, err)
	}
}

func TestSyncProjectGraphKeepsSameFactKeyPerAsset(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-graph-fact-scope.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "project-graph-fact-scope",
		OwnerUserID: "user-1",
		Name:        "攻击路径事实隔离测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, assetID := range []string{"asset-a", "asset-b"} {
		if err := db.CreateAsset(ctx, Asset{
			ID:          assetID,
			ProjectID:   project.ID,
			OwnerUserID: project.OwnerUserID,
			Name:        assetID,
			Kind:        "url",
			Value:       "https://" + assetID + ".example.com",
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("创建资产 %s 失败: %v", assetID, err)
		}
		if _, err := db.UpsertProjectFact(ctx, ProjectFact{
			ID: "fact-" + assetID, ProjectID: project.ID, AssetID: assetID,
			FactType: "service", Key: "service.fingerprint",
			Value: "nginx " + assetID, Confidence: 90,
			CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("写入资产事实失败: %v", err)
		}
	}

	if _, err := db.SyncProjectGraph(ctx, project); err != nil {
		t.Fatalf("同步攻击路径失败: %v", err)
	}
	nodes, err := db.ListProjectGraphNodes(ctx, project.ID)
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	factAssets := map[string]bool{}
	for _, node := range nodes {
		if node.Kind == "fact" && node.Title == "service.fingerprint" {
			factAssets[node.AssetID] = true
		}
	}
	if !factAssets["asset-a"] || !factAssets["asset-b"] {
		t.Fatalf("同名事实应按资产生成两个攻击路径节点，实际: %+v", nodes)
	}
}
