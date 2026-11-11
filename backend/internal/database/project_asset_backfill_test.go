package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestBackfillProjectAssetsLinksFactsAndVulnerabilities(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-backfill.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "project-assets",
		OwnerUserID: "user-1",
		Name:        "资产回填",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if _, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID:         newID(),
		ProjectID:  project.ID,
		FactType:   "fingerprint",
		Key:        "目标服务",
		Summary:    "目标服务",
		Relation:   "asset:未匹配资产文本",
		Confidence: 90,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("写入事实失败: %v", err)
	}
	vulnerability := Vulnerability{
		ID:          newID(),
		ProjectID:   project.ID,
		OwnerUserID: "user-1",
		Title:       "测试漏洞",
		Severity:    "high",
		Status:      "open",
		Target:      "https://10.0.0.1/pikachu/vul/test.php",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateVulnerability(ctx, vulnerability); err != nil {
		t.Fatalf("写入漏洞失败: %v", err)
	}

	if err := db.backfillProjectAssets(ctx); err != nil {
		t.Fatalf("回填资产失败: %v", err)
	}
	assets, err := db.ListProjectAssets(ctx, project.ID, "user-1")
	if err != nil {
		t.Fatalf("读取资产失败: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("事实关系不应自动创建资产，应仅回填 1 个漏洞资产，实际 %d: %+v", len(assets), assets)
	}
	if assets[0].Value != vulnerability.Target || assets[0].RiskScore != 80 {
		t.Fatalf("高危漏洞关联资产风险分应为 80: %+v", assets[0])
	}
	item, err := db.GetVulnerability(ctx, vulnerability.ID, "user-1")
	if err != nil || item.AssetID == "" {
		t.Fatalf("漏洞应关联回填资产: %+v, err=%v", item, err)
	}

	fact, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID:         newID(),
		ProjectID:  project.ID,
		FactType:   "fingerprint",
		Key:        "目标服务",
		Summary:    "目标服务",
		Relation:   "asset:" + item.AssetID,
		Confidence: 90,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("更新事实关系失败: %v", err)
	}
	if err := db.CreateProjectGraphNode(ctx, GraphNode{
		ID:        newID(),
		ProjectID: project.ID,
		Kind:      "fact",
		Title:     fact.Key,
		Status:    "confirmed",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建事实节点失败: %v", err)
	}

	if err := db.backfillProjectAssets(ctx); err != nil {
		t.Fatalf("重复回填失败: %v", err)
	}
	assets, err = db.ListProjectAssets(ctx, project.ID, "user-1")
	if err != nil || len(assets) != 1 {
		t.Fatalf("重复回填应保持 1 个资产: %+v, err=%v", assets, err)
	}
	facts, err := db.ListProjectFacts(ctx, project.ID)
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	if len(facts) != 1 || facts[0].Relation != "asset_id:"+item.AssetID {
		t.Fatalf("事实关系应迁移为稳定资产 ID: %+v", facts)
	}
	nodes, err := db.ListProjectGraphNodes(ctx, project.ID)
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	for _, node := range nodes {
		if node.Kind == "fact" && node.AssetID != item.AssetID {
			t.Fatalf("事实节点应关联稳定资产 ID: %+v", node)
		}
	}
}
