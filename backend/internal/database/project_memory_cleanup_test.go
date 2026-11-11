package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupProjectMemoryArchivesAndMergesFacts(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "memory-cleanup.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-cleanup", OwnerUserID: "user-1", Name: "清理",
		Goals: "完成测试", Scope: "https://cleanup.example.com",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	asset := Asset{
		ID: "asset-cleanup", ProjectID: "project-cleanup", OwnerUserID: "user-1",
		Name: "清理目标", Kind: "url", Value: "https://cleanup.example.com",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	for index, key := range []string{
		"docs.qq.com-开放重定向被WAF拦截(20261023)",
		"docs.qq.com-开放重定向被WAF拦截(20261024)",
		"docs.qq.com-开放重定向被WAF拦截(20261025)",
	} {
		if _, err := db.UpsertProjectFact(ctx, ProjectFact{
			ID:         "cleanup-fact-" + string(rune('a'+index)),
			ProjectID:  "project-cleanup",
			AssetID:    asset.ID,
			FactType:   "recon",
			Key:        key,
			Summary:    "外域参数被 WAF 拦截",
			Body:       "复测编号 " + string(rune('1'+index)),
			Confidence: 80 + index,
			CreatedAt:  now,
			UpdatedAt:  now.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatalf("写入事实失败: %v", err)
		}
	}
	for _, fact := range []ProjectFact{
		{ID: "cleanup-test-result", ProjectID: "project-cleanup", AssetID: asset.ID, FactType: "test_result", Key: "target/test-result", Summary: "测试结果", CreatedAt: now, UpdatedAt: now},
		{ID: "cleanup-finding", ProjectID: "project-cleanup", AssetID: asset.ID, FactType: "finding", Key: "finding/sqli", Summary: "漏洞", CreatedAt: now, UpdatedAt: now},
	} {
		if _, err := db.UpsertProjectFact(ctx, fact); err != nil {
			t.Fatalf("写入跨表事实失败: %v", err)
		}
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-cleanup", AssetID: asset.ID,
		Dimension: "SQL注入", Status: "tested_clean",
		Result: "无注入", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建测试结果失败: %v", err)
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID: "cleanup-vulnerability", ProjectID: "project-cleanup",
		OwnerUserID: "user-1", AssetID: asset.ID, Title: "SQL 注入",
		Severity: "high", Status: "open", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	project, err := db.GetProject(ctx, "project-cleanup", "user-1")
	if err != nil {
		t.Fatalf("读取项目失败: %v", err)
	}
	if _, err := db.SyncProjectGraph(ctx, *project); err != nil {
		t.Fatalf("初始化攻击路径失败: %v", err)
	}
	stats, err := db.CleanupProjectMemory(ctx, "project-cleanup")
	if err != nil {
		t.Fatalf("清理项目记忆失败: %v", err)
	}
	if stats.ArchivedTestResultFacts != 1 || stats.ArchivedFindingFacts != 1 {
		t.Fatalf("跨表事实归档数量异常: %+v", stats)
	}
	if stats.MergedGroups != 1 || stats.ArchivedDuplicateFacts != 2 {
		t.Fatalf("日期变体合并数量异常: %+v", stats)
	}
	facts, err := db.ListProjectFacts(ctx, "project-cleanup")
	if err != nil {
		t.Fatalf("读取清理后事实失败: %v", err)
	}
	if len(facts) != 1 {
		t.Fatalf("清理后应保留 1 条活跃事实，实际 %d", len(facts))
	}
	if stats.GraphFactNodesAfter > maxMaterializedFactsPerAsset {
		t.Fatalf("清理后 fact 节点仍过多: %+v", stats)
	}
	if err := db.RestoreProjectFact(ctx, "project-cleanup", "cleanup-fact-a"); err != nil {
		t.Fatalf("恢复归档事实失败: %v", err)
	}
	restored, err := db.ListProjectFacts(ctx, "project-cleanup")
	if err != nil || len(restored) != 2 {
		t.Fatalf("恢复后应有 2 条活跃事实: %+v err=%v", restored, err)
	}
}
