package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestProjectFactAndEvidenceGapFilters(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "project-query-pagination.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-query", OwnerUserID: "user-1", Name: "分页查询",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID: "asset-query", ProjectID: "project-query", OwnerUserID: "user-1",
		Name: "主站", Kind: "url", Value: "https://example.com", Status: "active",
		Source: AssetSourceManual, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	for _, fact := range []ProjectFact{
		{
			ID: "fact-with-evidence", ProjectID: "project-query", AssetID: "asset-query",
			FactType: "asset", Key: "框架", Summary: "Vue 前端", Value: "Vue 3",
			Evidence: "响应头 x-powered-by", Confidence: 90, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "fact-missing-evidence", ProjectID: "project-query", AssetID: "asset-query",
			FactType: "asset", Key: "后台路径", Summary: "疑似后台入口", Value: "/admin",
			Confidence: 60, CreatedAt: now, UpdatedAt: now.Add(time.Second),
		},
	} {
		if _, err := db.UpsertProjectFact(ctx, fact); err != nil {
			t.Fatalf("创建事实失败: %v", err)
		}
	}
	items, total, err := db.ListProjectFactsPageFiltered(ctx, ProjectFactFilter{
		ProjectID: "project-query",
		AssetID:   "asset-query",
		Status:    "missing_evidence",
		Query:     "后台",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("查询事实失败: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != "fact-missing-evidence" {
		t.Fatalf("事实过滤结果错误: total=%d items=%+v", total, items)
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID: "finding-gap", ProjectID: "project-query", AssetID: "asset-query",
		OwnerUserID: "user-1", Title: "任意文件上传", Severity: "high",
		Status: "confirmed", VulnerabilityType: "文件上传", Target: "https://example.com/upload",
		Description: "上传接口缺少限制", EvidenceRefs: []string{}, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	gaps, gapTotal, err := db.ListEvidenceGaps(ctx, EvidenceGapFilter{
		ProjectID: "project-query",
		AssetID:   "asset-query",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("查询证据缺口失败: %v", err)
	}
	if gapTotal != 2 || len(gaps) != 2 {
		t.Fatalf("证据缺口数量错误: total=%d items=%+v", gapTotal, gaps)
	}
	findingGaps, findingTotal, err := db.ListEvidenceGaps(ctx, EvidenceGapFilter{
		ProjectID: "project-query",
		AssetID:   "asset-query",
		Kind:      "finding",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("查询漏洞证据缺口失败: %v", err)
	}
	if findingTotal != 1 || len(findingGaps) != 1 || findingGaps[0].Kind != "finding" {
		t.Fatalf("漏洞证据缺口过滤错误: total=%d items=%+v", findingTotal, findingGaps)
	}
	if _, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID: "fact-literal-percent", ProjectID: "project-query", AssetID: "asset-query",
		FactType: "asset", Key: "命中率", Summary: "命中率 100%", Value: "100%",
		Confidence: 80, CreatedAt: now, UpdatedAt: now.Add(2 * time.Second),
	}); err != nil {
		t.Fatalf("创建百分号事实失败: %v", err)
	}
	literal, literalTotal, err := db.ListProjectFactsPageFiltered(ctx, ProjectFactFilter{
		ProjectID: "project-query",
		Query:     "100%",
		Limit:     10,
	})
	if err != nil || literalTotal != 1 || len(literal) != 1 || literal[0].ID != "fact-literal-percent" {
		t.Fatalf("事实搜索应把 %% 当作普通字符: total=%d items=%+v err=%v", literalTotal, literal, err)
	}
}
