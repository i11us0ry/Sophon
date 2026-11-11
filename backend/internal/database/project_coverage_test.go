package database

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestProjectCoverageComputesQueueAndRatio(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "coverage.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-cov",
		OwnerUserID: "user-1",
		Name:        "覆盖率测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	assets := []Asset{
		{
			ID: "asset-tested", ProjectID: "project-cov", OwnerUserID: "user-1",
			Name: "已测主机", Kind: "url", Value: "https://a.com/x?id=1",
			Status: "active", Criticality: "medium", RiskScore: 10,
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "asset-untested", ProjectID: "project-cov", OwnerUserID: "user-1",
			Name: "未测主机", Kind: "ip", Value: "10.0.0.2",
			Status: "active", Criticality: "critical", RiskScore: 90,
			CreatedAt: now, UpdatedAt: now,
		},
	}
	for _, asset := range assets {
		if err := db.CreateAsset(ctx, asset); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID: "finding-1", ProjectID: "project-cov", OwnerUserID: "user-1",
		Title: "SQL 注入", Severity: "critical", Status: "confirmed",
		AssetID: "asset-tested", Target: "https://a.com/x?id=1",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ID: "test-1", ProjectID: "project-cov", AssetID: "asset-tested",
		Dimension: "SQL注入", Status: "tested_clean",
		Result: "参数化查询未发现注入", Evidence: "布尔对照响应一致",
		Confidence: 90, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建测试结果失败: %v", err)
	}
	if _, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID: "fact-1", ProjectID: "project-cov", Key: "目标IP",
		Summary: "10.0.0.1", Confidence: 90, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建事实失败: %v", err)
	}
	if err := db.CreateProjectGraphNode(ctx, GraphNode{
		ID: "intent-1", ProjectID: "project-cov", Kind: "intent",
		Title: "验证 SQL 注入", Status: "running", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建意图失败: %v", err)
	}

	coverage, err := db.ProjectCoverage(ctx, "project-cov", "user-1")
	if err != nil {
		t.Fatalf("计算覆盖率失败: %v", err)
	}
	if coverage.AssetsTotal != 2 || coverage.AssetsTested != 1 || coverage.AssetsUntested != 1 {
		t.Fatalf("资产覆盖计算错误: %+v", coverage)
	}
	if coverage.CoverageRatio != 0.5 {
		t.Fatalf("覆盖率应为 0.5，实际 %v", coverage.CoverageRatio)
	}
	if coverage.AssetsCovered != 1 || coverage.AssetsPartial != 0 ||
		coverage.FullCoverageRatio != 0.5 {
		t.Fatalf("完整覆盖统计错误: %+v", coverage)
	}
	if len(coverage.AssetCoverage) != 2 {
		t.Fatalf("资产覆盖明细数量错误: %+v", coverage.AssetCoverage)
	}
	if coverage.TestsTotal != 1 || coverage.TestsCovered != 1 || coverage.TestCoverageRatio != 1 {
		t.Fatalf("测试覆盖计算错误: %+v", coverage)
	}
	if coverage.FindingsTotal != 1 || coverage.FindingsConfirmed != 1 || coverage.FindingsWithoutEvidence != 1 {
		t.Fatalf("漏洞统计错误: %+v", coverage)
	}
	if coverage.FactsWithoutEvidence != 1 || coverage.IntentsRunning != 1 {
		t.Fatalf("事实/意图统计错误: %+v", coverage)
	}
	if len(coverage.UntestedAssets) != 1 || coverage.UntestedAssets[0].ID != "asset-untested" {
		t.Fatalf("未测试资产列表错误: %+v", coverage.UntestedAssets)
	}
	if len(coverage.NextTargets) == 0 {
		t.Fatalf("未覆盖队列不应为空")
	}
	for index := 1; index < len(coverage.NextTargets); index++ {
		if coverage.NextTargets[index-1].Score < coverage.NextTargets[index].Score {
			t.Fatalf("队列应按优先级降序: %+v", coverage.NextTargets)
		}
	}
	foundAsset := false
	for _, target := range coverage.NextTargets {
		if target.Kind == "asset" && target.RefID == "asset-untested" {
			foundAsset = true
		}
	}
	if !foundAsset {
		t.Fatalf("未测试资产应进入队列: %+v", coverage.NextTargets)
	}

	// 跨租户读取必须失败（fail-closed）。
	if _, err := db.ProjectCoverage(ctx, "project-cov", "user-2"); err == nil {
		t.Fatalf("其他用户不应读取到项目覆盖率")
	}
}

func TestProjectCoverageTracksPartialAndLargeResultSets(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "coverage-partial.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-partial",
		OwnerUserID: "user-1",
		Name:        "部分覆盖测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	assets := []Asset{
		{
			ID: "asset-partial", ProjectID: "project-partial", OwnerUserID: "user-1",
			Name: "部分覆盖", Kind: "url", Value: "https://partial.example",
			Status: "active", Criticality: "high", RiskScore: 60,
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "asset-covered", ProjectID: "project-partial", OwnerUserID: "user-1",
			Name: "完整覆盖", Kind: "url", Value: "https://covered.example",
			Status: "active", Criticality: "medium", RiskScore: 30,
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "asset-untested", ProjectID: "project-partial", OwnerUserID: "user-1",
			Name: "未测试", Kind: "ip", Value: "10.0.0.3",
			Status: "active", Criticality: "critical", RiskScore: 90,
			CreatedAt: now, UpdatedAt: now,
		},
	}
	for _, asset := range assets {
		if err := db.CreateAsset(ctx, asset); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}

	testItems := []ProjectTestResult{
		{
			ID: "partial-clean", ProjectID: "project-partial", AssetID: "asset-partial",
			Dimension: "SQL注入", Status: "tested_clean", Required: true,
			Evidence: "布尔响应一致", CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "partial-blocked", ProjectID: "project-partial", AssetID: "asset-partial",
			Dimension: "越权访问", Status: "blocked", Required: true,
			Evidence: "WAF 阻断", CreatedAt: now, UpdatedAt: now,
		},
	}
	for index := 0; index < 501; index++ {
		testItems = append(testItems, ProjectTestResult{
			ID:        fmt.Sprintf("covered-%03d", index),
			ProjectID: "project-partial",
			AssetID:   "asset-covered",
			Dimension: fmt.Sprintf("dimension-%03d", index),
			Status:    "tested_clean",
			Required:  true,
			Evidence:  "对照响应一致",
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	for _, item := range testItems {
		if _, err := db.UpsertProjectTestResult(ctx, item); err != nil {
			t.Fatalf("创建测试结果失败: %v", err)
		}
	}

	coverage, err := db.ProjectCoverage(ctx, "project-partial", "user-1")
	if err != nil {
		t.Fatalf("计算覆盖率失败: %v", err)
	}
	if coverage.AssetsTotal != 3 || coverage.AssetsTested != 2 ||
		coverage.AssetsCovered != 1 || coverage.AssetsPartial != 1 ||
		coverage.AssetsBlocked != 1 || coverage.AssetsUntested != 1 {
		t.Fatalf("资产覆盖分类错误: %+v", coverage)
	}
	if coverage.TestsTotal != 503 || coverage.TestsCovered != 502 ||
		coverage.TestsBlocked != 1 {
		t.Fatalf("测试聚合被截断: %+v", coverage)
	}
	if coverage.FullCoverageRatio < 0.333 || coverage.FullCoverageRatio > 0.334 {
		t.Fatalf("完整覆盖率错误: %v", coverage.FullCoverageRatio)
	}
	states := make(map[string]AssetCoverageState, len(coverage.AssetCoverage))
	for _, state := range coverage.AssetCoverage {
		states[state.AssetID] = state
	}
	if states["asset-partial"].Status != "blocked" {
		t.Fatalf("部分覆盖资产状态错误: %+v", states["asset-partial"])
	}
	if states["asset-covered"].Status != "covered" {
		t.Fatalf("完整覆盖资产状态错误: %+v", states["asset-covered"])
	}
	if states["asset-untested"].Status != "untested" {
		t.Fatalf("未测试资产状态错误: %+v", states["asset-untested"])
	}
}

func TestAggregateProjectVulnerabilityCoverageDoesNotTruncate(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "coverage-findings.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-findings",
		OwnerUserID: "user-1",
		Name:        "漏洞覆盖测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID: "asset-findings", ProjectID: "project-findings", OwnerUserID: "user-1",
		Name: "漏洞资产", Kind: "url", Value: "https://findings.example",
		Status: "active", Criticality: "high", RiskScore: 80,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("开启事务失败: %v", err)
	}
	for index := 0; index < 1001; index++ {
		evidence := "复现响应"
		if index%2 == 0 {
			evidence = ""
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO vulnerabilities (
				id, project_id, asset_id, owner_user_id, title, severity, status,
				evidence, target, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("finding-%04d", index),
			"project-findings",
			"asset-findings",
			"user-1",
			fmt.Sprintf("finding-%d", index),
			"medium",
			"confirmed",
			evidence,
			"https://findings.example",
			now.Unix(),
			now.Unix(),
		); err != nil {
			_ = tx.Rollback()
			t.Fatalf("插入漏洞失败: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交漏洞失败: %v", err)
	}

	coverage, err := db.ProjectCoverage(ctx, "project-findings", "user-1")
	if err != nil {
		t.Fatalf("计算覆盖率失败: %v", err)
	}
	if coverage.FindingsTotal != 1001 ||
		coverage.FindingsConfirmed != 1001 ||
		coverage.FindingsWithoutEvidence != 501 {
		t.Fatalf("漏洞聚合被截断: %+v", coverage)
	}
	if coverage.AssetsTested != 1 || coverage.AssetsCovered != 0 ||
		coverage.AssetsPartial != 1 {
		t.Fatalf("有证据漏洞应产生部分覆盖: %+v", coverage)
	}
}
