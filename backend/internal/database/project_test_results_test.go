package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestNormalizeProjectTestResultStatusAliases(t *testing.T) {
	for input, want := range map[string]string{
		"":            "untested",
		"open":        "untested",
		"pending":     "untested",
		"todo":        "untested",
		"queued":      "untested",
		"working":     "running",
		"in_progress": "running",
		"in-progress": "running",
	} {
		got, ok := NormalizeProjectTestResultStatus(input)
		if !ok || got != want {
			t.Fatalf("状态别名 %q 应归一为 %q，实际 %q ok=%v", input, want, got, ok)
		}
	}
	if got, ok := NormalizeProjectTestResultStatus("invalid"); ok || got != "invalid" {
		t.Fatalf("非法状态必须拒绝，实际 %q ok=%v", got, ok)
	}
}

func TestProjectTestResultsUpsertAndCoverageState(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test-results.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-tests", OwnerUserID: "user-1", Name: "测试矩阵",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-tests", AssetID: "asset-1", Dimension: "SQL注入",
		Technique: "boolean", Status: "running", CreatedAt: now,
	}); err != nil {
		t.Fatalf("创建测试结果失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-tests", AssetID: "asset-1", Dimension: "SQL注入",
		Technique: "boolean", Status: "tested_clean", Result: "布尔对照无差异",
		Evidence: "响应长度一致", Confidence: 90, CreatedAt: now,
	}); err != nil {
		t.Fatalf("更新测试结果失败: %v", err)
	}
	items, err := db.ListProjectTestResults(ctx, "project-tests", 20)
	if err != nil || len(items) != 1 {
		t.Fatalf("相同测试维度应按唯一键更新: %+v err=%v", items, err)
	}
	if items[0].Status != "tested_clean" || !IsProjectTestResultCovered(items[0].Status) {
		t.Fatalf("测试状态更新错误: %+v", items[0])
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-tests", AssetID: "asset-1", Dimension: "SQL注入",
		Technique: "boolean", Status: "untested",
	}); err != nil {
		t.Fatalf("重复规划失败: %v", err)
	}
	items, err = db.ListProjectTestResults(ctx, "project-tests", 20)
	if err != nil || len(items) != 1 || items[0].Status != "tested_clean" {
		t.Fatalf("已完成假设不应被降级: %+v err=%v", items, err)
	}
	if IsProjectTestResultCovered("running") || IsProjectTestResultCovered("blocked") {
		t.Fatalf("running/blocked 不应算作覆盖")
	}
}

func TestDeleteProjectCleansTestResults(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test-results-delete.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-delete-tests", OwnerUserID: "user-1", Name: "删除测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if _, err := db.UpsertProjectTestResult(ctx, ProjectTestResult{
		ProjectID: "project-delete-tests", AssetID: "asset-1",
		Dimension: "SQL注入", Status: "tested_clean",
		Result: "无差异", Evidence: "响应一致", CreatedAt: now,
	}); err != nil {
		t.Fatalf("创建测试结果失败: %v", err)
	}
	if err := db.DeleteProject(ctx, "project-delete-tests", "user-1"); err != nil {
		t.Fatalf("删除项目失败: %v", err)
	}
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_test_results WHERE project_id = ?`,
		"project-delete-tests",
	).Scan(&count); err != nil {
		t.Fatalf("查询测试结果失败: %v", err)
	}
	if count != 0 {
		t.Fatalf("删除项目后测试结果未清理: %d", count)
	}
}

func TestVulnerabilityFingerprintStableAcrossTitles(t *testing.T) {
	base := Vulnerability{
		ProjectID:         "project-1",
		AssetID:           "asset-1",
		Target:            "https://EXAMPLE.com/login?id=1&user=admin#fragment",
		VulnerabilityType: "SQL Injection",
	}
	first := VulnerabilityFingerprint(base)
	base.Title = "另一个标题"
	base.Target = "https://example.com/login?user=admin&id=1"
	second := VulnerabilityFingerprint(base)
	if first == "" || first != second {
		t.Fatalf("相同目标和漏洞类型应生成稳定指纹: %s != %s", first, second)
	}
	base.VulnerabilityType = "XSS"
	if VulnerabilityFingerprint(base) == first {
		t.Fatalf("不同漏洞类型不应生成相同指纹")
	}
}

func TestVulnerabilityEvidenceValidation(t *testing.T) {
	item := Vulnerability{
		Target:            "https://a.com/x?id=1",
		Severity:          "high",
		ReproductionSteps: "id=1 AND 1=1",
		EvidenceRefs:      []string{"tool:sqlmap-1"},
		VerificationState: "verified",
	}
	if err := ValidateVulnerabilityEvidence(item); err != nil {
		t.Fatalf("完整证据应通过校验: %v", err)
	}
	item.EvidenceRefs = nil
	if err := ValidateVulnerabilityEvidence(item); err == nil {
		t.Fatalf("无证据应校验失败")
	}
	item.Evidence = "HTTP 差异"
	item.ReproductionSteps = ""
	if err := ValidateVulnerabilityEvidence(item); err == nil {
		t.Fatalf("高危漏洞缺少 POC 应校验失败")
	}
}
