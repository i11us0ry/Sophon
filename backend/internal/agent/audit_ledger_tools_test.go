package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestProjectAuditLedgerRecordsScopeMatrixRescanAndCheckpoint(t *testing.T) {
	if !localAnalysisToolAllowed("project_record_audit") {
		t.Fatal("本地代码审计阶段应允许 project_record_audit")
	}
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	asset := database.Asset{
		ID:          "asset-audit-ledger",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "审计服务",
		Kind:        "url",
		Value:       "https://audit.example",
		Status:      "active",
		Criticality: "high",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := service.db.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	hypothesis, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ID:        "hyp-sql-zero-param",
		ProjectID: "project-tools",
		AssetID:   asset.ID,
		Dimension: "SQL 注入",
		Technique: "zero-parameter",
		Status:    "untested",
		Required:  true,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建假设失败: %v", err)
	}

	if _, err := invokeProjectTool(t, service, ctx, "project_record_audit", map[string]interface{}{
		"action":              "scope",
		"included_categories": []string{"SQL 注入", "文件上传"},
		"excluded_categories": []string{"业务逻辑"},
		"evidence":            "项目目标明确要求 SQL 注入和文件上传，业务逻辑未纳入",
	}); err != nil {
		t.Fatalf("记录审计范围失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_audit", map[string]interface{}{
		"action":          "cell",
		"asset_id":        asset.ID,
		"service":         "SQLScriptService",
		"entry":           "GetDataFromStoredProc",
		"shape":           "SQL-zero-parameter",
		"surface":         "kdsvc",
		"coverage_status": "not_audited",
	}); err != nil {
		t.Fatalf("记录未审计矩阵失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_audit", map[string]interface{}{
		"action":          "rescan",
		"asset_id":        asset.ID,
		"service":         "SQLScriptService",
		"shape":           "SQL-zero-parameter",
		"rescan_surfaces": []string{"asmx", "ashx"},
		"next_action":     "回扫零参数 SQL 执行链",
	}); err != nil {
		t.Fatalf("记录同类回扫失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_audit", map[string]interface{}{
		"action":               "checkpoint",
		"active_hypothesis_id": hypothesis.ID,
		"pending_directions":   []string{"kdsvc 入口", "storedProc executeType"},
		"next_action":          "先回扫 kdsvc 零参数入口",
	}); err != nil {
		t.Fatalf("记录断点失败: %v", err)
	}

	facts, err := service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取事实失败: %v", err)
	}
	cellCount := 0
	hasScope := false
	hasCheckpoint := false
	for _, fact := range facts {
		switch fact.SubjectType {
		case auditSubjectScope:
			hasScope = true
		case auditSubjectCheckpoint:
			hasCheckpoint = true
		case auditSubjectCell:
			if fact.ObjectKey == "not_audited" {
				cellCount++
			}
		}
	}
	if !hasScope || !hasCheckpoint || cellCount != 3 {
		t.Fatalf("审计台账事实不完整: scope=%v checkpoint=%v cells=%d facts=%+v", hasScope, hasCheckpoint, cellCount, facts)
	}

	coverage, err := service.db.ProjectCoverage(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取覆盖率失败: %v", err)
	}
	if coverage.FactsWithoutEvidence != 0 {
		t.Fatalf("审计台账不应被计入事实证据缺口: %+v", coverage)
	}
	auditTargets := 0
	for _, target := range coverage.NextTargets {
		if target.Kind == "audit_cell" && strings.Contains(target.Reason, "not_audited") {
			auditTargets++
		}
	}
	if auditTargets < 3 {
		t.Fatalf("未审计单元格未进入未覆盖队列: %+v", coverage.NextTargets)
	}

	situation := service.projectSituation(ctx, "project-tools", "user-1")
	for _, want := range []string{"审计台账", "范围：纳入=", "NOT_AUDITED", "最近断点", "先回扫 kdsvc 零参数入口"} {
		if !strings.Contains(situation, want) {
			t.Fatalf("任务态势缺少审计台账内容 %q:\n%s", want, situation)
		}
	}
}

func TestProjectAuditRejectsReservedFactBypassAndMismatchedState(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key":          "business/forged-audit-cell",
		"summary":      "伪造未审计单元格",
		"fact_type":    "constraint",
		"subject_type": "audit_cell",
		"predicate":    "coverage",
		"object_type":  "coverage",
		"object_key":   "not_audited",
	}); err == nil || !strings.Contains(err.Error(), "project_record_audit") {
		t.Fatalf("通用事实工具不应绕审计写入校验: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key":       "business/audit-scope",
		"summary":   "伪造审计范围",
		"fact_type": "scope",
	}); err == nil || !strings.Contains(err.Error(), "project_record_audit") {
		t.Fatalf("保留审计 key 不应由通用事实工具覆盖: %v", err)
	}

	asset := database.Asset{
		ID:          "asset-audit-state",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "状态测试",
		Kind:        "url",
		Value:       "https://audit-state.example",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := service.db.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	_, err := invokeProjectTool(t, service, ctx, "project_record_audit", map[string]interface{}{
		"action":           "cell",
		"asset_id":         asset.ID,
		"service":          "SQLScriptService",
		"entry":            "Execute",
		"shape":            "SQL-zero-parameter",
		"surface":          "asmx",
		"coverage_status":  "not_audited",
		"conclusion_state": "CONFIRMED",
	})
	if err == nil || !strings.Contains(err.Error(), "NOT_AUDITED") {
		t.Fatalf("未审计单元格不能记录为 CONFIRMED: %v", err)
	}
}

func TestProjectAuditCellRequiresEvidenceForTestedConclusions(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	asset := database.Asset{
		ID:          "asset-audit-evidence",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "证据测试",
		Kind:        "url",
		Value:       "https://evidence-audit.example",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := service.db.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	_, err := invokeProjectTool(t, service, ctx, "project_record_audit", map[string]interface{}{
		"action":           "cell",
		"asset_id":         asset.ID,
		"service":          "SQLScriptService",
		"entry":            "Execute",
		"shape":            "SQL-zero-parameter",
		"surface":          "asmx",
		"coverage_status":  "tested",
		"conclusion_state": "NOT_EXPLOITABLE",
		"result":           "未发现差异",
	})
	if err == nil || !strings.Contains(err.Error(), "必须提供证据") {
		t.Fatalf("NOT_EXPLOITABLE 无证据应被拒绝: %v", err)
	}
}
