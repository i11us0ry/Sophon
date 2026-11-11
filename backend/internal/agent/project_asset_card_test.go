package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

func TestProjectAssetCardScopesContextToCurrentAsset(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	for _, asset := range []database.Asset{
		{
			ID: "asset-current", ProjectID: "project-tools", OwnerUserID: "user-1",
			Name: "当前资产", Kind: "url", Value: "https://current.example",
			Status: "active", Criticality: "high", RiskScore: 80,
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "asset-other", ProjectID: "project-tools", OwnerUserID: "user-1",
			Name: "其他资产", Kind: "url", Value: "https://other.example",
			Status: "active", Criticality: "low", RiskScore: 10,
			CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := service.db.CreateAsset(ctx, asset); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}
	if _, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ID: "asset-current-test", ProjectID: "project-tools", AssetID: "asset-current",
		Dimension: "越权访问", Technique: "auth-context", Status: "running",
		Required: true, Priority: 90, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建测试计划失败: %v", err)
	}
	if _, err := service.db.UpsertProjectFact(ctx, database.ProjectFact{
		ID: "asset-current-fact", ProjectID: "project-tools", AssetID: "asset-current",
		Key: "service/profile", Summary: "当前资产运行内部管理后台",
		MemoryKind: "service", Confidence: 90, Evidence: "首页标题",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产事实失败: %v", err)
	}
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID: "asset-current-finding", ProjectID: "project-tools", AssetID: "asset-current",
		OwnerUserID: "user-1", Title: "当前资产漏洞", Severity: "high",
		Status: "confirmed", Evidence: "复现响应", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID: "asset-current-intent", ProjectID: "project-tools", AssetID: "asset-current",
		Kind: "intent", Title: "验证资产越权", Status: "open",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产意图失败: %v", err)
	}

	assetCtx := execctx.WithAssetID(ctx, "asset-current")
	output, err := invokeProjectTool(t, service, assetCtx, "project_asset_card", map[string]interface{}{})
	if err != nil {
		t.Fatalf("读取资产卡片失败: %v", err)
	}
	for _, expected := range []string{
		"https://current.example",
		"越权访问",
		"当前资产运行内部管理后台",
		"当前资产漏洞",
		"验证资产越权",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("资产卡片缺少 %q: %s", expected, output)
		}
	}
	if strings.Contains(output, "https://other.example") {
		t.Fatalf("资产卡片不应包含其他资产: %s", output)
	}

	situation := service.projectSituationForContext(assetCtx, "project-tools", "user-1", "conv-tools")
	if !strings.Contains(situation, "当前资产卡片") ||
		!strings.Contains(situation, "https://current.example") {
		t.Fatalf("态势包未注入资产卡片: %s", situation)
	}
	if strings.Contains(situation, "https://other.example") {
		t.Fatalf("态势包不应包含其他资产: %s", situation)
	}
}
