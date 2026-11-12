package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestPlanHypothesesUsesConfiguredActiveLimit(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if _, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID: "project-tools",
		Dimension: "现存活跃假设",
		Status:    "untested",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建活跃假设失败: %v", err)
	}
	service.cfg.AgentMaxHypotheses = 1

	output, err := invokeProjectTool(
		t,
		service,
		ctx,
		"project_plan_hypotheses",
		map[string]interface{}{
			"hypotheses_json": `[{"asset_id":"asset-1","dimension":"SQL注入"}]`,
		},
	)
	if err != nil {
		t.Fatalf("达到上限不应返回错误: %v", err)
	}
	if !strings.Contains(output, "活跃假设已达到上限") ||
		!strings.Contains(output, "project_record_fact") ||
		!strings.Contains(output, "project_record_test") {
		t.Fatalf("达到上限应提示直接写回事实与测试结果: %s", output)
	}
}

func TestPlanHypothesesZeroActiveLimitIsUnlimited(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "asset-1",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "测试资产",
		Kind:        "domain",
		Value:       "app.example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID: "project-tools",
		Dimension: "现存活跃假设",
		Status:    "untested",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建活跃假设失败: %v", err)
	}
	service.cfg.AgentMaxHypotheses = 0

	output, err := invokeProjectTool(
		t,
		service,
		ctx,
		"project_plan_hypotheses",
		map[string]interface{}{
			"hypotheses_json": `[{"asset_id":"asset-1","dimension":"不限量假设"}]`,
		},
	)
	if err != nil {
		t.Fatalf("不限量时应能继续规划假设: %v", err)
	}
	if strings.Contains(output, "活跃假设已达到上限") {
		t.Fatalf("0 不应触发假设上限: %s", output)
	}
}
