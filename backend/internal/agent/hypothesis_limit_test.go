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
