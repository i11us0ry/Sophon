package agent

import (
	"strings"
	"testing"

	"sophon/internal/database"
)

func TestReportFindingEnqueuesPlannerTrigger(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(
		t,
		service,
		ctx,
		"project_report_finding",
		standardFindingArgs(map[string]interface{}{
			"target": "https://example.test/item",
		}),
	); err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	pending, err := service.db.CountPendingAgentTriggers(ctx, "conv-tools")
	if err != nil {
		t.Fatalf("读取 Trigger 失败: %v", err)
	}
	if pending == 0 {
		t.Fatal("Finding 写回后应产生 Planner Trigger")
	}
}

func TestRenderPlannerTriggersIncludesConcreteChange(t *testing.T) {
	text := renderPlannerTriggers([]plannerTriggerSummary{
		{
			Kind:     database.AgentTriggerFinding,
			IntentID: "intent-1",
			Detail:   "confirmed RCE",
		},
		{
			Kind:  database.AgentTriggerHint,
			Hints: []string{"focus on upload"},
		},
	})
	for _, expected := range []string{"Worker 产生 Finding", "intent-1", "confirmed RCE", "focus on upload"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Trigger 渲染缺少 %q: %s", expected, text)
		}
	}
}
