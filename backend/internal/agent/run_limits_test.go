package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestRunSubagentBudgetCapsWholeRun(t *testing.T) {
	ctx := withRunSubagentBudget(context.Background(), 2)
	if err := reserveRunSubagent(ctx); err != nil {
		t.Fatalf("第一个子 Agent 应允许启动: %v", err)
	}
	if err := reserveRunSubagent(ctx); err != nil {
		t.Fatalf("第二个子 Agent 应允许启动: %v", err)
	}
	err := reserveRunSubagent(ctx)
	if err == nil || !strings.Contains(err.Error(), "子 Agent 数量预算已耗尽") {
		t.Fatalf("超过总预算应拒绝启动，实际 err=%v", err)
	}
}

func TestRunBudgetClampsOversizedOptions(t *testing.T) {
	if got := clampRunBudget(0, defaultRunMaxSegments, maxRunMaxSegments); got != defaultRunMaxSegments {
		t.Fatalf("零值应使用默认预算，实际 %d", got)
	}
	if got := clampRunBudget(maxRunMaxSegments+100, defaultRunMaxSegments, maxRunMaxSegments); got != maxRunMaxSegments {
		t.Fatalf("超大段数应裁剪到 %d，实际 %d", maxRunMaxSegments, got)
	}
	service := &Service{cfg: config.Config{AgentMaxTurnTokens: maxRunMaxTurnTokens + 1}}
	if got := service.turnTokenBudget(); got != maxRunMaxTurnTokens {
		t.Fatalf("Token 配置应裁剪到 %d，实际 %d", maxRunMaxTurnTokens, got)
	}
}

func TestCoordinatedRunReservesPlannerAndWorkerBudget(t *testing.T) {
	if got := resolveRunSubagentLimit(missionPlan{Coordinated: true}, 1); got != 2 {
		t.Fatalf("协调任务至少应预留 Planner 和 Worker 两个子 Agent，实际 %d", got)
	}
	if got := resolveRunSubagentLimit(missionPlan{}, 1); got != 1 {
		t.Fatalf("非协调任务不应扩大子 Agent 预算，实际 %d", got)
	}
}

func TestResolveRunDurationSecondsAllowsUnlimited(t *testing.T) {
	if got := resolveRunDurationSeconds(0, 0); got != 0 {
		t.Fatalf("零配置和零请求应表示不限，实际 %d", got)
	}
	if got := resolveRunDurationSeconds(600, 0); got != 600 {
		t.Fatalf("应使用配置的运行时长 600，实际 %d", got)
	}
	if got := resolveRunDurationSeconds(600, 120); got != 120 {
		t.Fatalf("显式运行请求应覆盖配置，实际 %d", got)
	}
	if got := resolveRunDurationSeconds(-1, -1); got != 0 {
		t.Fatalf("负值应归一为不限，实际 %d", got)
	}
}

func TestRunTurnTokenSafetyBounds(t *testing.T) {
	if maxRunMaxTurnTokens != 100_000_000 {
		t.Fatalf("可配置单轮 Token 上限应为 100,000,000，实际 %d", maxRunMaxTurnTokens)
	}
}

func TestRunBudgetUsesMissionPlanLimitsForBoundedTask(t *testing.T) {
	plan := missionPlan{
		Mode:         missionModePentest,
		Bounded:      true,
		MaxSegments:  2,
		MaxToolCalls: 60,
	}
	segments, tools := resolveRunLimits(500, RunOptions{}, plan)
	if segments != 2 || tools != 60 {
		t.Fatalf("有界任务应使用意图预算 2/60，实际 %d/%d", segments, tools)
	}
	segments, tools = resolveRunLimits(500, RunOptions{MaxSegments: 1, MaxToolCalls: 30}, plan)
	if segments != 1 || tools != 30 {
		t.Fatalf("显式运行预算应继续收紧，实际 %d/%d", segments, tools)
	}
}

func TestRunBudgetIgnoresUnboundedMissionPlanCaps(t *testing.T) {
	segments, tools := resolveRunLimits(0, RunOptions{}, missionPlan{
		Mode:         missionModeCodeAudit,
		MaxSegments:  2,
		MaxToolCalls: 60,
	})
	if segments != defaultRunMaxSegments || tools != unlimitedRunIterations() {
		t.Fatalf("非有界任务不应继承模型预算，实际 %d/%d", segments, tools)
	}
}

func TestRunBudgetUsesConfiguredToolCallLimit(t *testing.T) {
	_, tools := resolveRunLimits(321, RunOptions{}, missionPlan{Mode: missionModeCodeAudit})
	if tools != 321 {
		t.Fatalf("应使用配置的工具调用上限 321，实际 %d", tools)
	}
}

func TestSegmentsForIterationBudget(t *testing.T) {
	if got := segmentsForIterationBudget(1000, maxSegmentIterations); got != 42 {
		t.Fatalf("1000 轮应按 24 轮单段换算为 42 段，实际 %d", got)
	}
	if got := segmentsForIterationBudget(24, maxSegmentIterations); got != 1 {
		t.Fatalf("24 轮应需要 1 段，实际 %d", got)
	}
	if got := segmentsForIterationBudget(0, maxSegmentIterations); got != unlimitedRunIterations() {
		t.Fatalf("0 轮应表示不限段数，实际 %d", got)
	}
}

func TestRunTokenBudgetCancelsAtLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx = withRunTokenBudget(ctx, 10, cancel)
	budget := runTokenBudgetFromContext(ctx)
	budget.add(9)
	if budget.exceeded() || ctx.Err() != nil {
		t.Fatalf("未达到上限时不应取消")
	}
	budget.add(1)
	if !budget.exceeded() || ctx.Err() == nil {
		t.Fatalf("达到上限时应立即取消当前 run")
	}
}

func TestValidateMissionVulnerabilityIDsDropsForeignAndUnknownIDs(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	validID := "vuln-valid-scope"
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          validID,
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "有效漏洞",
		Severity:    "high",
		Status:      "open",
		Target:      "https://app.example.com/api/user",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建测试漏洞失败: %v", err)
	}

	plan := service.validateMissionVulnerabilityIDs(ctx, "project-tools", "user-1", missionPlan{
		Mode:             missionModeCodeAudit,
		VulnerabilityIDs: []string{validID, "conv-tools", "0123456789abcdef0123456789abcdef"},
	})
	if len(plan.VulnerabilityIDs) != 1 || plan.VulnerabilityIDs[0] != validID {
		t.Fatalf("应只保留当前项目真实漏洞 ID: %+v", plan.VulnerabilityIDs)
	}
}
