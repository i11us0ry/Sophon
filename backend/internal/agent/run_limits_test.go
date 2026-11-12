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

func TestRunBudgetUsesMissionPlanLimitsForPentest(t *testing.T) {
	plan := missionPlan{
		Mode:         missionModePentest,
		MaxSegments:  2,
		MaxToolCalls: 60,
	}
	segments, tools := resolveRunLimits(RunOptions{}, plan)
	if segments != 2 || tools != 60 {
		t.Fatalf("渗透任务应使用意图预算 2/60，实际 %d/%d", segments, tools)
	}
	segments, tools = resolveRunLimits(RunOptions{MaxSegments: 1, MaxToolCalls: 30}, plan)
	if segments != 1 || tools != 30 {
		t.Fatalf("显式运行预算应继续收紧，实际 %d/%d", segments, tools)
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
