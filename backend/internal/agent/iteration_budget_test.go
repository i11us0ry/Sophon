package agent

import (
	"testing"

	"sophon/internal/config"
)

func TestConfiguredSegmentLimitPreservesUserTotal(t *testing.T) {
	if got := configuredSegmentLimit(300); got != maxSegmentIterations {
		t.Fatalf("单段窗口应限制为 %d，实际 %d", maxSegmentIterations, got)
	}
	if got := configuredSegmentLimit(10); got != 10 {
		t.Fatalf("配置低于单段窗口时应保持配置值，实际 %d", got)
	}
	if got := configuredSegmentLimit(0); got != maxSegmentIterations {
		t.Fatalf("零值应回退到默认窗口，实际 %d", got)
	}
}

func TestTurnTokenBudgetZeroUsesSafetyDefault(t *testing.T) {
	service := &Service{cfg: config.Config{AgentMaxTurnTokens: 0}}
	if got := service.turnTokenBudget(); got != defaultRunMaxTurnTokens {
		t.Fatalf("0 应使用默认安全预算 %d，实际 %d", defaultRunMaxTurnTokens, got)
	}
	service.cfg.AgentMaxTurnTokens = 500000
	if got := service.turnTokenBudget(); got != 500000 {
		t.Fatalf("显式预算应生效，实际 %d", got)
	}
}
