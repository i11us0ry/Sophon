package config

import (
	"strings"
	"testing"
)

func TestPickHITLToolsSemantics(t *testing.T) {
	t.Setenv("SOPHON_HITL_TOOLS", "")

	// 未配置 tools（nil）→ 使用内置高风险清单
	configured := pickHITLTools(nil)
	for _, tool := range []string{"exec", "execute-python-script", "install-python-package"} {
		if !strings.Contains(configured, tool) {
			t.Fatalf("默认审批清单缺少 %s：%s", tool, configured)
		}
	}

	// 显式空列表 → 空字符串，表示所有工具都需要审批
	if empty := pickHITLTools([]string{}); empty != "" {
		t.Fatalf("显式空列表应返回空字符串，实际 %q", empty)
	}

	// 显式列表 → 原样（去空白）
	if custom := pickHITLTools([]string{" calculator ", "", "nmap"}); custom != "calculator,nmap" {
		t.Fatalf("显式列表处理不正确：%q", custom)
	}

	// 环境变量优先级最高
	t.Setenv("SOPHON_HITL_TOOLS", "exec,calculator")
	if fromEnv := pickHITLTools([]string{"nmap"}); fromEnv != "exec,calculator" {
		t.Fatalf("环境变量应覆盖配置：%q", fromEnv)
	}
}

func TestNormalizeAgentMaxHypotheses(t *testing.T) {
	cases := []struct {
		input int
		want  int
	}{
		{0, 0},
		{-1, 0},
		{1, 1},
		{200, 200},
		{2000, 2000},
		{5000, 2000},
	}
	for _, item := range cases {
		if got := normalizeAgentMaxHypotheses(item.input); got != item.want {
			t.Fatalf("normalizeAgentMaxHypotheses(%d) = %d, want %d", item.input, got, item.want)
		}
	}
}

func TestZeroAgentLimitsRemainUnlimited(t *testing.T) {
	t.Setenv("SOPHON_AGENT_MAX_TURN_TOKENS", "")
	t.Setenv("SOPHON_AGENT_MAX_ITERATIONS", "")
	t.Setenv("SOPHON_AGENT_MAX_HYPOTHESES", "")
	zero := 0
	if got := pickIntAllowZero("SOPHON_AGENT_MAX_TURN_TOKENS", &zero, 40); got != 0 {
		t.Fatalf("Token 0 应为不限，实际 %d", got)
	}
	if got := pickIntAllowZero("SOPHON_AGENT_MAX_ITERATIONS", &zero, 40); got != 0 {
		t.Fatalf("迭代 0 应为不限，实际 %d", got)
	}
	if got := normalizeAgentMaxHypotheses(pickIntAllowZero("SOPHON_AGENT_MAX_HYPOTHESES", &zero, 200)); got != 0 {
		t.Fatalf("假设 0 应为不限，实际 %d", got)
	}
}

func TestNormalizeSubagentBudgets(t *testing.T) {
	if got := normalizeSubagentMaxToolCalls(0); got != 80 {
		t.Fatalf("默认工具调用预算错误: %d", got)
	}
	if got := normalizeSubagentMaxToolCalls(999); got != 500 {
		t.Fatalf("工具调用预算上限错误: %d", got)
	}
	if got := normalizeSubagentMaxDuration(10); got != 60 {
		t.Fatalf("耗时预算下限错误: %d", got)
	}
	if got := normalizeSubagentMaxCPUSeconds(0); got != 900 {
		t.Fatalf("默认 CPU 预算错误: %d", got)
	}
	if got := normalizeSubagentMaxProcesses(0); got != 8 {
		t.Fatalf("默认进程预算错误: %d", got)
	}
}

func TestDefaultStorageIncludesToolJobs(t *testing.T) {
	category, ok := defaultStorageConfig().Categories["tool_jobs"]
	if !ok || !category.Enabled || category.RetentionDays <= 0 {
		t.Fatalf("tool_jobs 存储清理默认配置缺失: %+v", category)
	}
}
