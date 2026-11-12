package agent

import (
	"context"
	"strings"
	"testing"
)

func TestPlatformVerificationWorkflowAppliedToMainAndSubAgents(t *testing.T) {
	service := &Service{}
	mainInstruction := service.mainAgentInstruction(context.Background())
	subAgentInstruction := (&subAgentRunner{service: service}).instruction(context.Background())
	for name, instruction := range map[string]string{
		"main":     mainInstruction,
		"subagent": subAgentInstruction,
	} {
		for _, expected := range []string{
			"WP-1 利用前·等价空间扩展",
			"WP-2 利用后·必要条件最小化",
			"WP-3 外部先验·搜索空间补全",
			"Fast Path 或未启动 Planner 时，不要求额外启动子 Agent",
			"Planner 不发送网络请求",
			"Worker 必须实际执行",
		} {
			if !strings.Contains(instruction, expected) {
				t.Fatalf("%s 指令缺少 %q", name, expected)
			}
		}
	}
}

func TestVerificationWorkflowIncludedInWritebackAndFinalization(t *testing.T) {
	for name, text := range map[string]string{
		"writeback":    projectWritebackGuidance,
		"finalization": finalizationSynthesisPrompt,
	} {
		if !strings.Contains(text, "WP-1") || !strings.Contains(text, "WP-2") {
			t.Fatalf("%s 缺少验证流程检查", name)
		}
	}
}

func TestWithPlatformVerificationWorkflowPreservesBaseInstruction(t *testing.T) {
	instruction := withPlatformVerificationWorkflow("基础指令")
	if !strings.HasPrefix(instruction, "基础指令") ||
		!strings.Contains(instruction, "WP-1") ||
		!strings.Contains(instruction, "WP-3") {
		t.Fatalf("平台验证流程注入异常: %s", instruction)
	}
}
