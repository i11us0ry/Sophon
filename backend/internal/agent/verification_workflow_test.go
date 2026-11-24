package agent

import (
	"context"
	"strings"
	"testing"
)

func TestAgentInstructionsDoNotInjectMandatoryVerificationWorkflow(t *testing.T) {
	service := &Service{}
	mainInstruction := service.mainAgentInstruction(context.Background())
	subAgentInstruction := (&subAgentRunner{service: service}).instruction(context.Background())
	for name, instruction := range map[string]string{
		"main":     mainInstruction,
		"subagent": subAgentInstruction,
	} {
		for _, forbidden := range []string{
			"WP-1",
			"WP-2",
			"WP-3",
			"平台通用验证流程",
		} {
			if strings.Contains(instruction, forbidden) {
				t.Fatalf("%s 指令不应包含固定验证流程 %q", name, forbidden)
			}
		}
	}
}

func TestProjectGuidanceDoesNotDefineMandatoryWorkflow(t *testing.T) {
	for _, forbidden := range []string{"项目写回纪律（强制）", "测试前用", "必须实际执行"} {
		if strings.Contains(projectWritebackGuidance, forbidden) ||
			strings.Contains(finalizationSynthesisPrompt, forbidden) {
			t.Fatalf("项目工具提示不应包含固定流程 %q", forbidden)
		}
	}
}

func TestWithPlatformVerificationWorkflowPreservesBaseInstruction(t *testing.T) {
	instruction := withPlatformVerificationWorkflow("基础指令")
	if instruction != "基础指令" {
		t.Fatalf("平台验证流程注入异常: %s", instruction)
	}
}
