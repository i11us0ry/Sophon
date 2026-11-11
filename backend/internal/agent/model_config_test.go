package agent

import (
	"context"
	"strings"
	"testing"

	"sophon/internal/config"
)

func TestBuildModelRequiresKeyWhenMockDisabled(t *testing.T) {
	_, err := buildModel(context.Background(), config.Config{
		AgentMock:  false,
		LLMAPIKey:  "",
		LLMBaseURL: "https://api.example.com/v1",
		LLMModel:   "test-model",
	})
	if err == nil || !strings.Contains(err.Error(), "API Key") {
		t.Fatalf("关闭 Mock 且缺少 API Key 时必须失败，实际 err=%v", err)
	}
}

func TestBuildModelUsesMockOnlyWhenExplicitlyEnabled(t *testing.T) {
	chatModel, err := buildModel(context.Background(), config.Config{
		AgentMock: true,
	})
	if err != nil {
		t.Fatalf("显式 Mock 模式应可启动: %v", err)
	}
	if chatModel == nil {
		t.Fatal("Mock 模型不能为空")
	}
}
