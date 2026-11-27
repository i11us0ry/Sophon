package agent

import (
	"errors"
	"testing"

	"sophon/internal/database"
)

func TestGlobalLLMErrorTripsCircuitAndDisablesRetry(t *testing.T) {
	service := newSubAgentTestService(t)
	service.resetLLMCircuit()
	err := errors.New("status code: 503: 没有可用的 LLM API Key")
	if !isGlobalLLMError(err) {
		t.Fatal("缺失 Key 应识别为全局错误")
	}
	if service.streamErrorRetryable(err) {
		t.Fatal("全局错误不应继续重试")
	}
	if err := service.checkLLMCircuit(); !isGlobalLLMError(err) {
		t.Fatalf("全局错误应打开熔断，实际 %v", err)
	}
	if shouldRequeueWorkerFailure(database.ProjectTestResult{Attempts: 1}, err) {
		t.Fatal("全局错误不应重新入队 Worker")
	}
	service.markLLMHealthy()
	if err := service.checkLLMCircuit(); err != nil {
		t.Fatalf("恢复后熔断应关闭: %v", err)
	}
}
