package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"

	"sophon/internal/config"
	"sophon/internal/execctx"
)

func TestWorkerControlInjectsSteerAndStopsNextToolCall(t *testing.T) {
	fake := newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command")
	fake.result = "ok"
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := execctx.WithSubagent(base, execctx.SubagentInfo{
		ID:   "sub-worker-control",
		Kind: "worker",
	})
	ctx = withWorkerBudget(ctx, config.Config{AgentSubagentMaxToolCalls: 10}, cancel)
	control := &workerControl{cancel: cancel}
	control.addSteer("优先检查上传入口")
	ctx = withWorkerControl(ctx, control)
	wrapped := wrapWorkerBudgetTools(ctx, []tool.BaseTool{fake})
	result, err := wrapped[0].(tool.InvokableTool).InvokableRun(
		ctx,
		`{"command":"echo ok"}`,
	)
	if err != nil {
		t.Fatalf("纠偏不应作为工具流错误终止 Worker: %v", err)
	}
	header, body, ok := parseToolResult(result)
	if !ok || header.Status != toolResultStatusBlocked || header.ErrorClass != toolErrorPolicy {
		t.Fatalf("纠偏应返回 blocked 工具结果: %+v body=%q", header, body)
	}
	for _, expected := range []string{
		"【规划者实时纠偏】",
		"优先检查上传入口",
		"plannerSteer=true",
		"toolExecuted=false",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("纠偏结果缺少 %q: %q", expected, body)
		}
	}
	if len(fake.calls) != 0 {
		t.Fatalf("纠偏后底层工具不应执行: %+v", fake.calls)
	}
	control.stop()
	if _, err := wrapped[0].(tool.InvokableTool).InvokableRun(
		ctx,
		`{"command":"echo stopped"}`,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("用户停止 Worker 后应返回 context.Canceled，实际: %v", err)
	}
}

func TestOrchestratorControlTargetsSingleWorker(t *testing.T) {
	conversationID := "conv-worker-control"
	var cancelled bool
	service := &Service{}
	control := service.registerWorkerControl(
		conversationID,
		"hypothesis-1",
		func() { cancelled = true },
	)
	ctx := execctx.WithConversationID(context.Background(), conversationID)
	ctx = execctx.WithProjectID(ctx, "project-worker-control")
	if _, err := service.controlOrchestration(
		ctx,
		"steer_worker",
		"停止当前参数猜测，先验证上传链",
		"hypothesis-1",
	); err != nil {
		t.Fatalf("Worker 纠偏失败: %v", err)
	}
	if pending := control.takeSteer(); len(pending) != 1 {
		t.Fatalf("Worker 纠偏未入队: %+v", pending)
	}
	if _, err := service.controlOrchestration(
		ctx,
		"stop_worker",
		"停止重复方向并释放并发槽位",
		"hypothesis-1",
	); err != nil {
		t.Fatalf("停止 Worker 失败: %v", err)
	}
	if !cancelled || !control.isStopped() {
		t.Fatal("停止 Worker 应取消其独立 context")
	}
	reason, message := control.stopDetails()
	if reason != "user_stopped" || message != "停止重复方向并释放并发槽位" {
		t.Fatalf("Worker 停止原因未保存: reason=%s message=%s", reason, message)
	}
}

func TestPausedOrchestrationDoesNotBlockRunningWorker(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	control := &workerControl{}
	if shouldBlockWorkerFailure(parent, control) {
		t.Fatal("整体编排暂停时不应把 Worker 假设写成 blocked")
	}
	control.stop()
	if !shouldBlockWorkerFailure(parent, control) {
		t.Fatal("用户单独停止 Worker 时应保留 blocked 语义")
	}
}

func TestWorkerStopMetadataDistinguishesPlannerFromUser(t *testing.T) {
	userCtx := context.Background()
	if reason, _ := workerStopMetadata(userCtx); reason != "user_stopped" {
		t.Fatalf("普通控制应标记 user_stopped，实际 %s", reason)
	}
	plannerCtx := execctx.WithSubagent(context.Background(), execctx.SubagentInfo{
		ID:   "planner-stop",
		Kind: "planner",
	})
	reason, message := workerStopMetadata(plannerCtx)
	if reason != "planner_stopped" || !strings.Contains(message, "Planner") {
		t.Fatalf("Planner 停止 Worker 的审计语义错误: reason=%s message=%s", reason, message)
	}
	reason, message = workerStopMetadata(plannerCtx, "回收槽位，转入更高优先级利用链")
	if reason != "planner_stopped" || message != "回收槽位，转入更高优先级利用链" {
		t.Fatalf("Planner 自定义停止原因错误: reason=%s message=%s", reason, message)
	}
}
