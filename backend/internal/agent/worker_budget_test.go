package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/execctx"
)

type blockingExecTool struct {
	started chan struct{}
	calls   atomic.Int32
}

func (t *blockingExecTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "exec", Desc: "阻塞执行"}, nil
}

func (t *blockingExecTool) InvokableRun(
	ctx context.Context,
	_ string,
	_ ...tool.Option,
) (string, error) {
	t.calls.Add(1)
	select {
	case <-t.started:
	default:
		close(t.started)
	}
	<-ctx.Done()
	return "", ctx.Err()
}

func TestWorkerBudgetAccumulatesCPUUsage(t *testing.T) {
	fake := newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command")
	gate := execctx.NewSkillGate("dotnet-code-audit")
	gate.MarkLoaded("dotnet-code-audit")
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := execctx.WithSubagent(base, execctx.SubagentInfo{
		ID:        "sub-cpu",
		Kind:      "worker",
		SkillGate: gate,
	})
	ctx = withWorkerBudget(ctx, config.Config{
		AgentSubagentMaxToolCalls:  10,
		AgentSubagentMaxCPUSeconds: 10,
	}, cancel)
	wrapped := wrapWorkerBudgetTools(ctx, []tool.BaseTool{fake})
	invokable := wrapped[0].(tool.InvokableTool)
	budget := workerBudgetFromContext(ctx)
	fake.result = fmt.Sprintf("ok\n[sophon budget:%s] cpu_seconds=6.000000\n", budget.budgetToken)
	if _, err := invokable.InvokableRun(ctx, `{"command":"echo one"}`); err != nil {
		t.Fatalf("第一次调用失败: %v", err)
	}
	if remaining := budget.remainingCPUSeconds(); remaining < 3.99 || remaining > 4.01 {
		t.Fatalf("CPU 预算剩余错误: %.3f", remaining)
	}
	fake.result = fmt.Sprintf("ok\n[sophon budget:%s] cpu_seconds=5.000000\n", budget.budgetToken)
	if _, err := invokable.InvokableRun(ctx, `{"command":"echo two"}`); err != nil {
		t.Fatalf("第二次调用失败: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("CPU 预算耗尽后不应取消 Worker: %v", ctx.Err())
	}
	result, err := invokable.InvokableRun(ctx, `{"command":"echo three"}`)
	if err != nil {
		t.Fatalf("CPU 预算耗尽不应中断工具流: %v", err)
	}
	header, body, ok := parseToolResult(result)
	if !ok || header.Status != toolResultStatusBlocked || !strings.Contains(body, "CPU 预算已耗尽") {
		t.Fatalf("CPU 预算耗尽应返回 blocked 结果: %+v body=%q", header, body)
	}
}

func TestWorkerToolRunnerUsesRemainingCPUBudget(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := execctx.WithConversationID(base, "conv-cpu-inject")
	ctx = execctx.WithUserID(ctx, "user-1")
	ctx = execctx.WithProjectID(ctx, "project-cpu-inject")
	ctx = execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID:           "sub-cpu-inject",
		Kind:         "worker",
		CPUSeconds:   10,
		MaxProcesses: 8,
	})
	ctx = withWorkerBudget(ctx, config.Config{
		AgentSubagentMaxCPUSeconds: 10,
	}, cancel)
	budget := workerBudgetFromContext(ctx)
	budget.recordCPUUsage(fmt.Sprintf("[sophon budget:%s] cpu_seconds=6.000000", budget.budgetToken))
	service := &Service{cfg: config.Config{
		Storage: config.StorageConfig{
			ArtifactRoot: t.TempDir(),
			Categories: map[string]config.StorageCategoryConfig{
				"workspace": {Path: "tmp/workspace"},
			},
		},
	}}
	args := map[string]interface{}{}
	if err := service.injectToolRunnerWorkspace(
		ctx,
		toolRunnerServerName,
		"conv-cpu-inject",
		args,
	); err != nil {
		t.Fatalf("注入工作区失败: %v", err)
	}
	if got, _ := args[toolRunnerCPUSecondsArg].(int); got != 4 {
		t.Fatalf("应注入剩余 CPU 预算 4 秒，实际 %#v", args[toolRunnerCPUSecondsArg])
	}
	if got, _ := args[toolRunnerMaxProcessesArg].(int); got != 8 {
		t.Fatalf("进程预算注入错误: %#v", args[toolRunnerMaxProcessesArg])
	}
	if got, _ := args[toolRunnerBudgetTokenArg].(string); got == "" || got != budget.budgetToken {
		t.Fatalf("预算 token 注入错误: %#v", args[toolRunnerBudgetTokenArg])
	}
}

func TestWorkerBudgetDoesNotRequireSkillLoad(t *testing.T) {
	fake := newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command")
	ctx := execctx.WithSubagent(context.Background(), execctx.SubagentInfo{
		ID:            "sub-budget",
		Kind:          "worker",
		AllowedSkills: []string{"dotnet-code-audit", "dotnet-injection-audit"},
	})
	wrapped := wrapWorkerBudgetTools(ctx, []tool.BaseTool{fake})
	invokable := wrapped[0].(tool.InvokableTool)
	result, err := invokable.InvokableRun(ctx, `{"command":"echo ok"}`)
	if err != nil || strings.Contains(result, "技能门禁") {
		t.Fatalf("未读取技能不应阻止 Worker 工具调用，result=%q err=%v", result, err)
	}
}

func TestWorkerBudgetRejectsAfterToolLimitWithoutCancelling(t *testing.T) {
	fake := newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command")
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := execctx.WithSubagent(base, execctx.SubagentInfo{
		ID:   "sub-budget-limit",
		Kind: "worker",
	})
	ctx = withWorkerBudget(ctx, config.Config{AgentSubagentMaxToolCalls: 1}, cancel)
	wrapped := wrapWorkerBudgetTools(ctx, []tool.BaseTool{fake})
	invokable := wrapped[0].(tool.InvokableTool)
	if _, err := invokable.InvokableRun(ctx, `{"command":"echo one"}`); err != nil {
		t.Fatalf("第一次调用应成功: %v", err)
	}
	result, err := invokable.InvokableRun(ctx, `{"command":"echo two"}`)
	if err != nil {
		t.Fatalf("预算超限不应中断工具流: %v", err)
	}
	header, body, ok := parseToolResult(result)
	if !ok || header.Status != toolResultStatusBlocked || !strings.Contains(body, "预算已耗尽") {
		t.Fatalf("第二次调用应触发非致命预算阻断: %+v body=%q", header, body)
	}
	if ctx.Err() != nil {
		t.Fatalf("预算超限后不应取消 Worker context: %v", ctx.Err())
	}
}

func TestWorkerStateQueryCircuitBreaksAfterNoProgress(t *testing.T) {
	fake := newFakeMCPTool("sophon-tool-runner", "project_list", "读取项目列表", "resource")
	fake.result = "当前项目没有匹配的资产。"
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := execctx.WithSubagent(base, execctx.SubagentInfo{
		ID:   "sub-state-circuit",
		Kind: "worker",
	})
	ctx = withWorkerBudget(ctx, config.Config{AgentSubagentMaxToolCalls: 10}, cancel)
	wrapped := wrapWorkerBudgetTools(ctx, []tool.BaseTool{fake})
	invokable := wrapped[0].(tool.InvokableTool)
	if _, err := invokable.InvokableRun(ctx, `{"resource":"assets"}`); err != nil {
		t.Fatalf("第一次状态查询失败: %v", err)
	}
	result, err := invokable.InvokableRun(ctx, `{"resource":"assets"}`)
	if err != nil {
		t.Fatalf("熔断不应中断工具流: %v", err)
	}
	header, body, ok := parseToolResult(result)
	if !ok || header.Status != toolResultStatusBlocked ||
		!strings.Contains(body, "已返回无进展结果") {
		t.Fatalf("重复无进展查询应被熔断: %+v body=%q", header, body)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("熔断后不应再次执行底层工具: %+v", fake.calls)
	}
}

func TestWorkerStateCircuitIsScopedByProjectListResource(t *testing.T) {
	fake := newFakeMCPTool("sophon-tool-runner", "project_list", "读取项目列表", "resource")
	fake.result = "当前项目没有匹配的资产。"
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := execctx.WithSubagent(base, execctx.SubagentInfo{ID: "sub-state-scope", Kind: "worker"})
	ctx = withWorkerBudget(ctx, config.Config{AgentSubagentMaxToolCalls: 10}, cancel)
	wrapped := wrapWorkerBudgetTools(ctx, []tool.BaseTool{fake})
	invokable := wrapped[0].(tool.InvokableTool)
	if _, err := invokable.InvokableRun(ctx, `{"resource":"assets"}`); err != nil {
		t.Fatalf("资产查询失败: %v", err)
	}
	fake.result = "假设列表正常"
	result, err := invokable.InvokableRun(ctx, `{"resource":"hypotheses"}`)
	if err != nil || !strings.Contains(result, "假设列表正常") {
		t.Fatalf("其他 resource 不应被资产查询熔断: result=%q err=%v", result, err)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("不同 resource 应正常执行底层工具: %+v", fake.calls)
	}
}

func TestWorkerBlockedCallsReachBoundedStop(t *testing.T) {
	fake := newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command")
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := execctx.WithSubagent(base, execctx.SubagentInfo{ID: "sub-budget-stop", Kind: "worker"})
	ctx = withWorkerBudget(ctx, config.Config{AgentSubagentMaxToolCalls: 1}, cancel)
	wrapped := wrapWorkerBudgetTools(ctx, []tool.BaseTool{fake})
	invokable := wrapped[0].(tool.InvokableTool)
	if _, err := invokable.InvokableRun(ctx, `{"command":"echo one"}`); err != nil {
		t.Fatalf("首次调用失败: %v", err)
	}
	for attempt := 1; attempt < workerBlockedCallLimit; attempt++ {
		if _, err := invokable.InvokableRun(ctx, `{"command":"echo blocked"}`); err != nil {
			t.Fatalf("第 %d 次超预算调用应为非致命 blocked: %v", attempt, err)
		}
	}
	if _, err := invokable.InvokableRun(ctx, `{"command":"echo hard-stop"}`); !errors.Is(err, context.Canceled) {
		t.Fatalf("连续超预算调用应强制结束 Worker，实际: %v", err)
	}
}

func TestWorkerBudgetGuidanceShowsUnlimited(t *testing.T) {
	service := &Service{cfg: config.Config{AgentSubagentMaxToolCalls: 0}}
	guidance := service.workerBudgetGuidance()
	if !strings.Contains(guidance, "工具调用上限：不限") ||
		strings.Contains(guidance, "工具调用上限：80 次") {
		t.Fatalf("Worker 工具预算应显示为不限: %s", guidance)
	}
}

func TestControlledJobCompletesAndPersistsCheckpoint(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "job-tools.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	fake := newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command")
	fake.result = "step-ok"
	service := &Service{
		db: db,
		cfg: config.Config{
			AgentSubagentMaxToolCalls: 20,
		},
		tools: []tool.BaseTool{fake},
		jobs:  map[string]toolJobHandle{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = execctx.WithConversationID(ctx, "conv-job")
	ctx = execctx.WithUserID(ctx, "user-1")
	ctx = execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID:   "sub-job",
		Kind: "worker",
	})
	start := findSubAgentTool(t, newJobTools(service), jobToolName)
	if _, err := start.InvokableRun(
		ctx,
		`{"action":"start","steps":["echo one","echo two"],"job_key":"scan"}`,
	); err != nil {
		t.Fatalf("启动 Job 失败: %v", err)
	}
	dedupKey := jobDedupKey("sub-job", "scan", []string{"echo one", "echo two"})
	var job *database.ToolJob
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err = db.GetToolJobByDedupKey(ctx, "conv-job", "user-1", dedupKey)
		if err == nil && job.Status == database.ToolJobStatusCompleted {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || job == nil || job.Status != database.ToolJobStatusCompleted {
		t.Fatalf("Job 未完成: job=%+v err=%v", job, err)
	}
	if job.NextStep != 2 || job.Result != "step-ok" || len(fake.calls) != 2 {
		t.Fatalf("Job 检查点或执行次数错误: job=%+v calls=%d", job, len(fake.calls))
	}
}

func TestControlledJobResumesFromCheckpoint(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "job-resume.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	job, _, err := db.CreateToolJob(context.Background(), database.ToolJob{
		ConversationID: "conv-job-resume",
		UserID:         "user-1",
		AgentID:        "sub-job",
		DedupKey:       "resume",
		Status:         database.ToolJobStatusInterrupted,
		Steps:          []string{"echo one", "echo two"},
		NextStep:       1,
		Progress:       map[string]interface{}{"currentStep": 1},
	})
	if err != nil {
		t.Fatalf("创建中断 Job 失败: %v", err)
	}
	fake := newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command")
	fake.result = "resumed"
	service := &Service{
		db:    db,
		cfg:   config.Config{AgentSubagentMaxToolCalls: 20},
		tools: []tool.BaseTool{fake},
		jobs:  map[string]toolJobHandle{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = execctx.WithConversationID(ctx, "conv-job-resume")
	ctx = execctx.WithUserID(ctx, "user-1")
	ctx = execctx.WithSubagent(ctx, execctx.SubagentInfo{ID: "sub-job", Kind: "worker"})
	resume := findSubAgentTool(t, newJobTools(service), jobToolName)
	if _, err := resume.InvokableRun(ctx, `{"action":"resume","job_id":"`+job.ID+`"}`); err != nil {
		t.Fatalf("恢复 Job 失败: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err = db.GetToolJob(ctx, job.ID, "user-1")
		if err == nil && job.Status == database.ToolJobStatusCompleted {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || job.Status != database.ToolJobStatusCompleted {
		t.Fatalf("恢复后的 Job 未完成: job=%+v err=%v", job, err)
	}
	if job.NextStep != 2 || len(fake.calls) != 1 || !strings.Contains(fake.calls[0], "echo two") {
		t.Fatalf("Job 未从检查点继续: job=%+v calls=%#v", job, fake.calls)
	}
}

func TestConversationStopCancelsControlledJob(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "job-cancel.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blocking := &blockingExecTool{started: make(chan struct{})}
	service := &Service{
		db:    db,
		tools: []tool.BaseTool{blocking},
		jobs:  map[string]toolJobHandle{},
	}
	ctx := context.Background()
	ctx = execctx.WithConversationID(ctx, "conv-job-cancel")
	ctx = execctx.WithUserID(ctx, "user-1")
	ctx = execctx.WithSubagent(ctx, execctx.SubagentInfo{ID: "sub-job-cancel", Kind: "worker"})
	start := findSubAgentTool(t, newJobTools(service), jobToolName)
	if _, err := start.InvokableRun(ctx, `{"action":"start","steps":["blocking"],"job_key":"cancel"}`); err != nil {
		t.Fatalf("启动 Job 失败: %v", err)
	}
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatalf("Job 未开始执行")
	}
	if cancelled := service.CancelConversationJobs("conv-job-cancel", "user-1"); cancelled != 1 {
		t.Fatalf("应取消 1 个会话 Job，实际 %d", cancelled)
	}
	dedupKey := jobDedupKey("sub-job-cancel", "cancel", []string{"blocking"})
	var job *database.ToolJob
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err = db.GetToolJobByDedupKey(context.Background(), "conv-job-cancel", "user-1", dedupKey)
		if err == nil && job.Status == database.ToolJobStatusCancelled {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || job == nil || job.Status != database.ToolJobStatusCancelled {
		t.Fatalf("会话取消未联动 Job: job=%+v err=%v", job, err)
	}
}

func TestConcurrentJobResumeStartsOnlyOnce(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "job-resume-race.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	job, _, err := db.CreateToolJob(context.Background(), database.ToolJob{
		ConversationID: "conv-job-race",
		UserID:         "user-1",
		AgentID:        "sub-job-race",
		DedupKey:       "race",
		Status:         database.ToolJobStatusInterrupted,
		Steps:          []string{"blocking"},
	})
	if err != nil {
		t.Fatalf("创建 Job 失败: %v", err)
	}
	blocking := &blockingExecTool{started: make(chan struct{})}
	service := &Service{
		db:    db,
		tools: []tool.BaseTool{blocking},
		jobs:  map[string]toolJobHandle{},
	}
	ctx := context.Background()
	ctx = execctx.WithConversationID(ctx, "conv-job-race")
	ctx = execctx.WithUserID(ctx, "user-1")
	ctx = execctx.WithSubagent(ctx, execctx.SubagentInfo{ID: "sub-job-race", Kind: "worker"})
	resume := findSubAgentTool(t, newJobTools(service), jobToolName)
	errCh := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func() {
			_, err := resume.InvokableRun(ctx, `{"action":"resume","job_id":"`+job.ID+`"}`)
			errCh <- err
		}()
	}
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatalf("Job 未启动")
	}
	time.Sleep(100 * time.Millisecond)
	if calls := blocking.calls.Load(); calls != 1 {
		t.Fatalf("并发 Resume 启动了 %d 个执行实例", calls)
	}
	for index := 0; index < 2; index++ {
		if err := <-errCh; err != nil {
			t.Fatalf("Resume 返回错误: %v", err)
		}
	}
	if cancelled := service.CancelConversationJobs("conv-job-race", "user-1"); cancelled != 1 {
		t.Fatalf("应取消 1 个并发恢复 Job，实际 %d", cancelled)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err = db.GetToolJob(context.Background(), job.ID, "user-1")
		if err == nil && job.Status == database.ToolJobStatusCancelled {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("取消后的 Job 状态未落库: %+v err=%v", job, err)
}

func TestJobToolValidatesActions(t *testing.T) {
	service := &Service{}
	jobTools := newJobTools(service)
	if len(jobTools) != 1 {
		t.Fatalf("Job 应合并为单一工具，实际 %d 个", len(jobTools))
	}
	jobTool := findSubAgentTool(t, jobTools, jobToolName)

	ctx := execctx.WithConversationID(context.Background(), "conv-job-validation")
	ctx = execctx.WithUserID(ctx, "user-1")
	cases := []struct {
		args string
		want string
	}{
		{`{"action":"start","steps":[]}`, "steps 不能为空"},
		{`{"action":"status"}`, "需要 job_id"},
		{`{"action":"resume"}`, "需要 job_id"},
		{`{"action":"cancel"}`, "需要 job_id"},
		{`{"action":"unknown"}`, "action 必须是"},
	}
	for _, item := range cases {
		if _, err := jobTool.InvokableRun(ctx, item.args); err == nil || !strings.Contains(err.Error(), item.want) {
			t.Fatalf("参数 %s 应返回包含 %q 的错误，实际: %v", item.args, item.want, err)
		}
	}
}
