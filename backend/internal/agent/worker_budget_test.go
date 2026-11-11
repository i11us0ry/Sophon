package agent

import (
	"context"
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
	if ctx.Err() == nil {
		t.Fatalf("CPU 预算耗尽后应取消 Worker")
	}
	if _, err := invokable.InvokableRun(ctx, `{"command":"echo three"}`); err == nil ||
		!strings.Contains(err.Error(), "CPU 预算已耗尽") {
		t.Fatalf("CPU 预算耗尽后应拒绝调用，实际 err=%v", err)
	}
}

func TestWorkerToolRunnerUsesRemainingCPUBudget(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := execctx.WithConversationID(base, "conv-cpu-inject")
	ctx = execctx.WithUserID(ctx, "user-1")
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

func TestWorkerBudgetCancelsAfterToolLimit(t *testing.T) {
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
	if _, err := invokable.InvokableRun(ctx, `{"command":"echo two"}`); err == nil ||
		!strings.Contains(err.Error(), "预算已耗尽") {
		t.Fatalf("第二次调用应触发预算错误，实际 err=%v", err)
	}
	if ctx.Err() == nil {
		t.Fatalf("预算超限后应取消 Worker context")
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
		jobs:  map[string]context.CancelFunc{},
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
		jobs:  map[string]context.CancelFunc{},
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

func TestControlledJobCancelsWithConversationContext(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "job-cancel.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	blocking := &blockingExecTool{started: make(chan struct{})}
	service := &Service{
		db:    db,
		tools: []tool.BaseTool{blocking},
		jobs:  map[string]context.CancelFunc{},
	}
	ctx, cancel := context.WithCancel(context.Background())
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
	cancel()
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
		jobs:  map[string]context.CancelFunc{},
	}
	ctx, cancel := context.WithCancel(context.Background())
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
	cancel()
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
