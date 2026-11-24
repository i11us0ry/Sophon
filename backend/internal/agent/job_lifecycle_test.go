package agent

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/execctx"
)

type gatedJobExecTool struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (t *gatedJobExecTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: "exec", Desc: "可控 Job 执行"}, nil
}

func (t *gatedJobExecTool) InvokableRun(
	ctx context.Context,
	_ string,
	_ ...tool.Option,
) (string, error) {
	t.once.Do(func() { close(t.started) })
	select {
	case <-t.release:
		return "job-finished", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestControlledJobSurvivesAgentRunCancellation(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "job-detached.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	execTool := &gatedJobExecTool{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	service := &Service{
		db:    db,
		tools: []tool.BaseTool{execTool},
		jobs:  map[string]toolJobHandle{},
	}
	ctx, cancelRun := context.WithCancel(context.Background())
	ctx = execctx.WithConversationID(ctx, "conv-job-detached")
	ctx = execctx.WithUserID(ctx, "user-1")

	jobTool := findSubAgentTool(t, newJobTools(service), jobToolName)
	if _, err := jobTool.InvokableRun(
		ctx,
		`{"action":"start","steps":["long-running"],"job_key":"detached"}`,
	); err != nil {
		t.Fatalf("启动 Job 失败: %v", err)
	}
	select {
	case <-execTool.started:
	case <-time.After(time.Second):
		t.Fatal("Job 未开始执行")
	}

	cancelRun()
	time.Sleep(30 * time.Millisecond)
	dedupKey := jobDedupKey("mainagent", "detached", []string{"long-running"})
	running, err := db.GetToolJobByDedupKey(
		context.Background(),
		"conv-job-detached",
		"user-1",
		dedupKey,
	)
	if err != nil || running == nil || running.Status != database.ToolJobStatusRunning {
		t.Fatalf("Agent Run 取消后 Job 不应停止: job=%+v err=%v", running, err)
	}

	close(execTool.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		running, err = db.GetToolJob(context.Background(), running.ID, "user-1")
		if err == nil && running.Status == database.ToolJobStatusCompleted {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || running.Status != database.ToolJobStatusCompleted ||
		running.Result != "job-finished" {
		t.Fatalf("脱离 Run 后 Job 未完成: job=%+v err=%v", running, err)
	}
}

func TestControlledJobPreservesParentDeadline(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "job-deadline.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	execTool := &gatedJobExecTool{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	service := &Service{
		db:    db,
		tools: []tool.BaseTool{execTool},
		jobs:  map[string]toolJobHandle{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	ctx = execctx.WithConversationID(ctx, "conv-job-deadline")
	ctx = execctx.WithUserID(ctx, "user-1")

	jobTool := findSubAgentTool(t, newJobTools(service), jobToolName)
	if _, err := jobTool.InvokableRun(
		ctx,
		`{"action":"start","steps":["deadline"],"job_key":"deadline"}`,
	); err != nil {
		t.Fatalf("启动 Job 失败: %v", err)
	}
	select {
	case <-execTool.started:
	case <-time.After(time.Second):
		t.Fatal("Job 未开始执行")
	}

	dedupKey := jobDedupKey("mainagent", "deadline", []string{"deadline"})
	var job *database.ToolJob
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err = db.GetToolJobByDedupKey(
			context.Background(),
			"conv-job-deadline",
			"user-1",
			dedupKey,
		)
		if err == nil && job.Status == database.ToolJobStatusCancelled {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Job 未继承父级 deadline: job=%+v err=%v", job, err)
}

func TestJobCancelDoesNotRewriteFailedTerminalState(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "job-terminal.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	job, _, err := db.CreateToolJob(context.Background(), database.ToolJob{
		ConversationID: "conv-job-terminal",
		UserID:         "user-1",
		AgentID:        "mainagent",
		DedupKey:       "failed-job",
		Status:         database.ToolJobStatusFailed,
		Steps:          []string{"broken"},
		Error:          "previous failure",
	})
	if err != nil {
		t.Fatalf("创建失败 Job 失败: %v", err)
	}
	service := &Service{db: db, jobs: map[string]toolJobHandle{}}
	ctx := execctx.WithConversationID(context.Background(), "conv-job-terminal")
	ctx = execctx.WithUserID(ctx, "user-1")

	toolItem := findSubAgentTool(t, newJobTools(service), jobToolName)
	result, err := toolItem.InvokableRun(
		ctx,
		`{"action":"cancel","job_id":"`+job.ID+`"}`,
	)
	if err != nil {
		t.Fatalf("取消失败 Job 返回错误: %v", err)
	}
	if !strings.Contains(result, "不再改写为取消") {
		t.Fatalf("失败 Job 取消提示异常: %s", result)
	}
	latest, err := db.GetToolJob(context.Background(), job.ID, "user-1")
	if err != nil || latest.Status != database.ToolJobStatusFailed {
		t.Fatalf("失败 Job 终态被覆盖: job=%+v err=%v", latest, err)
	}
}

func TestJobProgressPreservesEvidenceAndArtifacts(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "job-evidence.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	execTool := newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command")
	execTool.result = renderToolSuccess(
		"exec",
		"done\n[sophon evidence_ref] tool:job-exec-1\nartifact: /tmp/job-output.txt",
	)
	service := &Service{
		db:    db,
		cfg:   config.Config{AgentSubagentMaxToolCalls: 10},
		tools: []tool.BaseTool{execTool},
		jobs:  map[string]toolJobHandle{},
	}
	ctx := execctx.WithConversationID(context.Background(), "conv-job-evidence")
	ctx = execctx.WithUserID(ctx, "user-1")

	jobTool := findSubAgentTool(t, newJobTools(service), jobToolName)
	if _, err := jobTool.InvokableRun(
		ctx,
		`{"action":"start","steps":["collect"],"job_key":"evidence"}`,
	); err != nil {
		t.Fatalf("启动 Job 失败: %v", err)
	}
	dedupKey := jobDedupKey("mainagent", "evidence", []string{"collect"})
	var job *database.ToolJob
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		job, err = db.GetToolJobByDedupKey(
			context.Background(),
			"conv-job-evidence",
			"user-1",
			dedupKey,
		)
		if err == nil && job.Status == database.ToolJobStatusCompleted {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || job == nil || job.Status != database.ToolJobStatusCompleted {
		t.Fatalf("Job 未完成: job=%+v err=%v", job, err)
	}
	if !jobProgressContains(job.Progress, "lastEvidenceRefs", "tool:job-exec-1") ||
		!jobProgressContains(job.Progress, "lastArtifacts", "/tmp/job-output.txt") {
		t.Fatalf("Job 未保存证据或 artifact: %+v", job.Progress)
	}
}

func jobProgressContains(progress map[string]interface{}, key, want string) bool {
	items, _ := progress[key].([]interface{})
	for _, item := range items {
		if text, ok := item.(string); ok && text == want {
			return true
		}
	}
	return false
}
