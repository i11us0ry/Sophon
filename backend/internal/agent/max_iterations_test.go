package agent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/adk"

	"sophon/internal/database"
)

func TestIsMaxIterationsError(t *testing.T) {
	if !isMaxIterationsError(adk.ErrExceedMaxIterations) {
		t.Fatal("应识别 Eino 最大迭代错误")
	}
	if !isMaxIterationsError(
		&wrappedMaxIterationsError{},
	) {
		t.Fatal("应识别包含 exceeds max iterations 的错误信息")
	}
	if isMaxIterationsError(nil) {
		t.Fatal("nil 不应被识别为最大迭代错误")
	}
}

func TestFailedRunMessageNeverEmpty(t *testing.T) {
	capture := &runCapture{}
	capture.recordToolCall("call-1", "exec")
	capture.recordToolResult("call-1")
	message := failedRunMessage(
		errors.New("failed to receive stream chunk: net/http: request canceled"),
		capture,
	)
	for _, want := range []string{"本轮执行中断", "failed to receive stream chunk", "1 次工具调用", "1 次工具结果", "继续"} {
		if !strings.Contains(message, want) {
			t.Fatalf("失败兜底消息缺少 %q: %s", want, message)
		}
	}
}

func TestFailedRunMessageExplainsContextCancellation(t *testing.T) {
	message := failedRunMessage(errors.New("context canceled"), &runCapture{})
	if !strings.Contains(message, "服务重启、部署或手动停止") {
		t.Fatalf("取消任务应给出可读原因: %s", message)
	}
}

type wrappedMaxIterationsError struct{}

func (e *wrappedMaxIterationsError) Error() string {
	return "[NodeRunError] exceeds max iterations"
}

func TestMaxIterationsResult(t *testing.T) {
	capture := &runCapture{}
	capture.raw.WriteString("已完成端口扫描和漏洞验证。")

	result := maxIterationsResult(capture, 40)
	for _, want := range []string{"已完成端口扫描和漏洞验证。", "40", "继续"} {
		if !strings.Contains(result, want) {
			t.Fatalf("结果缺少 %q: %s", want, result)
		}
	}

	empty := maxIterationsResult(&runCapture{}, 40)
	if !strings.Contains(empty, "最大迭代轮数") {
		t.Fatalf("空结果应返回迭代提示: %s", empty)
	}
}

func TestFinalizeRetestAtIterationLimit(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "finding-iteration-limit",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "有界复测",
		Severity:    "high",
		Status:      "open",
		Target:      "http://10.8.0.61/FileService.svc",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	run, err := service.db.CreateVulnerabilityRetestRun(
		ctx,
		"finding-iteration-limit",
		"user-1",
		"conv-tools",
		nil,
	)
	if err != nil {
		t.Fatalf("创建复测任务失败: %v", err)
	}
	plan := missionPlan{
		Mode:             missionModeRetest,
		VulnerabilityIDs: []string{"finding-iteration-limit"},
		RetestIDs:        []string{run.ID},
		Bounded:          true,
	}
	withWriteback := &runCapture{}
	withWriteback.recordToolCall("write", "project_retest_finding")
	withWriteback.recordToolResult("write")
	if terminal, _ := service.finalizeRetestAtIterationLimit(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		plan,
		withWriteback,
		maxSegmentIterations,
	); terminal {
		t.Fatal("已经写回复测结果时不应重复自动写回")
	}
	terminal, reason := service.finalizeRetestAtIterationLimit(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		plan,
		&runCapture{},
		maxSegmentIterations,
	)
	if !terminal || !strings.Contains(reason, "24") {
		t.Fatalf("达到迭代上限应自动写回 insufficient_evidence: terminal=%v reason=%s", terminal, reason)
	}
	event, err := service.db.GetVulnerabilityRetest(ctx, run.ID, "user-1")
	if err != nil || event.Status != "completed" || event.Result != "inconclusive" {
		t.Fatalf("复测任务未按 inconclusive 完成: %+v err=%v", event, err)
	}
	if !strings.Contains(event.Notes, "24") {
		t.Fatalf("自动写回说明缺少真实迭代上限: %s", event.Notes)
	}
}
