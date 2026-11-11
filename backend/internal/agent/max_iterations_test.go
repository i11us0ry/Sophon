package agent

import (
	"errors"
	"strings"
	"testing"

	"github.com/cloudwego/eino/adk"
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
