package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

type errorProbeTool struct {
	name   string
	result string
	err    error
}

func (t *errorProbeTool) Info(_ context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: t.name}, nil
}

func (t *errorProbeTool) InvokableRun(
	_ context.Context,
	_ string,
	_ ...tool.Option,
) (string, error) {
	return t.result, t.err
}

func invokeWrappedProbe(
	t *testing.T,
	ctx context.Context,
	probe *errorProbeTool,
) (string, error, *tolerantTool) {
	t.Helper()
	items := wrapTolerantTools([]tool.BaseTool{probe})
	if len(items) != 1 {
		t.Fatalf("包装结果数量异常: %d", len(items))
	}
	wrapped, ok := items[0].(*tolerantTool)
	if !ok {
		t.Fatalf("工具未被包装: %T", items[0])
	}
	invokable, ok := items[0].(tool.InvokableTool)
	if !ok {
		t.Fatalf("包装后应实现 InvokableTool")
	}
	result, err := invokable.InvokableRun(ctx, "{}")
	return result, err, wrapped
}

func TestTolerantToolReturnsErrorAsResult(t *testing.T) {
	probe := &errorProbeTool{
		name:   "http-framework-test",
		result: "错误: 命令退出码 1\nIllegal header name",
		err:    errors.New("MCP tool http-framework-test failed"),
	}
	result, err, _ := invokeWrappedProbe(t, context.Background(), probe)
	if err != nil {
		t.Fatalf("工具失败应回传给模型而不是中断: %v", err)
	}
	if !strings.Contains(result, "[工具 http-framework-test 执行失败") {
		t.Fatalf("缺少失败提示: %q", result)
	}
	if !strings.Contains(result, "Illegal header name") {
		t.Fatalf("缺少原始错误详情: %q", result)
	}
	for _, expected := range []string{"先分析错误类型", "修改命令", "禁止原样重复", "不得绕过"} {
		if !strings.Contains(result, expected) {
			t.Fatalf("失败提示缺少重试分析要求 %q: %q", expected, result)
		}
	}
}

func TestDefaultSystemPromptRequiresToolFailureRetryAnalysis(t *testing.T) {
	if len([]rune(defaultSystemPrompt)) > 2200 {
		t.Fatalf("默认系统提示仍然过长: %d", len([]rune(defaultSystemPrompt)))
	}
	for _, expected := range []string{
		"必须先分析错误类型和可修复性",
		"修改命令、参数或执行方式后重试",
		"禁止原样重复失败命令",
		"不得用等价方式规避安全策略",
		"internet_search",
	} {
		if !strings.Contains(defaultSystemPrompt, expected) {
			t.Fatalf("系统提示缺少失败重试要求 %q", expected)
		}
	}
}

func TestDefaultPromptAllowsMinimizedSensitiveEndpointTesting(t *testing.T) {
	for _, expected := range []string{
		"user/order/face/contact/behavior/download",
		"page_size=1",
		"禁止批量翻页",
		"Policy Engine 拒绝",
		"技术阻断",
	} {
		if !strings.Contains(defaultSystemPrompt, expected) {
			t.Fatalf("系统提示缺少敏感接口最小化测试规则 %q", expected)
		}
	}
}

func TestProjectWritebackPromptCoversCompactWriteContract(t *testing.T) {
	if len([]rune(projectWritebackGuidance)) > 1400 {
		t.Fatalf("项目写回纪律仍然过长: %d", len([]rune(projectWritebackGuidance)))
	}
	for _, expected := range []string{
		"project_insert_assets",
		"project_plan_hypotheses",
		"project_start_hypothesis",
		"project_complete_hypothesis",
		"project_record_test",
		"project_record_audit",
		"tested_clean",
		"project_report_finding",
		"evidence_refs",
		"project_list(resource=facts/findings)",
	} {
		if !strings.Contains(projectWritebackGuidance, expected) {
			t.Fatalf("项目写回纪律缺少关键契约 %q", expected)
		}
	}
}

func TestTolerantToolUsesErrorMessageWhenResultEmpty(t *testing.T) {
	probe := &errorProbeTool{name: "project_report_finding", err: errors.New("title 不能为空")}
	result, err, _ := invokeWrappedProbe(t, context.Background(), probe)
	if err != nil {
		t.Fatalf("工具失败应回传: %v", err)
	}
	if !strings.Contains(result, "title 不能为空") {
		t.Fatalf("结果为空时应使用错误文本: %q", result)
	}
}

func TestTolerantToolKeepsCancelSemantics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	probe := &errorProbeTool{name: "demo", err: errors.New("boom")}
	if _, err, _ := invokeWrappedProbe(t, ctx, probe); err == nil {
		t.Fatalf("上下文取消时仍应中断整轮")
	}
}

func TestTolerantToolPassesThroughSuccess(t *testing.T) {
	probe := &errorProbeTool{name: "demo", result: "ok"}
	result, err, wrapped := invokeWrappedProbe(t, context.Background(), probe)
	if err != nil || result != "ok" {
		t.Fatalf("成功结果应原样透传: %q, err=%v", result, err)
	}
	info, err := wrapped.Info(context.Background())
	if err != nil || info == nil || info.Name != "demo" {
		t.Fatalf("Info 应委托给内部工具: %+v, err=%v", info, err)
	}
}

func TestTolerantToolTruncatesLongErrorKeepingTail(t *testing.T) {
	probe := &errorProbeTool{
		name:   "demo",
		result: strings.Repeat("前", 9000) + "Name or service not known",
		err:    errors.New("boom"),
	}
	result, err, _ := invokeWrappedProbe(t, context.Background(), probe)
	if err != nil {
		t.Fatalf("工具失败应回传: %v", err)
	}
	if !strings.Contains(result, "Name or service not known") {
		t.Fatalf("超长错误应保留末尾原因: %q", result)
	}
	if !strings.Contains(result, "已省略") {
		t.Fatalf("应标注省略信息: %q", result)
	}
	if len([]rune(result)) > tolerantToolErrorRunes+600 {
		t.Fatalf("长错误应被截断，实际 %d 字", len([]rune(result)))
	}
}
