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
	header, body, ok := parseToolResult(result)
	if !ok || header.Status != toolResultStatusError || header.ErrorClass != toolErrorCommandExit {
		t.Fatalf("错误协议头异常: %+v body=%q", header, body)
	}
	if !strings.Contains(body, "Illegal header name") {
		t.Fatalf("缺少原始错误详情: %q", body)
	}
	actions := strings.Join(header.NextActions, " ")
	for _, expected := range []string{"检查命令输出", "修改命令或参数", "禁止原样重复"} {
		if !strings.Contains(actions, expected) {
			t.Fatalf("失败提示缺少重试分析要求 %q: %q", expected, actions)
		}
	}
}

func TestDefaultSystemPromptKeepsExecutionBoundariesConcise(t *testing.T) {
	if len([]rune(defaultSystemPrompt)) > 2200 {
		t.Fatalf("默认系统提示仍然过长: %d", len([]rune(defaultSystemPrompt)))
	}
	for _, expected := range []string{
		"工具与能力",
		"mcp_search_tools",
		"mcp_use_tool",
		"project_next_targets",
		"pent_agent_execute",
		"read_skill",
		"只有用户明确表示“不需要 Worker”或等价指令时，主 Agent 才自行执行",
		"工具失败时先判断错误类型和可修复性",
		"不得用等价方式绕过授权、拦截或人工审批",
	} {
		if !strings.Contains(defaultSystemPrompt, expected) {
			t.Fatalf("系统提示缺少基础设施边界 %q", expected)
		}
	}
}

func TestDefaultPromptDoesNotEncodeEndpointSpecificWorkflow(t *testing.T) {
	for _, forbidden := range []string{
		"page_size=1",
		"禁止批量翻页",
		"必须先调用",
		"优先处理 `project_next_targets`",
		"每个测试方向必须形成",
	} {
		if strings.Contains(defaultSystemPrompt, forbidden) {
			t.Fatalf("系统提示不应固化具体测试流程 %q", forbidden)
		}
	}
}

func TestDefaultPromptDoesNotForceSpecificToolChoice(t *testing.T) {
	if strings.Contains(defaultSystemPrompt, "必须使用 java_decompile") ||
		strings.Contains(defaultSystemPrompt, "必须调用 pent_agent") ||
		strings.Contains(defaultSystemPrompt, "必须填写 worker_focus") {
		t.Fatalf("默认提示不应强制某个工具")
	}
}

func TestProjectToolGuidanceDescribesCapabilitiesWithoutWorkflow(t *testing.T) {
	if len([]rune(projectWritebackGuidance)) > 500 {
		t.Fatalf("项目工具提示仍然过长: %d", len([]rune(projectWritebackGuidance)))
	}
	for _, expected := range []string{
		"项目工具能力",
		"project_*",
		"project_list(resource=facts/findings)",
		"project_get(resource=graph_node)",
	} {
		if !strings.Contains(projectWritebackGuidance, expected) {
			t.Fatalf("项目工具提示缺少能力说明 %q", expected)
		}
	}
	for _, forbidden := range []string{"（强制）", "测试前用", "必须", "立即用"} {
		if strings.Contains(projectWritebackGuidance, forbidden) {
			t.Fatalf("项目工具提示不应规定执行流程 %q", forbidden)
		}
	}
}

func TestTolerantToolUsesErrorMessageWhenResultEmpty(t *testing.T) {
	probe := &errorProbeTool{name: "project_report_finding", err: errors.New("title 不能为空")}
	result, err, _ := invokeWrappedProbe(t, context.Background(), probe)
	if err != nil {
		t.Fatalf("工具失败应回传: %v", err)
	}
	_, body, ok := parseToolResult(result)
	if !ok || !strings.Contains(body, "title 不能为空") {
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
	header, body, ok := parseToolResult(result)
	if err != nil || !ok || header.Status != toolResultStatusSuccess || body != "ok" {
		t.Fatalf("成功结果协议异常: %q, header=%+v, err=%v", result, header, err)
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
	header, body, ok := parseToolResult(result)
	if !ok || header.ErrorClass != toolErrorTargetUnreachable {
		t.Fatalf("长错误分类异常: %+v, %q", header, result)
	}
	if !strings.Contains(body, "Name or service not known") {
		t.Fatalf("超长错误应保留末尾原因: %q", body)
	}
	if !strings.Contains(body, "已省略") {
		t.Fatalf("应标注省略信息: %q", body)
	}
	if len([]rune(body)) > tolerantToolErrorRunes+600 {
		t.Fatalf("长错误应被截断，实际 %d 字", len([]rune(body)))
	}
}
