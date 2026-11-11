package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/execctx"
)

// fakeMCPTool 模拟一个带服务名的 MCP 工具，用于验证发现层与能力门禁。
type fakeMCPTool struct {
	server string
	info   *schema.ToolInfo
	calls  []string
	result string
}

func (t *fakeMCPTool) MCPServerName() string { return t.server }

func (t *fakeMCPTool) Info(context.Context) (*schema.ToolInfo, error) { return t.info, nil }

func (t *fakeMCPTool) InvokableRun(
	_ context.Context,
	argumentsInJSON string,
	_ ...tool.Option,
) (string, error) {
	t.calls = append(t.calls, argumentsInJSON)
	return t.result, nil
}

func newFakeMCPTool(server, name, desc string, required ...string) *fakeMCPTool {
	params := map[string]*schema.ParameterInfo{}
	for _, param := range required {
		params[param] = stringParam("参数 "+param, true)
	}
	return &fakeMCPTool{
		server: server,
		info: &schema.ToolInfo{
			Name:        name,
			Desc:        desc,
			ParamsOneOf: schema.NewParamsOneOfByParams(params),
		},
		result: "ok",
	}
}

func TestToolRegistryQualifiedNameAndSearch(t *testing.T) {
	registry := newToolRegistry()
	scan := newFakeMCPTool("sophon-tool-runner", "sqlmap", "SQL 注入检测工具", "url")
	port := newFakeMCPTool("sophon-tool-runner", "nmap", "端口扫描工具", "target")
	registry.add("sophon-tool-runner", scan, scan.info)
	registry.add("sophon-tool-runner", port, port.info)

	if got := mcpQualifiedToolName("sophon-tool-runner", "sqlmap"); got != "sophon-tool-runner__sqlmap" {
		t.Fatalf("限定名生成错误: %s", got)
	}
	if entry := registry.get("sophon-tool-runner__sqlmap"); entry == nil || entry.toolName != "sqlmap" {
		t.Fatalf("按限定名检索失败: %#v", entry)
	}
	if got := requiredParams(scan.info); len(got) != 1 || got[0] != "url" {
		t.Fatalf("必填参数提取错误: %#v", got)
	}
	if matches := registry.search("sql", 10); len(matches) != 1 || matches[0].toolName != "sqlmap" {
		t.Fatalf("关键字检索错误: %#v", matches)
	}
	if matches := registry.search("端口", 10); len(matches) != 1 || matches[0].toolName != "nmap" {
		t.Fatalf("描述检索错误: %#v", matches)
	}
	if matches := registry.search("sql 注入", 10); len(matches) != 1 {
		t.Fatalf("多关键字检索错误: %#v", matches)
	}
	if matches := registry.findByToolName("sqlmap"); len(matches) != 1 {
		t.Fatalf("按裸工具名检索错误: %#v", matches)
	}
	if server := registry.serverOf("sophon-tool-runner__sqlmap"); server != "sophon-tool-runner" {
		t.Fatalf("服务名解析错误: %s", server)
	}
}

func TestMCPDiscoveryToolsSearchAndUse(t *testing.T) {
	ctx := context.Background()
	service := &Service{registry: newToolRegistry()}
	echo := newFakeMCPTool("sophon-tool-runner", "echo_tool", "回显工具", "message")
	service.registry.add("sophon-tool-runner", echo, echo.info)

	searchResult, err := service.runMCPSearchTools(ctx, `{"query":"echo"}`)
	if err != nil {
		t.Fatalf("搜索工具失败: %v", err)
	}
	if !strings.Contains(searchResult, "sophon-tool-runner__echo_tool") ||
		!strings.Contains(searchResult, "必填参数: message") {
		t.Fatalf("搜索结果缺少限定名或必填参数: %s", searchResult)
	}

	if _, err := service.runMCPUsetool(
		ctx,
		`{"tool_name":"sophon-tool-runner__echo_tool","arguments_json":"{\"message\":\"hi\"}"}`,
	); err != nil {
		t.Fatalf("调用注册工具失败: %v", err)
	}
	if len(echo.calls) != 1 || echo.calls[0] != `{"message":"hi"}` {
		t.Fatalf("工具参数未按原样透传: %#v", echo.calls)
	}

	// arguments_json 允许直接传对象，避免模型把 JSON 再转义一次。
	if _, err := service.runMCPUsetool(
		ctx,
		`{"tool_name":"sophon-tool-runner__echo_tool","arguments_json":{"message":"yo"}}`,
	); err != nil {
		t.Fatalf("对象形式参数调用失败: %v", err)
	}
	if len(echo.calls) != 2 || echo.calls[1] != `{"message":"yo"}` {
		t.Fatalf("对象形式参数未透传: %#v", echo.calls)
	}

	if _, err := service.runMCPUsetool(ctx, `{"tool_name":"echo_tool"}`); err == nil ||
		!strings.Contains(err.Error(), "sophon-tool-runner__echo_tool") {
		t.Fatalf("裸工具名应提示限定名，实际 err=%v", err)
	}
	if _, err := service.runMCPUsetool(ctx, `{"tool_name":"missing__tool"}`); err == nil {
		t.Fatalf("未注册工具应返回错误")
	}
	if _, err := service.runMCPUsetool(
		ctx,
		`{"tool_name":"sophon-tool-runner__echo_tool","arguments_json":"not-json"}`,
	); err == nil {
		t.Fatalf("非法 JSON 参数应返回错误")
	}
}

func TestMCPDiscoveryToolsRespectSubagentMode(t *testing.T) {
	service := &Service{registry: newToolRegistry()}
	scan := newFakeMCPTool("sophon-tool-runner", "sqlmap", "SQL 注入检测", "url")
	service.registry.add("sophon-tool-runner", scan, scan.info)

	ctx := execctx.WithSubagent(context.Background(), execctx.SubagentInfo{
		ID:    "sub-test",
		Mode:  subagentModeReadOnly,
		Depth: 1,
	})
	_, err := service.runMCPUsetool(
		ctx,
		`{"tool_name":"sophon-tool-runner__sqlmap","arguments_json":{"url":"http://example.com"}}`,
	)
	if err == nil || !strings.Contains(err.Error(), "只读子 Agent") {
		t.Fatalf("只读子 Agent 应被拒绝调用主动测试工具，实际 err=%v", err)
	}
	if len(scan.calls) != 0 {
		t.Fatalf("被拒绝的工具不应真正执行: %#v", scan.calls)
	}
}

func TestNewServiceKeepsHighFrequencyToolsDirect(t *testing.T) {
	service, err := NewService(nil, config.Config{AgentMock: true}, []tool.BaseTool{
		newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command"),
		newFakeMCPTool("sophon-tool-runner", "execute-python-script", "执行脚本", "script"),
		newFakeMCPTool("sophon-tool-runner", "sqlmap", "SQL 注入检测", "url"),
	}, nil)
	if err != nil {
		t.Fatalf("创建 Agent 服务失败: %v", err)
	}
	if service.registry.len() != 1 {
		t.Fatalf("只有非高频 MCP 工具应进入注册表: %d", service.registry.len())
	}
	names := map[string]bool{}
	for _, item := range service.tools {
		info, err := item.Info(context.Background())
		if err != nil || info == nil {
			continue
		}
		names[info.Name] = true
	}
	for _, want := range []string{"exec", "execute-python-script", mcpSearchToolName, mcpUseToolName} {
		if !names[want] {
			t.Fatalf("工具 %s 应直接暴露给模型: %#v", want, names)
		}
	}
	if names["sqlmap"] {
		t.Fatalf("高频以外的 MCP 工具不应直接暴露 schema")
	}
	entry := service.registry.get("sophon-tool-runner__sqlmap")
	if entry == nil {
		t.Fatalf("被隐藏的 MCP 工具应可通过限定名调用")
	}
	if builtin := service.registry.get("sophon-agent__project_list_chains"); builtin != nil {
		t.Fatalf("平台内置工具不应进入 MCP 发现层: %#v", builtin)
	}
}
