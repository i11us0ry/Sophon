package mcpclient

import (
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"sophon/internal/toolwire"
)

func TestResultTextPreservesTextAndStructuredContent(t *testing.T) {
	result := &sdkmcp.CallToolResult{
		Content: []sdkmcp.Content{
			&sdkmcp.TextContent{Text: "scan finished"},
		},
		StructuredContent: map[string]any{
			"records": []any{map[string]any{"port": 443}},
		},
	}
	text, err := resultText(result)
	if err != nil {
		t.Fatalf("渲染 MCP 结果失败: %v", err)
	}
	if !strings.Contains(text, "scan finished") ||
		!strings.Contains(text, toolwire.StructuredContentMarker) ||
		!strings.Contains(text, `"port":443`) {
		t.Fatalf("MCP 文本或结构化内容丢失: %s", text)
	}
}

func TestResultTextStructuredOnly(t *testing.T) {
	result := &sdkmcp.CallToolResult{
		StructuredContent: map[string]any{"ok": true},
	}
	text, err := resultText(result)
	if err != nil {
		t.Fatalf("渲染纯结构化结果失败: %v", err)
	}
	body, structured := toolwire.SplitStructured(text)
	if body != "" || !strings.Contains(string(structured), `"ok":true`) {
		t.Fatalf("纯结构化结果异常: body=%q structured=%s", body, structured)
	}
}

func TestMCPToolFailureUsesCommandExitMetadata(t *testing.T) {
	errorValue := mcpToolFailure("exec", "$ grep missing\n错误: 命令退出码 2", map[string]any{
		"kind":        "command_result",
		"status":      "error",
		"exit_code":   2,
		"error_class": "command_exit",
	})
	if errorValue == nil || errorValue.Error() != "命令退出码 2" {
		t.Fatalf("命令退出错误未正确分类: %v", errorValue)
	}
}

func TestMCPToolFailureUsesPolicyMetadata(t *testing.T) {
	errorValue := mcpToolFailure("exec", "禁止后台启动", map[string]any{
		"kind":        "command_result",
		"status":      "error",
		"error_class": "policy",
	})
	if errorValue == nil || errorValue.Error() != "工具策略拒绝执行" {
		t.Fatalf("策略错误未正确分类: %v", errorValue)
	}
}
