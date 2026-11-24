package agent

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"
)

func TestMCPSearchDescriptionCoversToolCategories(t *testing.T) {
	service := &Service{registry: newToolRegistry()}
	suo5 := newFakeMCPTool("tool-runner", "suo5", "代理隧道", "target")
	godzilla := newFakeMCPTool("tool-runner", "godzilla", "哥斯拉 Godzilla WebShell 连接验证", "options_json")
	service.registry.add(
		"tool-runner",
		suo5,
		suo5.info,
	)
	service.registry.add(
		"tool-runner",
		godzilla,
		godzilla.info,
	)
	var searchTool tool.BaseTool
	for _, item := range newMCPDiscoveryTools(service) {
		info, err := item.Info(context.Background())
		if err != nil {
			t.Fatalf("读取工具信息失败: %v", err)
		}
		if info != nil && info.Name == mcpSearchToolName {
			searchTool = item
			break
		}
	}
	if searchTool == nil {
		t.Fatal("未找到 mcp_search_tools")
	}
	info, err := searchTool.Info(context.Background())
	if err != nil {
		t.Fatalf("读取 mcp_search_tools 信息失败: %v", err)
	}
	for _, want := range []string{"信息收集", "渗透测试", "代码审计", "代理隧道"} {
		if !strings.Contains(info.Desc, want) {
			t.Fatalf("mcp_search_tools 简介缺少 %q: %s", want, info.Desc)
		}
	}
	for query, want := range map[string]string{
		"suo5":     "tool-runner__suo5",
		"godzilla": "tool-runner__godzilla",
		"哥斯拉":      "tool-runner__godzilla",
	} {
		result, err := service.runMCPSearchTools(
			context.Background(),
			fmt.Sprintf(`{"query":%q}`, query),
		)
		if err != nil || !strings.Contains(result, want) {
			t.Fatalf("MCP 搜索 %q 未找到 %q: result=%q err=%v", query, want, result, err)
		}
	}
}
