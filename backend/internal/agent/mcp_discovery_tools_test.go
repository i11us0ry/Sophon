package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"
)

func TestMCPSearchDescriptionCoversToolCategories(t *testing.T) {
	service := &Service{registry: newToolRegistry()}
	suo5 := newFakeMCPTool("tool-runner", "suo5", "代理隧道", "target")
	service.registry.add(
		"tool-runner",
		suo5,
		suo5.info,
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
}
