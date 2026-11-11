package agent

import (
	"context"
	"testing"

	"github.com/cloudwego/eino/components/tool"

	"sophon/internal/config"
)

func TestToolInventorySplitsDirectAndSearchable(t *testing.T) {
	service, err := NewService(nil, config.Config{AgentMock: true}, []tool.BaseTool{
		newFakeMCPTool("sophon-tool-runner", "exec", "执行命令", "command"),
		newFakeMCPTool("sophon-tool-runner", "execute-python-script", "执行脚本", "script"),
		newFakeMCPTool("sophon-tool-runner", "nmap", "端口扫描", "target"),
	}, nil)
	if err != nil {
		t.Fatalf("创建 Agent 服务失败: %v", err)
	}

	inventory := service.ToolInventory(context.Background())
	direct := map[string]InventoryTool{}
	for _, item := range inventory.Direct {
		direct[item.Name] = item
	}

	discovery, ok := direct[mcpSearchToolName]
	if !ok {
		t.Fatalf("内置工具 %s 应在直连清单中", mcpSearchToolName)
	}
	if discovery.Kind != toolKindBuiltin || discovery.Toggleable || !discovery.Enabled {
		t.Fatalf("内置工具应不可停用: %#v", discovery)
	}
	if useTool, ok := direct[mcpUseToolName]; !ok || useTool.Kind != toolKindBuiltin {
		t.Fatalf("内置工具 %s 缺失: %#v", mcpUseToolName, useTool)
	}
	if projectTool, ok := direct["project_list"]; !ok || projectTool.Kind != toolKindBuiltin {
		t.Fatalf("项目工具应作为内置工具直连: %#v", projectTool)
	}
	if projectGet, ok := direct["project_get"]; !ok || projectGet.Kind != toolKindBuiltin {
		t.Fatalf("项目详情聚合工具应作为内置工具直连: %#v", projectGet)
	}
	if internetSearch, ok := direct[internetSearchToolName]; !ok ||
		internetSearch.Kind != toolKindBuiltin ||
		internetSearch.Toggleable {
		t.Fatalf("互联网搜索应作为不可停用的内置直连工具: %#v", internetSearch)
	}
	for _, legacy := range []string{
		"project_asset_card",
		"project_get_finding",
		"project_graph_node",
	} {
		if _, exposed := direct[legacy]; exposed {
			t.Fatalf("旧详情工具 %s 不应继续直连", legacy)
		}
	}

	exec, ok := direct["exec"]
	if !ok {
		t.Fatalf("高频 MCP 工具 exec 应在直连清单中")
	}
	if exec.Kind != toolKindMCP || !exec.Toggleable || !exec.Enabled {
		t.Fatalf("直连 MCP 工具应可停用: %#v", exec)
	}
	if exec.ServerName != "sophon-tool-runner" || exec.QualifiedName != "sophon-tool-runner__exec" {
		t.Fatalf("直连 MCP 工具应带来源服务与限定名: %#v", exec)
	}
	if exec.Capability != "destructive" {
		t.Fatalf("exec 默认能力标签应为 destructive: %s", exec.Capability)
	}
	if _, ok := direct["nmap"]; ok {
		t.Fatalf("可搜索的 MCP 工具不应出现在直连清单")
	}
	// 平台内置工具始终直连，不进入 MCP 发现层。
	if _, ok := direct["project_record_fact"]; !ok {
		t.Fatalf("内置工具 project_record_fact 应直连")
	}
	if _, ok := direct["project_list"]; !ok {
		t.Fatalf("内置工具 project_list 应直连")
	}
	if _, ok := direct["project_get"]; !ok {
		t.Fatalf("内置工具 project_get 应直连")
	}
	for _, item := range inventory.Searchable {
		if item.ServerName == "sophon-agent" || item.Kind != toolKindMCP {
			t.Fatalf("可搜索分区只应包含外部 MCP 工具: %#v", item)
		}
	}

	if inventory.Discovery.Registered != 1 {
		t.Fatalf("注册表应只包含非高频 MCP 工具: %d", inventory.Discovery.Registered)
	}
	if inventory.Discovery.SearchTool != mcpSearchToolName || inventory.Discovery.UseTool != mcpUseToolName {
		t.Fatalf("发现层工具名错误: %#v", inventory.Discovery)
	}
	var nmap InventoryTool
	found := false
	for _, item := range inventory.Searchable {
		if item.QualifiedName == "sophon-tool-runner__nmap" {
			nmap = item
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("可搜索工具应包含 nmap: %#v", inventory.Searchable)
	}
	if nmap.Name != "nmap" || nmap.QualifiedName != "sophon-tool-runner__nmap" {
		t.Fatalf("可搜索工具标识错误: %#v", nmap)
	}
	if nmap.Exposure != toolExposureSearchable || !nmap.Toggleable || !nmap.Enabled {
		t.Fatalf("可搜索工具状态错误: %#v", nmap)
	}
	if nmap.Capability != "intrusive" {
		t.Fatalf("nmap 默认能力标签应为 intrusive: %s", nmap.Capability)
	}
	if len(nmap.Parameters) != 1 || nmap.Parameters[0].Name != "target" || !nmap.Parameters[0].Required {
		t.Fatalf("可搜索工具参数提取错误: %#v", nmap.Parameters)
	}
}

func TestToolInventoryWithoutRegistry(t *testing.T) {
	service := &Service{}
	inventory := service.ToolInventory(context.Background())
	if inventory.Direct == nil || inventory.Searchable == nil {
		t.Fatalf("空服务应返回空数组而不是 null: %#v", inventory)
	}
	if inventory.Discovery.SearchTool != mcpSearchToolName {
		t.Fatalf("发现层工具名缺失: %#v", inventory.Discovery)
	}
}
