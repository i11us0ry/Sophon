package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/policy"
)

const (
	mcpSearchToolName = "mcp_search_tools"
	mcpUseToolName    = "mcp_use_tool"
)

// newMCPDiscoveryTools 构造 MCP 工具发现层：先搜索、再按限定名调用。
// 注册表为空（没有 MCP 服务）时不暴露这两个工具，避免模型空转。
func newMCPDiscoveryTools(service *Service) []tool.BaseTool {
	if service == nil || service.registry == nil || service.registry.len() == 0 {
		return nil
	}
	return []tool.BaseTool{
		&jsonTool{
			name: mcpSearchToolName,
			desc: "按关键字检索当前已注册的 MCP 工具，覆盖信息收集、渗透测试、代码审计、" +
				"代理隧道等场景，返回限定名（server__tool）、能力标签、启用状态与必填参数。" +
				"需要执行 MCP 工具前先用它确认工具名与参数。",
			params: map[string]*schema.ParameterInfo{
				"query": stringParam("检索关键字，可包含工具名、用途、目标关键词；留空返回全部工具", true),
				"limit": integerParam("返回条数上限，默认 20，最大 50"),
			},
			run: service.runMCPSearchTools,
		},
		&jsonTool{
			name: mcpUseToolName,
			desc: "调用一个已注册的 MCP 工具。tool_name 使用 mcp_search_tools 返回的限定名" +
				"（server__tool），arguments_json 是该工具的 JSON 参数对象。" +
				"调用仍会经过能力策略与人工审批。",
			params: map[string]*schema.ParameterInfo{
				"tool_name":      stringParam("MCP 工具限定名，格式 server__tool", true),
				"arguments_json": stringParam("工具参数 JSON 对象，例如 {\"url\":\"http://target\"}"),
			},
			run: service.runMCPUsetool,
		},
	}
}

func (s *Service) runMCPSearchTools(ctx context.Context, raw string) (string, error) {
	var request struct {
		Query string  `json:"query"`
		Limit flexInt `json:"limit"`
	}
	if err := decodeToolArgs(raw, &request); err != nil {
		return "", err
	}
	limit := int(request.Limit)
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}
	matches := s.registry.search(request.Query, limit)
	total := s.registry.len()
	settings := s.mcpToolSettings(ctx)
	disabled := s.disabledMCPToolNames(ctx)

	var builder strings.Builder
	fmt.Fprintf(
		&builder,
		"已注册 MCP 工具 %d 个，匹配 %d 个（limit=%d）。\n",
		total,
		len(matches),
		limit,
	)
	if len(matches) == 0 {
		builder.WriteString("没有匹配项，请更换关键字，或省略 query 查看全部工具。")
		return builder.String(), nil
	}
	for index, entry := range matches {
		capability, enabled := mcpToolStatus(entry, settings, disabled)
		fmt.Fprintf(
			&builder,
			"\n%d. %s [capability=%s, enabled=%t]\n   描述: %s\n",
			index+1,
			entry.qualified,
			capability,
			enabled,
			truncateRunes(orDefaultProjectToolValue(entry.desc, "无描述"), 160),
		)
		if len(entry.required) > 0 {
			fmt.Fprintf(&builder, "   必填参数: %s\n", strings.Join(entry.required, ", "))
		}
		fmt.Fprintf(
			&builder,
			"   调用示例: %s {\"tool_name\":%q,\"arguments_json\":\"{...}\"}\n",
			mcpUseToolName,
			entry.qualified,
		)
	}
	builder.WriteString("\n只调用 enabled=true 的工具；停用的工具需要用户在 MCP 工具管理中重新启用。")
	return builder.String(), nil
}

func (s *Service) runMCPUsetool(ctx context.Context, raw string) (string, error) {
	var request struct {
		ToolName      string          `json:"tool_name"`
		ArgumentsJSON json.RawMessage `json:"arguments_json"`
	}
	if err := decodeToolArgs(raw, &request); err != nil {
		return "", err
	}
	qualified := strings.TrimSpace(request.ToolName)
	if qualified == "" {
		return "", fmt.Errorf("tool_name 不能为空")
	}
	entry := s.registry.get(qualified)
	if entry == nil {
		if matches := s.registry.findByToolName(qualified); len(matches) > 0 {
			names := make([]string, 0, len(matches))
			for _, match := range matches {
				names = append(names, match.qualified)
			}
			sort.Strings(names)
			return "", fmt.Errorf(
				"工具 %s 需要限定名，请改用其中之一：%s",
				qualified,
				strings.Join(names, ", "),
			)
		}
		return "", fmt.Errorf("未注册的工具 %s，请先用 %s 检索", qualified, mcpSearchToolName)
	}
	if enabled, capability := s.mcpEntryStatus(ctx, entry); !enabled {
		return "", fmt.Errorf(
			"工具 %s（capability=%s）已在 MCP 工具管理中被停用，本次调用未执行",
			entry.qualified,
			capability,
		)
	}
	arguments, err := normalizeRawArguments(request.ArgumentsJSON)
	if err != nil {
		return "", fmt.Errorf("工具 %s 参数不合法: %w", entry.qualified, err)
	}
	args := map[string]interface{}{}
	if err := json.Unmarshal([]byte(arguments), &args); err != nil {
		return "", fmt.Errorf("工具 %s 参数需为 JSON 对象: %w", entry.qualified, err)
	}
	if allowed, reason := s.subagentToolDecision(ctx, entry.qualified, args); !allowed {
		return "", fmt.Errorf("子 Agent 能力模式拒绝执行 %s：%s", entry.qualified, reason)
	}
	return invokeTool(ctx, entry.tool, arguments)
}

func (s *Service) mcpToolSettings(ctx context.Context) map[string]databaseMCPToolSetting {
	settings := map[string]databaseMCPToolSetting{}
	if s == nil || s.db == nil {
		return settings
	}
	items, err := s.db.ListMCPToolSettings(ctx)
	if err != nil {
		return settings
	}
	for _, item := range items {
		key := mcpQualifiedToolName(item.ServerName, item.ToolName)
		settings[key] = databaseMCPToolSetting{
			enabled:    item.Enabled,
			capability: item.Capability,
		}
	}
	return settings
}

type databaseMCPToolSetting struct {
	enabled    bool
	capability string
}

func mcpToolStatus(
	entry *registryEntry,
	settings map[string]databaseMCPToolSetting,
	disabled map[string]bool,
) (policy.Capability, bool) {
	capability := policy.DefaultCapability(entry.toolName)
	enabled := true
	if setting, ok := settings[entry.qualified]; ok {
		if normalized, valid := policy.NormalizeCapability(setting.capability); valid {
			capability = normalized
		}
		enabled = setting.enabled
	}
	if disabled[entry.toolName] {
		return capability, false
	}
	return capability, enabled
}

func (s *Service) mcpEntryStatus(ctx context.Context, entry *registryEntry) (bool, policy.Capability) {
	capability, enabled := mcpToolStatus(entry, s.mcpToolSettings(ctx), s.disabledMCPToolNames(ctx))
	return enabled, capability
}

func (s *Service) disabledMCPToolNames(ctx context.Context) map[string]bool {
	if s == nil || s.db == nil {
		return map[string]bool{}
	}
	disabled, err := s.db.DisabledMCPToolNames(ctx)
	if err != nil {
		return map[string]bool{}
	}
	return disabled
}

func normalizeRawArguments(raw json.RawMessage) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return "{}", nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var decoded string
		if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
			return "", err
		}
		trimmed = strings.TrimSpace(decoded)
		if trimmed == "" {
			return "{}", nil
		}
	}
	var probe map[string]interface{}
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return "", fmt.Errorf("参数需为 JSON 对象: %w", err)
	}
	return trimmed, nil
}
