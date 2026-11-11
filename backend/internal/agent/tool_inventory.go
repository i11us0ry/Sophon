package agent

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/cloudwego/eino/schema"
)

// 工具在管理页中的分类：直接暴露给模型，或由 mcp_search_tools 检索后调用。
const (
	toolKindBuiltin        = "builtin"
	toolKindMCP            = "mcp"
	toolExposureDirect     = "direct"
	toolExposureSearchable = "searchable"
)

// ToolParameter 描述工具入参，供 MCP 工具管理页展示。
type ToolParameter struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	Enum        []string `json:"enum,omitempty"`
}

// InventoryTool 是工具管理页的一项：内置/直连工具或可搜索的 MCP 工具。
type InventoryTool struct {
	Name          string          `json:"name"`
	QualifiedName string          `json:"qualifiedName,omitempty"`
	ServerName    string          `json:"serverName,omitempty"`
	Kind          string          `json:"kind"`
	Exposure      string          `json:"exposure"`
	Description   string          `json:"description"`
	Capability    string          `json:"capability"`
	Enabled       bool            `json:"enabled"`
	Toggleable    bool            `json:"toggleable"`
	Parameters    []ToolParameter `json:"parameters"`
}

// ToolDiscoveryInfo 描述工具发现层的入口与规模。
type ToolDiscoveryInfo struct {
	SearchTool string `json:"searchTool"`
	UseTool    string `json:"useTool"`
	Registered int    `json:"registered"`
}

// ToolInventory 是模型当前实际可见的工具视图。
type ToolInventory struct {
	Direct     []InventoryTool   `json:"direct"`
	Searchable []InventoryTool   `json:"searchable"`
	Discovery  ToolDiscoveryInfo `json:"discovery"`
}

// ToolInventory 汇总两类工具：每轮直接暴露给模型的工具，以及只在注册表中、
// 需要 mcp_search_tools + mcp_use_tool 才能调用的 MCP 工具。
func (s *Service) ToolInventory(ctx context.Context) ToolInventory {
	inventory := ToolInventory{
		Direct:     []InventoryTool{},
		Searchable: []InventoryTool{},
		Discovery: ToolDiscoveryInfo{
			SearchTool: mcpSearchToolName,
			UseTool:    mcpUseToolName,
		},
	}
	if s == nil {
		return inventory
	}
	inventory.Discovery.Registered = s.registry.len()
	settings := s.mcpToolSettings(ctx)
	disabled := s.disabledMCPToolNames(ctx)

	for _, item := range s.tools {
		if item == nil {
			continue
		}
		info, err := item.Info(ctx)
		if err != nil || info == nil || strings.TrimSpace(info.Name) == "" {
			continue
		}
		name := strings.TrimSpace(info.Name)
		entry := InventoryTool{
			Name:        name,
			Kind:        toolKindBuiltin,
			Exposure:    toolExposureDirect,
			Description: strings.TrimSpace(info.Desc),
			// 内置工具由平台实现，不参与 MCP 能力标签体系，因此不展示能力等级。
			Capability: "",
			Enabled:    true,
			Toggleable: false,
			Parameters: toolSchemaParameters(info),
		}
		if named, ok := item.(serverNamedTool); ok {
			if serverName := strings.TrimSpace(named.MCPServerName()); serverName != "" {
				qualified := mcpQualifiedToolName(serverName, name)
				capability, enabled := mcpToolStatus(&registryEntry{
					serverName: serverName,
					toolName:   name,
					qualified:  qualified,
				}, settings, disabled)
				entry.Kind = toolKindMCP
				entry.ServerName = serverName
				entry.QualifiedName = qualified
				entry.Capability = string(capability)
				entry.Enabled = enabled
				// 直连的 MCP 工具仍然支持停用与能力标签调整。
				entry.Toggleable = true
			}
		}
		inventory.Direct = append(inventory.Direct, entry)
	}
	sort.Slice(inventory.Direct, func(i, j int) bool {
		if inventory.Direct[i].Kind != inventory.Direct[j].Kind {
			return inventory.Direct[i].Kind == toolKindBuiltin
		}
		return inventory.Direct[i].Name < inventory.Direct[j].Name
	})

	for _, registered := range s.registry.list() {
		capability, enabled := mcpToolStatus(registered, settings, disabled)
		entry := InventoryTool{
			Name:          registered.toolName,
			QualifiedName: registered.qualified,
			ServerName:    registered.serverName,
			Kind:          toolKindMCP,
			Exposure:      toolExposureSearchable,
			Description:   registered.desc,
			Capability:    string(capability),
			Enabled:       enabled,
			Toggleable:    true,
			Parameters:    []ToolParameter{},
		}
		if info, err := registered.tool.Info(ctx); err == nil && info != nil {
			entry.Parameters = toolSchemaParameters(info)
			if entry.Description == "" {
				entry.Description = strings.TrimSpace(info.Desc)
			}
		}
		inventory.Searchable = append(inventory.Searchable, entry)
	}
	return inventory
}

// toolSchemaParameters 从工具 schema 提取参数列表，与 MCP 工具接口保持同样的展示结构。
func toolSchemaParameters(info *schema.ToolInfo) []ToolParameter {
	parameters := []ToolParameter{}
	if info == nil || info.ParamsOneOf == nil {
		return parameters
	}
	raw, err := info.ParamsOneOf.ToJSONSchema()
	if err != nil || raw == nil {
		return parameters
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return parameters
	}
	var parsed struct {
		Properties map[string]struct {
			Type        string   `json:"type"`
			Description string   `json:"description"`
			Enum        []string `json:"enum"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		return parameters
	}
	required := make(map[string]bool, len(parsed.Required))
	for _, name := range parsed.Required {
		required[name] = true
	}
	names := make([]string, 0, len(parsed.Properties))
	for name := range parsed.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		property := parsed.Properties[name]
		parameters = append(parameters, ToolParameter{
			Name:        name,
			Type:        property.Type,
			Description: property.Description,
			Required:    required[name],
			Enum:        property.Enum,
		})
	}
	return parameters
}
