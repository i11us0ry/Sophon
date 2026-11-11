package agent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

// mcpQualifiedToolName 生成 server__tool 形式的全局工具名。
// 不同 MCP 服务可能存在同名工具（如多个服务都提供 exec），限定名用于消除歧义。
func mcpQualifiedToolName(serverName, toolName string) string {
	server := strings.TrimSpace(serverName)
	name := strings.TrimSpace(toolName)
	if server == "" {
		return name
	}
	return server + "__" + name
}

type registryEntry struct {
	serverName string
	toolName   string
	qualified  string
	desc       string
	required   []string
	tool       tool.BaseTool
}

// toolRegistry 保存 MCP 工具的检索索引；工具本体仍然走原有执行链路
// （Policy Engine -> 人工审批 -> 执行记录 -> 并发限制）。
type toolRegistry struct {
	mu      sync.RWMutex
	entries map[string]*registryEntry
	byTool  map[string][]*registryEntry
}

func newToolRegistry() *toolRegistry {
	return &toolRegistry{
		entries: map[string]*registryEntry{},
		byTool:  map[string][]*registryEntry{},
	}
}

func (r *toolRegistry) add(serverName string, item tool.BaseTool, info *schema.ToolInfo) {
	if r == nil || item == nil || info == nil || strings.TrimSpace(info.Name) == "" {
		return
	}
	entry := &registryEntry{
		serverName: strings.TrimSpace(serverName),
		toolName:   strings.TrimSpace(info.Name),
		qualified:  mcpQualifiedToolName(serverName, info.Name),
		desc:       strings.TrimSpace(info.Desc),
		required:   requiredParams(info),
		tool:       item,
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[entry.qualified] = entry
	key := strings.ToLower(entry.toolName)
	r.byTool[key] = append(r.byTool[key], entry)
}

func (r *toolRegistry) get(qualified string) *registryEntry {
	if r == nil {
		return nil
	}
	key := strings.TrimSpace(qualified)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if entry, ok := r.entries[key]; ok {
		return entry
	}
	for candidate, entry := range r.entries {
		if strings.EqualFold(candidate, key) {
			return entry
		}
	}
	return nil
}

// findByToolName 返回所有同名工具；用于把模型直接写出的裸工具名引导到限定名。
func (r *toolRegistry) findByToolName(toolName string) []*registryEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]*registryEntry(nil), r.byTool[strings.ToLower(strings.TrimSpace(toolName))]...)
}

func (r *toolRegistry) list() []*registryEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := make([]*registryEntry, 0, len(r.entries))
	for _, entry := range r.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].qualified < entries[j].qualified
	})
	return entries
}

func (r *toolRegistry) len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// serverOf 返回工具所属 MCP 服务名，未登记时返回空串（内置工具）。
func (r *toolRegistry) serverOf(toolName string) string {
	entry := r.get(toolName)
	if entry != nil {
		return entry.serverName
	}
	matches := r.findByToolName(toolName)
	if len(matches) == 1 {
		return matches[0].serverName
	}
	return ""
}

// search 按关键字检索工具：所有关键字需在限定名、工具名、服务名或描述中出现。
func (r *toolRegistry) search(query string, limit int) []*registryEntry {
	entries := r.list()
	keywords := strings.Fields(strings.ToLower(strings.TrimSpace(query)))
	matched := make([]*registryEntry, 0, len(entries))
	for _, entry := range entries {
		if matchesKeywords(entry, keywords) {
			matched = append(matched, entry)
		}
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}
	if len(matched) > limit {
		matched = matched[:limit]
	}
	return matched
}

func matchesKeywords(entry *registryEntry, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	haystack := strings.ToLower(strings.Join([]string{
		entry.qualified,
		entry.toolName,
		entry.serverName,
		entry.desc,
		strings.Join(entry.required, " "),
	}, "\n"))
	for _, keyword := range keywords {
		if !strings.Contains(haystack, keyword) {
			return false
		}
	}
	return true
}

// requiredParams 从工具 schema 中提取必填参数名，用于搜索结果里提示调用方式。
func requiredParams(info *schema.ToolInfo) []string {
	if info == nil || info.ParamsOneOf == nil {
		return nil
	}
	schemaValue, err := info.ParamsOneOf.ToJSONSchema()
	if err != nil || schemaValue == nil {
		return nil
	}
	required := append([]string(nil), schemaValue.Required...)
	sort.Strings(required)
	return required
}

type serverNamedTool interface {
	MCPServerName() string
}

// invokeTool 统一调用入口：只有实现了 InvokableTool 的工具才能执行。
func invokeTool(
	ctx context.Context,
	item tool.BaseTool,
	argumentsInJSON string,
	options ...tool.Option,
) (string, error) {
	invokable, ok := item.(tool.InvokableTool)
	if !ok {
		return "", fmt.Errorf("工具不支持调用")
	}
	return invokable.InvokableRun(ctx, argumentsInJSON, options...)
}
