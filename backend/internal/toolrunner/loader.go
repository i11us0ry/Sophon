// Package toolrunner 加载 CS AI 工具目录中的 YAML 定义，并把它们暴露为 MCP 工具。
package toolrunner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Parameter struct {
	Name        string   `yaml:"name"`
	Type        string   `yaml:"type"`
	Description string   `yaml:"description"`
	Required    bool     `yaml:"required"`
	Flag        string   `yaml:"flag"`
	Format      string   `yaml:"format"`
	Default     any      `yaml:"default"`
	Position    *int     `yaml:"position"`
	Options     []string `yaml:"options"`
	Template    string   `yaml:"template"`
}

type Tool struct {
	Name             string      `yaml:"name"`
	Command          string      `yaml:"command"`
	Enabled          bool        `yaml:"enabled"`
	ShortDescription string      `yaml:"short_description"`
	Description      string      `yaml:"description"`
	Args             []string    `yaml:"args"`
	AllowedExitCodes []int       `yaml:"allowed_exit_codes"`
	Parameters       []Parameter `yaml:"parameters"`
	// TimeoutSeconds 是工具级超时上限（0 表示继承 runner 全局超时）。
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// RequiresBinaries / RequiresPython 显式声明运行依赖，供工具自检使用：
	// 包装脚本里 subprocess 调用的命令与运行时才 import 的模块，静态扫描不到时靠它兜底。
	RequiresBinaries []string `yaml:"requires_binaries"`
	RequiresPython   []string `yaml:"requires_python"`
	// RequiresCapabilities 声明原始套接字等 Linux capability 依赖，供工具自检使用。
	RequiresCapabilities []string `yaml:"requires_capabilities"`
}

// maxToolTimeoutSeconds 限制工具级超时上限，避免 YAML 写出不可控的长任务。
const maxToolTimeoutSeconds = 3600

// LoadDir 读取目录下全部 *.yaml 工具定义，按名称排序。
func LoadDir(dir string) ([]Tool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取工具目录 %s: %w", dir, err)
	}
	tools := make([]Tool, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".yaml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取 %s: %w", path, err)
		}
		var item Tool
		if err := yaml.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("解析 %s: %w", path, err)
		}
		if strings.TrimSpace(item.Name) == "" || strings.TrimSpace(item.Command) == "" {
			continue
		}
		item.TimeoutSeconds = normalizeTimeoutSeconds(item.TimeoutSeconds)
		item.RequiresBinaries = normalizeRequirementList(item.RequiresBinaries)
		item.RequiresPython = normalizeRequirementList(item.RequiresPython)
		item.RequiresCapabilities = normalizeRequirementList(item.RequiresCapabilities)
		tools = append(tools, item)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools, nil
}

func normalizeTimeoutSeconds(value int) int {
	if value < 0 {
		return 0
	}
	if value > maxToolTimeoutSeconds {
		return maxToolTimeoutSeconds
	}
	return value
}

// normalizeRequirementList 去掉空项与重复项，保持声明顺序。
func normalizeRequirementList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		result = append(result, trimmed)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// Summary 返回给模型看的简短描述，优先 short_description，避免上下文被长描述占满。
func (t Tool) Summary() string {
	if value := strings.TrimSpace(t.ShortDescription); value != "" {
		return value
	}
	desc := strings.TrimSpace(t.Description)
	if index := strings.IndexByte(desc, '\n'); index > 0 {
		desc = strings.TrimSpace(desc[:index])
	}
	if runes := []rune(desc); len(runes) > 300 {
		desc = string(runes[:300]) + "..."
	}
	return desc
}

// InputSchema 生成 MCP 工具的 JSON Schema。
func (t Tool) InputSchema() map[string]any {
	properties := make(map[string]any, len(t.Parameters))
	required := make([]string, 0, len(t.Parameters))
	for _, param := range t.Parameters {
		property := map[string]any{
			"type":        jsonType(param.Type),
			"description": strings.TrimSpace(param.Description),
		}
		if len(param.Options) > 0 {
			property["enum"] = param.Options
		}
		properties[param.Name] = property
		if param.Required {
			required = append(required, param.Name)
		}
	}
	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func jsonType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "bool":
		return "boolean"
	case "int", "integer":
		return "integer"
	case "float", "number":
		return "number"
	case "array":
		return "array"
	case "object":
		return "object"
	default:
		return "string"
	}
}
