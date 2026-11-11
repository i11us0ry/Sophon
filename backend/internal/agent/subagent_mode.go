package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/execctx"
	"sophon/internal/policy"
)

// 子 Agent 能力模式。模式只收紧角色和工具边界，安全拦截统一由拦截设置判定。
const (
	subagentModeReadOnly  = "read_only"
	subagentModeReadWrite = "read_write"
	subagentModeExecute   = "execute"
	subagentModeAll       = "all"
)

// subagentModeHelp 用于工具描述，保持与 normalizeSubagentMode 的取值一致。
const subagentModeHelp = "read_only=只读；read_write=可写工作区与写回事实/漏洞；execute=可主动测试，安全拦截由拦截设置判定；all=继承主 Agent 全部能力（默认）"

func normalizeSubagentMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default":
		return subagentModeAll
	case subagentModeReadOnly, "readonly", "read-only", "只读":
		return subagentModeReadOnly
	case subagentModeReadWrite, "readwrite", "read-write", "可写":
		return subagentModeReadWrite
	case subagentModeExecute, "exec", "主动执行", "主动测试":
		return subagentModeExecute
	case subagentModeAll, "full", "完整":
		return subagentModeAll
	default:
		return ""
	}
}

// newSubagentID 生成子 Agent 标识，同时用作其独立工作区目录名。
func newSubagentID() string {
	id := randomID()
	if len(id) > 12 {
		id = id[:12]
	}
	return "sub-" + id
}

// parseSubagentMCPScope 解析 MCP 继承策略：空表示继承全部，
// 支持 none / all / 服务名 / 工具名 / server__tool，多个取值用逗号或空格分隔。
func parseSubagentMCPScope(value string) []string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	parts := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
	scope := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			scope = append(scope, item)
		}
	}
	return scope
}

// subagentModeGuidance 把能力模式写进子 Agent 提示词，让模型知道被拒绝的边界，
// 真正的权限判定仍然由 subagentToolDecision 在工具执行前完成。
func subagentModeGuidance(ctx context.Context) string {
	info, ok := execctx.Subagent(ctx)
	if !ok {
		return ""
	}
	switch normalizeSubagentMode(info.Mode) {
	case subagentModeReadOnly:
		return "\n\n能力模式：只读。只能查询、分析和读取，禁止修改本地文件、项目数据或对目标发起主动测试；被拒绝的工具不要绕过，改为在结论中说明。"
	case subagentModeReadWrite:
		return "\n\n能力模式：可写。可以读写自己的工作区并写回事实、测试结果与漏洞证据，但不能对目标发起主动扫描或破坏性操作。"
	case subagentModeExecute:
		return "\n\n能力模式：主动测试。可以发起主动验证；deny、ask、allow 安全判断以设置中的拦截规则为唯一依据。"
	default:
		return ""
	}
}

// projectMutatingTool 判断内置项目工具是否会修改项目数据。
// 只读模式据此拒绝写回，写回类工具在其他模式中允许使用（凭证与证据必须落库）。
func projectMutatingTool(toolName string) bool {
	name := strings.ToLower(strings.TrimSpace(toolName))
	for _, marker := range []string{
		"upsert", "create", "update", "delete", "_report_", "complete", "start",
		"plan", "import", "save", "write", "recompute", "sync",
		// 放进发现层后仍需拦截的写操作命名（只读子 Agent 不得调用）。
		"add", "insert", "record", "resolve", "link", "set_",
	} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// projectWritebackTool 判断工具是否是「把测试结果写回项目」的通道。
func projectWritebackTool(toolName string) bool {
	name := strings.ToLower(strings.TrimSpace(toolName))
	if !strings.HasPrefix(name, "project_") {
		return false
	}
	for _, marker := range []string{"upsert", "report", "complete", "start", "plan", "record", "write"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// subagentToolDecision 在工具执行前按子 Agent 能力模式做一次收紧判定。
// 返回 allowed=false 时，调用方应把理由回传模型而不是中断整轮。
func (s *Service) subagentToolDecision(
	ctx context.Context,
	toolName string,
	args map[string]interface{},
) (bool, string) {
	info, ok := execctx.Subagent(ctx)
	if !ok {
		return true, ""
	}
	mode := normalizeSubagentMode(info.Mode)
	if mode == "" {
		return false, fmt.Sprintf("未知的子 Agent 能力模式 %q", info.Mode)
	}
	if mode == subagentModeAll {
		return true, ""
	}

	analysis := s.analyzeToolCapability(ctx, toolName, args)
	plainName := s.plainToolName(toolName)
	mutating := projectMutatingTool(plainName)
	writeback := projectWritebackTool(plainName)

	switch mode {
	case subagentModeReadOnly:
		if mutating {
			return false, "只读子 Agent 不允许修改项目数据"
		}
		if analysis.capability.Rank() > policy.CapabilityRead.Rank() {
			return false, fmt.Sprintf(
				"只读子 Agent 不允许执行 %s 级工具（%s）",
				analysis.capability,
				analysis.reason,
			)
		}
		return true, ""
	case subagentModeReadWrite:
		if writeback {
			return true, ""
		}
		if analysis.capability.Rank() <= policy.CapabilityRead.Rank() {
			return true, ""
		}
		if analysis.localWrite {
			return true, ""
		}
		return false, fmt.Sprintf(
			"可写子 Agent 只允许本地读写，拒绝 %s 级操作（%s）",
			analysis.capability,
			analysis.reason,
		)
	case subagentModeExecute:
		return true, ""
	}
	return false, "子 Agent 能力模式未授权该工具"
}

type toolCapabilityAnalysis struct {
	capability policy.Capability
	reason     string
	// localWrite 表示命令/脚本只在本地写入，不涉及外部目标。
	localWrite bool
}

// analyzeToolCapability 解析工具本次调用的能力等级：
// exec 与脚本按本次参数静态分析，其他工具按 MCP 配置/默认能力标签判定。
func (s *Service) analyzeToolCapability(
	ctx context.Context,
	toolName string,
	args map[string]interface{},
) toolCapabilityAnalysis {
	plainName := s.plainToolName(toolName)
	serverName := ""
	if s != nil && s.registry != nil {
		serverName = s.registry.serverOf(toolName)
	}

	switch strings.ToLower(plainName) {
	case "exec":
		analysis := policy.AnalyzeCommand(modeStringArg(args, "command"))
		return toolCapabilityAnalysis{
			capability: analysis.Capability,
			reason:     analysis.Reason,
			localWrite: analysis.Capability == policy.CapabilityDestructive &&
				!analysis.Delete &&
				!analysis.Catastrophic &&
				!analysis.UnresolvedTarget &&
				len(analysis.Targets) == 0,
		}
	case "execute-python-script":
		analysis := policy.AnalyzePythonScript(modeStringArg(args, "script"))
		return toolCapabilityAnalysis{
			capability: analysis.Capability,
			reason:     analysis.Reason,
			localWrite: analysis.Capability == policy.CapabilityDestructive && !analysis.Delete,
		}
	}

	if s != nil && s.db != nil && serverName != "" {
		if setting, err := s.db.GetMCPToolSetting(ctx, serverName, plainName); err == nil && setting != nil {
			if capability, ok := policy.NormalizeCapability(setting.Capability); ok {
				return toolCapabilityAnalysis{
					capability: capability,
					reason:     "按 MCP 工具能力标签判定",
				}
			}
		}
	}
	capability := policy.DefaultCapability(plainName)
	return toolCapabilityAnalysis{
		capability: capability,
		reason:     "按内置能力标签判定",
	}
}

// plainToolName 把 server__tool 限定名还原为工具名，未登记时原样返回。
func (s *Service) plainToolName(toolName string) string {
	trimmed := strings.TrimSpace(toolName)
	if s != nil && s.registry != nil {
		if entry := s.registry.get(trimmed); entry != nil {
			return entry.toolName
		}
	}
	// 未登记时按 server__tool 约定回退，保证能力判定仍能识别内置工具。
	if index := strings.Index(trimmed, "__"); index > 0 && index+2 < len(trimmed) {
		return trimmed[index+2:]
	}
	return trimmed
}

func modeStringArg(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	value, _ := args[key].(string)
	return value
}

// gatedSubagentTool 在子 Agent 工具调用前执行能力模式判定。
type gatedSubagentTool struct {
	service *Service
	name    string
	inner   tool.BaseTool
}

func (t *gatedSubagentTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return t.inner.Info(ctx)
}

func (t *gatedSubagentTool) MCPServerName() string {
	if named, ok := t.inner.(serverNamedTool); ok {
		return named.MCPServerName()
	}
	return ""
}

func (t *gatedSubagentTool) InvokableRun(
	ctx context.Context,
	argumentsInJSON string,
	options ...tool.Option,
) (string, error) {
	// 工具发现层的内部工具在自身逻辑里对目标工具做同样的判定，此处不重复。
	if t.name != mcpUseToolName && t.name != mcpSearchToolName {
		args := map[string]interface{}{}
		if trimmed := strings.TrimSpace(argumentsInJSON); trimmed != "" && trimmed != "null" {
			_ = json.Unmarshal([]byte(trimmed), &args)
		}
		if allowed, reason := t.service.subagentToolDecision(ctx, t.name, args); !allowed {
			return fmt.Sprintf(
				"[工具 %s 执行失败，请根据错误决定重试或向用户说明]\n子 Agent 能力模式拒绝执行 %s：%s",
				t.name,
				t.name,
				reason,
			), nil
		}
	}
	return invokeTool(ctx, t.inner, argumentsInJSON, options...)
}

// gateSubagentTools 为子 Agent 包装一层能力门禁；非子 Agent 上下文直接返回原工具。
func (s *Service) gateSubagentTools(ctx context.Context, items []tool.BaseTool) []tool.BaseTool {
	if _, ok := execctx.Subagent(ctx); !ok {
		return items
	}
	gated := make([]tool.BaseTool, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		info, err := item.Info(ctx)
		if err != nil || info == nil {
			continue
		}
		gated = append(gated, &gatedSubagentTool{service: s, name: info.Name, inner: item})
	}
	return gated
}

// applySubagentMCPScope 按子 Agent 的 MCP 继承策略过滤工具集。
// Scope 为空表示全部继承；包含 "none" 时不继承任何 MCP 工具；
// 其余取值可以是 MCP 服务名、工具名或 server__tool 限定名。
func (s *Service) applySubagentMCPScope(ctx context.Context, items []tool.BaseTool) []tool.BaseTool {
	info, ok := execctx.Subagent(ctx)
	if !ok || len(info.MCPScope) == 0 {
		return items
	}
	allowed := map[string]bool{}
	inheritNone := false
	for _, token := range info.MCPScope {
		switch normalized := strings.ToLower(strings.TrimSpace(token)); normalized {
		case "":
			continue
		case "all":
			return items
		case "none", "no", "无":
			inheritNone = true
		default:
			allowed[normalized] = true
		}
	}
	filtered := make([]tool.BaseTool, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		toolInfo, err := item.Info(ctx)
		if err != nil || toolInfo == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(toolInfo.Name))
		serverName := ""
		if s.registry != nil {
			serverName = strings.ToLower(strings.TrimSpace(s.registry.serverOf(name)))
		}
		// 内置工具不受 MCP 继承策略影响，始终可用。
		if serverName == "" {
			filtered = append(filtered, item)
			continue
		}
		if inheritNone {
			continue
		}
		if allowed[name] || allowed[serverName] || allowed[serverName+"__"+name] {
			filtered = append(filtered, item)
		}
	}
	return filtered
}
