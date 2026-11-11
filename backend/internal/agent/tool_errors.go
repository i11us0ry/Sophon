package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const tolerantToolErrorRunes = 6000

// tolerantTool 把工具执行错误转成普通工具结果回传模型，让模型自行重试或向用户解释；
// 只有上下文取消（用户停止/超时）仍然中断整轮。
type tolerantTool struct {
	inner tool.BaseTool
}

func (t *tolerantTool) Info(ctx context.Context) (*schema.ToolInfo, error) {
	return t.inner.Info(ctx)
}

// MCPServerName 转发 MCP 服务名，保证包装后仍能识别工具来源。
func (t *tolerantTool) MCPServerName() string {
	if named, ok := t.inner.(serverNamedTool); ok {
		return named.MCPServerName()
	}
	return ""
}

func (t *tolerantTool) InvokableRun(
	ctx context.Context,
	argumentsInJSON string,
	opts ...tool.Option,
) (string, error) {
	invokable, ok := t.inner.(tool.InvokableTool)
	if !ok {
		return "", fmt.Errorf("tool %s is not invokable", t.toolName(ctx))
	}
	result, err := invokable.InvokableRun(ctx, argumentsInJSON, opts...)
	if err == nil {
		return result, nil
	}
	if ctx.Err() != nil {
		return result, err
	}

	detail := strings.TrimSpace(result)
	if detail == "" {
		detail = strings.TrimSpace(err.Error())
	}
	// 工具错误通常写在输出末尾（命令回显、日志在前），超长时保留尾部。
	detail = truncateToolErrorTail(detail, tolerantToolErrorRunes)
	return fmt.Sprintf(
		"[工具 %s 执行失败。先分析错误类型：命令语法、引号、路径、参数、"+
			"Shell兼容、临时网络或超时等可修复问题，必须修改命令、参数或执行方式后重试，"+
			"禁止原样重复失败命令；连续两次相同错误后停止重试。"+
			"策略拒绝、权限或凭据缺失、目标持续不可达、用户取消等情况不得绕过，"+
			"说明原因后再跳过。]\n%s",
		t.toolName(ctx),
		detail,
	), nil
}

// truncateToolErrorTail 保留错误文本末尾：开头往往是命令回显或日志，真正的失败原因在最后。
func truncateToolErrorTail(value string, max int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) <= max {
		return string(runes)
	}
	marker := fmt.Sprintf("…（前 %d 字已省略）\n", len(runes)-max)
	return marker + string(runes[len(runes)-max:])
}

func (t *tolerantTool) toolName(ctx context.Context) string {
	if info, err := t.inner.Info(ctx); err == nil && info != nil && strings.TrimSpace(info.Name) != "" {
		return info.Name
	}
	return "unknown"
}

// wrapTolerantTools 包装可调用工具，使执行失败回传模型而不是中断整轮对话。
func wrapTolerantTools(items []tool.BaseTool) []tool.BaseTool {
	wrapped := make([]tool.BaseTool, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		if _, ok := item.(tool.InvokableTool); !ok {
			wrapped = append(wrapped, item)
			continue
		}
		if _, ok := item.(*tolerantTool); ok {
			wrapped = append(wrapped, item)
			continue
		}
		wrapped = append(wrapped, &tolerantTool{inner: item})
	}
	return wrapped
}
