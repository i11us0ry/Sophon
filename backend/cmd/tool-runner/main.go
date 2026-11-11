// sophon-tool-runner 把 CS AI tools/ 目录下的 YAML 工具定义暴露为 MCP 工具。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"sophon/internal/toolrunner"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	defaultDir := strings.TrimSpace(os.Getenv("SOPHON_TOOLS_DIR"))
	if defaultDir == "" {
		defaultDir = "/opt/sophon/tools"
	}
	toolsDir := flag.String("tools-dir", defaultDir, "工具定义目录")
	timeout := flag.Duration("timeout", 900*time.Second, "单个工具执行超时上限（工具定义可用 timeout_seconds 收紧）")
	flag.Parse()

	tools, err := toolrunner.LoadDir(*toolsDir)
	if err != nil {
		log.Fatalf("加载工具定义失败: %v", err)
	}
	executor := &toolrunner.Executor{
		Timeout:       *timeout,
		WorkspaceRoot: strings.TrimSpace(os.Getenv("SOPHON_WORKSPACE_ROOT")),
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "sophon-tool-runner",
		Version: "0.1.0",
	}, nil)

	registered := 0
	for _, item := range tools {
		if !item.Enabled {
			continue
		}
		item := item
		server.AddTool(&mcp.Tool{
			Name:        item.Name,
			Description: item.Summary(),
			InputSchema: item.InputSchema(),
		}, func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := map[string]any{}
			if request != nil && request.Params != nil && request.Params.Arguments != nil {
				raw, err := json.Marshal(request.Params.Arguments)
				if err != nil {
					return nil, err
				}
				if err := json.Unmarshal(raw, &args); err != nil {
					return nil, err
				}
			}
			result, runErr := executor.Run(ctx, item, args)
			text := renderResult(result, runErr)
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: text}},
				IsError: runErr != nil,
			}, nil
		})
		registered++
	}
	log.Printf(
		"sophon-tool-runner: 已注册 %d/%d 个工具（目录 %s）",
		registered,
		len(tools),
		*toolsDir,
	)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("MCP 服务运行失败: %v", err)
	}
}

func renderResult(result *toolrunner.Result, runErr error) string {
	var builder strings.Builder
	if result != nil && result.Command != "" {
		// 命令可能内嵌整段脚本（http-framework-test 约 16KB），限长避免淹没真正的输出与错误。
		builder.WriteString("$ " + truncateCommand(result.Command, 500) + "\n")
	}
	if runErr != nil {
		builder.WriteString("错误: " + runErr.Error() + "\n")
	}
	if result != nil && strings.TrimSpace(result.Output) != "" {
		builder.WriteString(result.Output)
		if !strings.HasSuffix(result.Output, "\n") {
			builder.WriteString("\n")
		}
	}
	if result != nil && result.CPUSeconds > 0 {
		if token := strings.TrimSpace(result.BudgetToken); token != "" {
			builder.WriteString(fmt.Sprintf(
				"[sophon budget:%s] cpu_seconds=%.6f\n",
				token,
				result.CPUSeconds,
			))
		}
	}
	if hint := runtimeCommandHint(result); hint != "" {
		builder.WriteString(hint + "\n")
	}
	if builder.Len() == 0 {
		return "(无输出)"
	}
	return builder.String()
}

var missingRuntimeCommandPattern = regexp.MustCompile(`(?mi)(?:^|[:\s])(file|time): (?:command )?not found`)

func runtimeCommandHint(result *toolrunner.Result) string {
	if result == nil {
		return ""
	}
	match := missingRuntimeCommandPattern.FindStringSubmatch(result.Output)
	if len(match) < 2 {
		return ""
	}
	switch strings.ToLower(match[1]) {
	case "file":
		return "环境提示：file 不可用；可用 stat、od 或 Python 标准库判断文件类型。"
	case "time":
		return "环境提示：外部 time 不可用；可用 date +%s%N 或 Python time.perf_counter() 计时。"
	default:
		return ""
	}
}

// truncateCommand 限制命令回显长度，超长部分用省略标记替代。
func truncateCommand(command string, max int) string {
	runes := []rune(command)
	if len(runes) <= max {
		return command
	}
	return string(runes[:max]) + fmt.Sprintf("…（命令回显已省略 %d 字）", len(runes)-max)
}
