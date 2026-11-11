package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudwego/eino/components/tool"

	"sophon/internal/config"
	"sophon/internal/execctx"
)

func subagentContext(mode string) context.Context {
	return execctx.WithSubagent(context.Background(), execctx.SubagentInfo{
		ID:    "sub-test",
		Mode:  mode,
		Depth: 1,
	})
}

func TestSubagentToolDecisionEnforcesModes(t *testing.T) {
	service := &Service{registry: newToolRegistry()}
	cases := []struct {
		name string
		mode string
		tool string
		args map[string]interface{}
		want bool
	}{
		{
			name: "只读允许本地查询",
			mode: subagentModeReadOnly,
			tool: "exec",
			args: map[string]interface{}{"command": "ls -la"},
			want: true,
		},
		{
			name: "只读拒绝主动测试",
			mode: subagentModeReadOnly,
			tool: "exec",
			args: map[string]interface{}{"command": "sqlmap -u http://example.com/?id=1"},
			want: false,
		},
		{
			name: "只读拒绝项目写回",
			mode: subagentModeReadOnly,
			tool: "project_upsert_fact",
			args: map[string]interface{}{},
			want: false,
		},
		{
			name: "只读拒绝发现层写工具",
			mode: subagentModeReadOnly,
			tool: "sophon-agent__project_add_hint",
			args: map[string]interface{}{},
			want: false,
		},
		{
			name: "只读拒绝记录关联",
			mode: subagentModeReadOnly,
			tool: "sophon-agent__project_record_link",
			args: map[string]interface{}{},
			want: false,
		},
		{
			name: "可写允许发现层写工具",
			mode: subagentModeReadWrite,
			tool: "sophon-agent__project_set_group_priority",
			args: map[string]interface{}{},
			want: true,
		},
		{
			name: "可写允许本地写文件",
			mode: subagentModeReadWrite,
			tool: "exec",
			args: map[string]interface{}{"command": "cp a.txt b.txt"},
			want: true,
		},
		{
			name: "可写拒绝主动测试",
			mode: subagentModeReadWrite,
			tool: "exec",
			args: map[string]interface{}{"command": "sqlmap -u http://example.com/?id=1"},
			want: false,
		},
		{
			name: "可写允许写回漏洞",
			mode: subagentModeReadWrite,
			tool: "project_report_finding",
			args: map[string]interface{}{},
			want: true,
		},
		{
			name: "主动测试允许扫描",
			mode: subagentModeExecute,
			tool: "exec",
			args: map[string]interface{}{"command": "sqlmap -u http://example.com/?id=1"},
			want: true,
		},
		{
			name: "主动测试不重复判断删除",
			mode: subagentModeExecute,
			tool: "exec",
			args: map[string]interface{}{"command": "rm -rf /tmp/sophon-delete-test"},
			want: true,
		},
		{
			name: "主动测试不误判 dump-header",
			mode: subagentModeExecute,
			tool: "exec",
			args: map[string]interface{}{"command": "curl -s -m 20 -k -D - https://example.com/"},
			want: true,
		},
		{
			name: "主动测试不误判 shell 循环",
			mode: subagentModeExecute,
			tool: "exec",
			args: map[string]interface{}{"command": "for p in /a /b; do curl -s https://example.com$p; done"},
			want: true,
		},
		{
			name: "完整模式继承父权限",
			mode: subagentModeAll,
			tool: "exec",
			args: map[string]interface{}{"command": "rm -rf /tmp/sophon-delete-test"},
			want: true,
		},
		{
			name: "未知模式失败关闭",
			mode: "unknown-mode",
			tool: "exec",
			args: map[string]interface{}{"command": "ls -la"},
			want: false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			allowed, reason := service.subagentToolDecision(
				subagentContext(testCase.mode),
				testCase.tool,
				testCase.args,
			)
			if allowed != testCase.want {
				t.Fatalf(
					"模式 %s 调用 %s 期望 allowed=%t，实际 %t（%s）",
					testCase.mode,
					testCase.tool,
					testCase.want,
					allowed,
					reason,
				)
			}
		})
	}
}

func TestSubagentToolDecisionWithoutSubagentContext(t *testing.T) {
	service := &Service{registry: newToolRegistry()}
	allowed, reason := service.subagentToolDecision(
		context.Background(),
		"exec",
		map[string]interface{}{"command": "rm -rf /"},
	)
	if !allowed || reason != "" {
		t.Fatalf("主 Agent 上下文不应被能力模式拦截: %t %s", allowed, reason)
	}
}

func TestGatedSubagentToolRejectsWithoutStoppingRun(t *testing.T) {
	service := &Service{registry: newToolRegistry()}
	inner := newFakeMCPTool("sophon-tool-runner", "sqlmap", "SQL 注入检测", "url")
	gated := service.gateSubagentTools(
		subagentContext(subagentModeReadOnly),
		[]tool.BaseTool{inner},
	)
	if len(gated) != 1 {
		t.Fatalf("门禁包装数量错误: %d", len(gated))
	}
	result, err := gated[0].(tool.InvokableTool).InvokableRun(
		subagentContext(subagentModeReadOnly),
		`{"url":"http://example.com"}`,
	)
	if err != nil {
		t.Fatalf("被能力模式拒绝时应回传结果而不是中断整轮: %v", err)
	}
	if !strings.Contains(result, "能力模式拒绝执行") {
		t.Fatalf("未说明拒绝原因: %s", result)
	}
	if len(inner.calls) != 0 {
		t.Fatalf("被拒绝的工具不应执行: %#v", inner.calls)
	}
}

func TestSubagentWorkspaceIsolation(t *testing.T) {
	root := t.TempDir()
	service := &Service{
		cfg: config.Config{
			Storage: config.StorageConfig{
				ArtifactRoot: root,
				Categories: map[string]config.StorageCategoryConfig{
					"workspace": {Enabled: true, Path: "tmp/workspace"},
				},
			},
		},
	}
	args := map[string]interface{}{}
	ctx := subagentContext(subagentModeReadOnly)
	if err := service.injectToolRunnerWorkspace(
		ctx,
		"sophon-tool-runner",
		"conversation-1",
		args,
	); err != nil {
		t.Fatalf("注入子 Agent 工作区失败: %v", err)
	}
	want := filepath.Join(root, "tmp", "workspace", "conversation-1", "subagents", "sub-test")
	wantConversation := filepath.Join(root, "tmp", "workspace", "conversation-1")
	if args[toolRunnerWorkspaceArg] != want {
		t.Fatalf("子 Agent 工作区错误: %#v", args[toolRunnerWorkspaceArg])
	}
	if args[toolRunnerConversationArg] != wantConversation {
		t.Fatalf("子 Agent 会话共享工作区错误: %#v", args[toolRunnerConversationArg])
	}
	if info, err := os.Stat(want); err != nil || !info.IsDir() {
		t.Fatalf("子 Agent 工作区未创建: %v", err)
	}

	mainArgs := map[string]interface{}{}
	if err := service.injectToolRunnerWorkspace(
		context.Background(),
		"sophon-tool-runner",
		"conversation-1",
		mainArgs,
	); err != nil {
		t.Fatalf("注入主 Agent 工作区失败: %v", err)
	}
	if mainArgs[toolRunnerWorkspaceArg] == want {
		t.Fatalf("主 Agent 不应写入子 Agent 工作区: %#v", mainArgs)
	}
	if mainArgs[toolRunnerWorkspaceArg] != wantConversation ||
		mainArgs[toolRunnerConversationArg] != wantConversation {
		t.Fatalf("主 Agent 工作区与共享工作区应一致: %#v", mainArgs)
	}
}

func TestApplySubagentMCPScope(t *testing.T) {
	service := &Service{registry: newToolRegistry()}
	scan := newFakeMCPTool("tool-runner", "sqlmap", "SQL 注入检测", "url")
	service.registry.add("tool-runner", scan, scan.info)
	builtin := &jsonTool{name: "project_list_facts", desc: "列出事实"}
	items := []tool.BaseTool{scan, builtin}

	noneCtx := execctx.WithSubagent(context.Background(), execctx.SubagentInfo{
		ID: "sub-1", Mode: subagentModeAll, MCPScope: []string{"none"},
	})
	filtered := service.applySubagentMCPScope(noneCtx, items)
	// none 策略只裁掉 MCP 服务工具，平台内置工具仍应可用。
	if len(filtered) != 1 {
		t.Fatalf("none 策略应只保留内置工具: %d", len(filtered))
	}
	if info, _ := filtered[0].Info(context.Background()); info.Name != "project_list_facts" {
		t.Fatalf("none 策略保留了错误的工具: %#v", info)
	}

	namedCtx := execctx.WithSubagent(context.Background(), execctx.SubagentInfo{
		ID: "sub-2", Mode: subagentModeAll, MCPScope: []string{"tool-runner__sqlmap"},
	})
	if filtered := service.applySubagentMCPScope(namedCtx, items); len(filtered) != 2 {
		t.Fatalf("按限定名继承应保留两个工具: %d", len(filtered))
	}

	allCtx := execctx.WithSubagent(context.Background(), execctx.SubagentInfo{
		ID: "sub-3", Mode: subagentModeAll,
	})
	if filtered := service.applySubagentMCPScope(allCtx, items); len(filtered) != 2 {
		t.Fatalf("默认应继承全部工具: %d", len(filtered))
	}
}
