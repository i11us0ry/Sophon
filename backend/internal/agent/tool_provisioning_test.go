package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sophon/internal/database"
)

func TestAgentCanRegisterProbeAndRunOwnTool(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	service.cfg.Storage.ArtifactRoot = t.TempDir()
	tools := newToolProvisioningTools(service)
	register := findSubAgentTool(t, tools, "tool_register")
	probe := findSubAgentTool(t, tools, "tool_probe")
	run := findSubAgentTool(t, tools, "tool_run")

	toolDir := filepath.Join(service.cfg.Storage.ArtifactRoot, "agent-tools")
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatalf("创建工具目录失败: %v", err)
	}
	command := filepath.Join(toolDir, "agent-tool")
	if err := os.WriteFile(command, []byte(`#!/bin/sh
if [ "$1" = "--version" ]; then echo agent-tool-1.0; exit 0; fi
printf 'env=%s args=%s\n' "$AGENT_TOOL_HOME" "$*"
`), 0o755); err != nil {
		t.Fatalf("写入测试工具失败: %v", err)
	}
	registerArgs, _ := json.Marshal(map[string]any{
		"name":         "agent-tool",
		"command":      command,
		"env":          map[string]string{"AGENT_TOOL_HOME": toolDir},
		"version":      "1.0",
		"source":       "test-download",
		"scope":        "project",
		"health_check": []string{"--version"},
	})
	output, err := register.InvokableRun(ctx, string(registerArgs))
	if err != nil {
		t.Fatalf("注册 Agent 工具失败: %v", err)
	}
	if !strings.Contains(output, `"status": "verified"`) {
		t.Fatalf("工具健康检查未通过: %s", output)
	}

	probeArgs, _ := json.Marshal(map[string]any{"name": "agent-tool"})
	probeOutput, err := probe.InvokableRun(ctx, string(probeArgs))
	if err != nil || !strings.Contains(probeOutput, `"found": true`) {
		t.Fatalf("工具探测失败: output=%s err=%v", probeOutput, err)
	}

	runArgs, _ := json.Marshal(map[string]any{
		"name": "agent-tool",
		"args": []string{"hello"},
	})
	runOutput, err := run.InvokableRun(ctx, string(runArgs))
	if err != nil {
		t.Fatalf("运行注册工具失败: %v", err)
	}
	if !strings.Contains(runOutput, "env="+toolDir) || !strings.Contains(runOutput, "args=hello") {
		t.Fatalf("注册工具参数或环境未生效: %s", runOutput)
	}
	if err := service.db.CreateInterceptRule(ctx, database.InterceptRule{
		ID:          "deny-registered-tool-test",
		Name:        "deny registered tool test",
		Enabled:     true,
		Priority:    999,
		MatchTarget: "tool_input",
		MatchType:   "regex",
		Pattern:     "sophon-tool-policy-test",
		Action:      "deny",
		Message:     "test deny",
	}); err != nil {
		t.Fatalf("创建拦截规则失败: %v", err)
	}
	blockedArgs, _ := json.Marshal(map[string]any{
		"name": "agent-tool",
		"args": []string{"rm", "-rf", "/tmp/sophon-tool-policy-test"},
	})
	if _, err := run.InvokableRun(ctx, string(blockedArgs)); err == nil ||
		!strings.Contains(err.Error(), "拦截设置拒绝") {
		t.Fatalf("注册工具运行应经过现有拦截策略: %v", err)
	}

	registered, err := service.db.ListRegisteredTools(
		context.Background(),
		"user-1",
		"project-tools",
		"conv-tools",
	)
	if err != nil || len(registered) != 1 || registered[0].Name != "agent-tool" {
		t.Fatalf("注册表数据错误: items=%+v err=%v", registered, err)
	}
	paths, err := service.db.ListToolRuntimePaths(
		context.Background(),
		"user-1",
		"project-tools",
		"conv-tools",
	)
	if err != nil || len(paths) == 0 || paths[0].Path != toolDir {
		t.Fatalf("注册工具目录未加入动态 PATH: paths=%+v err=%v", paths, err)
	}
	audits, err := service.db.ListAuditLogs(context.Background(), "user-1", 20)
	if err != nil {
		t.Fatalf("读取工具审计日志失败: %v", err)
	}
	foundRegister := false
	foundRun := false
	for _, audit := range audits {
		if audit.Action == "tool.register" {
			foundRegister = true
		}
		if audit.Action == "tool.run" {
			foundRun = true
		}
	}
	if !foundRegister || !foundRun {
		t.Fatalf("工具注册和运行应写入审计日志: %+v", audits)
	}
}

func TestToolEnvAddPathSupportsSessionScope(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	service.cfg.Storage.ArtifactRoot = t.TempDir()
	addPath := findSubAgentTool(t, newToolProvisioningTools(service), "tool_env_add_path")
	dir := t.TempDir()
	args, _ := json.Marshal(map[string]any{
		"path":  dir,
		"scope": "session",
	})
	if _, err := addPath.InvokableRun(ctx, string(args)); err != nil {
		t.Fatalf("添加会话 PATH 失败: %v", err)
	}
	paths, err := service.db.ListToolRuntimePaths(
		context.Background(),
		"user-1",
		"project-tools",
		"conv-tools",
	)
	if err != nil || len(paths) != 1 || paths[0].Scope != database.ToolScopeSession ||
		paths[0].Path != dir {
		t.Fatalf("会话 PATH 注册错误: paths=%+v err=%v", paths, err)
	}
}
