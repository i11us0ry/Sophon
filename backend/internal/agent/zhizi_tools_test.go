package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
	zhizipkg "sophon/internal/zhizi"

	"github.com/cloudwego/eino/components/tool"
)

func TestZhiziToolWritesPersistentExecutionRecord(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	result, err := service.runAuditedZhiziTool(
		ctx,
		zhiziExecToolName,
		map[string]interface{}{"command": "printf ok"},
		func() (string, error) {
			return `{"stdout":"ok","exitCode":0}`, nil
		},
	)
	if err != nil || result == "" {
		t.Fatalf("智子工具审计包装执行失败: %q %v", result, err)
	}
	var status, storedResult string
	if err := service.db.QueryRowContext(
		context.Background(),
		`SELECT status, result FROM tool_executions
		 WHERE tool_name = ? ORDER BY started_at DESC, rowid DESC LIMIT 1`,
		zhiziExecToolName,
	).Scan(&status, &storedResult); err != nil {
		t.Fatalf("未找到智子工具执行记录: %v", err)
	}
	if status != "completed" || storedResult != result {
		t.Fatalf("智子工具执行记录错误: status=%s result=%q", status, storedResult)
	}
}

func TestCompletedMissionDoesNotBlockZhiziTools(t *testing.T) {
	service := &Service{}
	ctx := withMissionExecution(context.Background(), missionExecution{
		Plan:      missionPlan{Mode: missionModeAgent},
		Phase:     missionPhaseGeneral,
		AgentMode: agentModeFast,
	})
	ctx = withMissionObjectiveState(ctx)
	markMissionObjectiveComplete(ctx, "finding-1", "目标已完成")
	allowed, reason := service.missionToolDecision(ctx, zhiziExecToolName, map[string]interface{}{
		"command": "printf should-not-run",
	})
	if !allowed {
		t.Fatalf("目标完成状态不应剥夺主 Agent 的智子工具选择: %s", reason)
	}
}

func TestZhiziExecUsesRemotePathPolicy(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan:      missionPlan{Mode: missionModeCodeAudit},
		Phase:     missionPhaseSourceAudit,
		AgentMode: agentModeFast,
	})
	command := `cd /home/sophon/sophon/kkg; echo "=== api paths ==="; grep -oE '"/api/v[0-9][^"]{2,80}"' app.js | head -120`
	allowed, reason := service.missionToolDecision(ctx, zhiziExecToolName, map[string]interface{}{
		"command": command,
	})
	if !allowed {
		t.Fatalf("智子远端绝对路径不应按容器本地路径校验: %s", reason)
	}
}

func TestZhiziExecutionPriorityGuidance(t *testing.T) {
	guidance := zhiziExecutionPriorityGuidance("node-a")
	for _, expected := range []string{
		"智子分身执行优先级（强约束）",
		"必须首先选择 zhizi_exec、zhizi_python",
		"本地 exec、execute-python-script",
		"其余 sophon-tool-runner 工具已被禁用",
		"不得回退到本地 shell",
	} {
		if !strings.Contains(guidance, expected) {
			t.Fatalf("智子优先提示缺少 %q: %s", expected, guidance)
		}
	}
}

func TestDeepPentestHidesDirectZhiziToolsFromMainAgent(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	node, err := service.db.CreateZhiziNode(ctx, database.ZhiziNode{
		CreatedByUserID:    "user-1",
		Name:               "deep-test",
		Host:               "127.0.0.1",
		Port:               22,
		Username:           "root",
		AuthType:           "key",
		HostKeyFingerprint: "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
		WorkRoot:           "/tmp/sophon",
		MaxSlots:           1,
		Enabled:            true,
	}, database.ZhiziNodeSecret{PrivateKey: "unused"})
	if err != nil {
		t.Fatalf("创建测试节点失败: %v", err)
	}
	if err := service.db.RecordZhiziNodeTest(ctx, node.ID, nil); err != nil {
		t.Fatalf("记录节点测试成功失败: %v", err)
	}
	if err := service.db.SetZhiziConversationEnabled(ctx, "conv-tools", "user-1", true); err != nil {
		t.Fatalf("启用智子失败: %v", err)
	}
	if _, err := service.db.AcquireZhiziLease(ctx, "conv-tools", "user-1", time.Minute); err != nil {
		t.Fatalf("获取智子租约失败: %v", err)
	}
	deepCtx := withMissionExecution(ctx, missionExecution{
		Plan:      missionPlan{Mode: missionModePentest, ProjectScope: true},
		Phase:     missionPhasePentest,
		AgentMode: agentModeDeep,
	})
	names := missionToolNames(t, service.activeToolsForMission(
		deepCtx,
		agentModeDeep,
		missionPlan{Mode: missionModePentest, ProjectScope: true},
		missionPhasePentest,
	))
	if names[zhiziExecToolName] || names[zhiziPythonToolName] {
		t.Fatalf("Deep Path 主 Agent 不应直接获得智子执行工具: %v", names)
	}
	_ = service.db.ReleaseZhiziLeaseByConversation(ctx, "conv-tools")
	_ = node
}

func TestZhiziToolsRequireActiveLeaseForMainAndSubAgents(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	service.zhizi = zhizipkg.NewExecutor(service.db)
	localTool := &jsonTool{name: "exec", desc: "本地命令"}
	service.tools = append(newZhiziTools(service), localTool)
	service.baseTools = service.tools
	subCtx := execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID: "sub-agent", Kind: "worker", Mode: subagentModeReadWrite, Depth: 1,
	})
	hasTool := func(items []tool.BaseTool, name string) bool {
		for _, item := range items {
			info, err := item.Info(ctx)
			if err == nil && info != nil && info.Name == name {
				return true
			}
		}
		return false
	}
	assertNoZhizi := func(label string, items []tool.BaseTool) {
		t.Helper()
		for _, name := range []string{
			zhiziExecToolName,
			zhiziPythonToolName,
			zhiziUploadToolName,
			zhiziDownloadToolName,
			zhiziStatusToolName,
		} {
			if hasTool(items, name) {
				t.Fatalf("%s不应暴露 %s: %v", label, name, toolNamesForTest(items, ctx))
			}
		}
		if !hasTool(items, "exec") {
			t.Fatalf("%s仍应保留普通本地工具", label)
		}
	}

	assertNoZhizi("未启用智子的主 Agent ", service.activeTools(ctx))
	assertNoZhizi("未启用智子的子 Agent ", service.subAgentActiveTools(subCtx))
	if _, _, err := zhiziExecutionContext(subCtx, service); err == nil {
		t.Fatalf("无活跃租约时运行时应拒绝智子工具")
	}

	node, err := service.db.CreateZhiziNode(ctx, database.ZhiziNode{
		CreatedByUserID:    "user-1",
		Name:               "lease-test",
		Host:               "127.0.0.1",
		Port:               22,
		Username:           "root",
		AuthType:           "key",
		HostKeyFingerprint: "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
		WorkRoot:           "/tmp/sophon",
		MaxSlots:           1,
		Enabled:            true,
	}, database.ZhiziNodeSecret{PrivateKey: "unused"})
	if err != nil {
		t.Fatalf("创建节点失败: %v", err)
	}
	if err := service.db.RecordZhiziNodeTest(ctx, node.ID, nil); err != nil {
		t.Fatalf("记录节点测试成功失败: %v", err)
	}
	if err := service.db.SetZhiziConversationEnabled(ctx, "conv-tools", "user-1", true); err != nil {
		t.Fatalf("启用智子失败: %v", err)
	}
	lease, err := service.db.AcquireZhiziLease(ctx, "conv-tools", "user-1", time.Minute)
	if err != nil {
		t.Fatalf("获取租约失败: %v", err)
	}
	t.Cleanup(func() { _ = service.db.ReleaseZhiziLease(context.Background(), lease.ID) })

	if !hasTool(service.activeTools(ctx), zhiziStatusToolName) {
		t.Fatalf("活跃租约下主 Agent 应恢复智子工具")
	}
	if !hasTool(service.subAgentActiveTools(subCtx), zhiziStatusToolName) {
		t.Fatalf("活跃租约下子 Agent 应恢复智子工具")
	}
	if hasTool(service.activeTools(ctx), "exec") {
		t.Fatalf("活跃智子租约下不应继续暴露本地 exec")
	}
	if hasTool(service.subAgentActiveTools(subCtx), "exec") {
		t.Fatalf("活跃智子租约下子 Agent 不应继续暴露本地 exec")
	}
	if _, _, err := zhiziExecutionContext(subCtx, service); err != nil {
		t.Fatalf("活跃租约下运行时校验失败: %v", err)
	}
}

func TestZhiziQualifiedToolAliasesAreRecognized(t *testing.T) {
	for _, name := range []string{
		"zhizi_exec",
		"sophon-zhizi__zhizi_exec",
		"SOPHON-ZHIZI__ZHIZI_PYTHON",
	} {
		if !isZhiziToolName(name) {
			t.Fatalf("智子工具别名未识别: %s", name)
		}
	}
	if isZhiziToolName("sophon-tool-runner__exec") {
		t.Fatalf("本地 exec 不应被识别为智子工具")
	}
}

func TestZhiziEnabledWithoutLeaseBlocksLocalFallback(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if err := service.db.SetZhiziConversationEnabled(ctx, "conv-tools", "user-1", true); err != nil {
		t.Fatalf("启用智子失败: %v", err)
	}
	blocked, reason := service.localExecutionBlockedByZhizi(ctx)
	if !blocked || !strings.Contains(reason, "租约不可用") {
		t.Fatalf("租约不可用时应阻止本地回退: blocked=%t reason=%q", blocked, reason)
	}
	service.tools = []tool.BaseTool{&jsonTool{name: "exec", desc: "本地命令"}}
	if names := toolNamesForTest(service.activeTools(ctx), ctx); len(names) != 0 {
		t.Fatalf("租约不可用时不应暴露本地执行工具: %v", names)
	}
}

func TestZhiziRuntimeStateAvoidsPerToolDatabaseLookup(t *testing.T) {
	service := &Service{}
	ctx := execctx.WithZhiziRuntimeState(context.Background(), execctx.ZhiziRuntimeState{
		Enabled: true,
		Active:  true,
	})
	blocked, reason := service.localExecutionBlockedByZhizi(ctx)
	if !blocked || !strings.Contains(reason, "必须使用 zhizi_*") {
		t.Fatalf("运行时智子状态未生效: blocked=%t reason=%q", blocked, reason)
	}
}

func toolNamesForTest(items []tool.BaseTool, ctx context.Context) []string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		info, err := item.Info(ctx)
		if err == nil && info != nil {
			names = append(names, info.Name)
		}
	}
	return names
}
