package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
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

func TestCompletedMissionBlocksZhiziTools(t *testing.T) {
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
	if allowed || reason == "" {
		t.Fatalf("任务完成后必须阻止新的智子工具调用: allowed=%v reason=%q", allowed, reason)
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
		"不得在没有尝试智子工具的情况下直接选择本地 exec",
		"只有智子工具明确失败、租约不可用",
		"使用本地 exec 或 execute-python-script 前",
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
