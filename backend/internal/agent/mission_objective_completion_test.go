package agent

import (
	"context"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestMissionObjectiveCompletionStopsFollowUpsAndSubagents(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	plan := missionPlan{
		Mode:               missionModePentest,
		PentestTargets:     []string{"10.8.0.61"},
		Objective:          "利用指定漏洞获取服务器权限",
		CompletionCriteria: "取得命令回显或等价 shell 控制证据",
	}
	ctx = withMissionObjectiveState(ctx)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan:  plan,
		Phase: missionPhasePentest,
		Scope: missionScope{
			Hosts:    []string{"10.8.0.61"},
			AssetIDs: []string{"asset-server-control"},
			Active:   true,
		},
		AgentMode: agentModeFast,
	})
	finding := &database.Vulnerability{
		ID:                "finding-server-control",
		ProjectID:         "project-tools",
		AssetID:           "asset-server-control",
		OwnerUserID:       "user-1",
		Title:             "K3Cloud-/kdagent.aspx-命令注入-获取服务器权限",
		Status:            "confirmed",
		VulnerabilityType: "命令注入",
		Evidence:          "GET /kdagent.aspx?c=whoami 返回命令输出 iis apppool\\k3cloud",
		Impact:            "匿名攻击者可直接获取服务器控制权",
		VerificationState: "exploitable",
		Confidence:        97,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	service.markMissionObjectiveCompleteFromFinding(ctx, finding)

	completed, findingID, _ := missionObjectiveCompletion(ctx)
	if !completed || findingID != finding.ID {
		t.Fatalf("服务器控制目标应标记完成: completed=%v finding=%s", completed, findingID)
	}
	if !missionSuppressesAutomaticFollowUps(ctx) {
		t.Fatal("目标完成后必须停止自动派生后续漏洞意图")
	}
	if allowed, _ := service.missionToolDecision(ctx, "pent_agent_execute", map[string]interface{}{
		"task": "继续测试其他入口",
	}); allowed {
		t.Fatal("目标完成后不应允许启动新的子 Agent")
	}
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Minute),
		&runCapture{},
		"已获取服务器权限。",
	)
	if !decision.Allowed || !decision.ObjectiveCompleted {
		t.Fatalf("目标完成后最终化应直接通过: %+v", decision)
	}

	before, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	if err := service.spawnFindingFollowUpIntents(ctx, "project-tools", finding); err != nil {
		t.Fatalf("目标完成后派生检查失败: %v", err)
	}
	after, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("目标完成后不应新增后续意图: before=%d after=%d", len(before), len(after))
	}
}

func TestMissionObjectiveCompletionRequiresExploitEvidence(t *testing.T) {
	execution := missionExecution{
		Plan: missionPlan{
			Mode:               missionModePentest,
			Objective:          "获取服务器权限",
			CompletionCriteria: "取得命令回显",
		},
	}
	incomplete := &database.Vulnerability{
		ID:                "finding-no-evidence",
		Status:            "confirmed",
		Title:             "命令注入-获取服务器权限",
		VulnerabilityType: "命令注入",
		VerificationState: "exploitable",
		Confidence:        95,
	}
	if missionFindingCompletesObjective(execution, incomplete) {
		t.Fatal("没有执行证据时不得判定目标完成")
	}
	incomplete.Evidence = "whoami 命令回显 iis apppool\\k3cloud"
	if !missionFindingCompletesObjective(execution, incomplete) {
		t.Fatal("确认可利用且有命令回显时应判定目标完成")
	}
}

func TestMissionObjectiveCompletedSubagentDecisionUsesParentContext(t *testing.T) {
	service := &Service{}
	ctx := context.Background()
	ctx = withMissionObjectiveState(ctx)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan:  missionPlan{Mode: missionModePentest},
		Phase: missionPhasePentest,
	})
	markMissionObjectiveComplete(ctx, "finding-1", "已完成")
	if allowed, reason := service.missionToolDecision(ctx, "pent_agent_execute_hypothesis", nil); allowed ||
		reason == "" {
		t.Fatalf("完成后子 Agent 工具必须被明确拒绝: allowed=%v reason=%q", allowed, reason)
	}
}
