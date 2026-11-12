package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

func TestProjectGetRetestContextTool(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:                "vuln-retest-context",
		ProjectID:         "project-tools",
		OwnerUserID:       "user-1",
		Title:             "SRM 任意文件上传",
		Severity:          "critical",
		Status:            "confirmed",
		VulnerabilityType: "文件上传",
		Target:            "src/WebSite/App_Data/Common.config",
		HTTPMethod:        "POST",
		Parameter:         "file1",
		Preconditions:     "无需登录",
		ReproductionSteps: "POST /SRM/ScpSupRegHandler",
		Description:       "原始漏洞概述",
		Evidence:          "HTTP 200，附件保存成功",
		Impact:            "写入服务器文件",
		CreatedAt:         now,
		UpdatedAt:         now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	if err := service.db.CreateConversation(ctx, database.Conversation{
		ID:          "retest-source-conversation",
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Title:       "原验证会话",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建来源会话失败: %v", err)
	}
	if err := service.db.AddMessage(ctx, database.Message{
		ID:             "retest-source-message",
		ConversationID: "retest-source-conversation",
		Role:           "user",
		Content:        "授权目标 http://10.8.0.61 和 http://10.8.0.61:8000",
		CreatedAt:      now,
	}); err != nil {
		t.Fatalf("写下来源消息失败: %v", err)
	}
	run, err := service.db.CreateVulnerabilityRetestRun(
		ctx,
		"vuln-retest-context",
		"user-1",
		execctx.ConversationID(ctx),
		[]string{"retest-source-conversation"},
	)
	if err != nil {
		t.Fatalf("创建复测任务失败: %v", err)
	}

	output, err := invokeProjectTool(t, service, ctx, "project_get_retest_context", map[string]interface{}{
		"retest_id": run.ID,
	})
	if err != nil {
		t.Fatalf("读取复测上下文失败: %v", err)
	}
	for _, expected := range []string{
		run.ID,
		"vuln-retest-context",
		"SRM 任意文件上传",
		"HTTP 200，附件保存成功",
		"http://10.8.0.61",
		"retest-source-conversation",
		"project_retest_finding",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("复测上下文缺少 %q: %s", expected, output)
		}
	}
}

func TestProjectGetRetestContextRejectsCrossUserAndProject(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()

	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-retest-cross-user",
		ProjectID:   "project-tools",
		OwnerUserID: "user-2",
		Title:       "其他用户漏洞",
		Status:      "open",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建跨用户漏洞失败: %v", err)
	}
	crossUserRun, err := service.db.CreateVulnerabilityRetestRun(
		ctx,
		"vuln-retest-cross-user",
		"user-2",
		execctx.ConversationID(ctx),
		nil,
	)
	if err != nil {
		t.Fatalf("创建跨用户任务失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_get_retest_context", map[string]interface{}{
		"retest_id": crossUserRun.ID,
	}); err == nil || !strings.Contains(err.Error(), "不存在或无权访问") {
		t.Fatalf("跨用户复测任务必须被拒绝: %v", err)
	}

	if err := service.db.CreateProject(ctx, database.Project{
		ID:          "project-other",
		OwnerUserID: "user-1",
		Name:        "其他项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建其他项目失败: %v", err)
	}
	if err := service.db.CreateConversation(ctx, database.Conversation{
		ID:          "conversation-other",
		OwnerUserID: "user-1",
		ProjectID:   "project-other",
		Title:       "其他项目会话",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建其他项目会话失败: %v", err)
	}
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-retest-cross-project",
		ProjectID:   "project-other",
		OwnerUserID: "user-1",
		Title:       "其他项目漏洞",
		Status:      "open",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建跨项目漏洞失败: %v", err)
	}
	crossProjectRun, err := service.db.CreateVulnerabilityRetestRun(
		ctx,
		"vuln-retest-cross-project",
		"user-1",
		"conversation-other",
		nil,
	)
	if err != nil {
		t.Fatalf("创建跨项目任务失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_get_retest_context", map[string]interface{}{
		"retest_id": crossProjectRun.ID,
	}); err == nil || !strings.Contains(err.Error(), "不属于当前会话") {
		t.Fatalf("跨项目复测任务必须被拒绝: %v", err)
	}
}

func TestRetestButtonMissionPlanSkipsIntentRouter(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-button-retest",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "按钮复测",
		Severity:    "high",
		Status:      "open",
		Target:      "src/WebSite/App_Data/Common.config",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	run, err := service.db.CreateVulnerabilityRetestRun(
		ctx,
		"vuln-button-retest",
		"user-1",
		execctx.ConversationID(ctx),
		nil,
	)
	if err != nil {
		t.Fatalf("创建复测任务失败: %v", err)
	}
	if err := service.db.SetConversationAgentRole(
		ctx,
		"conv-tools",
		"user-1",
		SystemRetestAgentID,
	); err != nil {
		t.Fatalf("绑定复测角色失败: %v", err)
	}
	project, err := service.db.GetProject(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目失败: %v", err)
	}
	project.Scope = "10.8.0.61"
	if err := service.db.UpdateProject(ctx, *project); err != nil {
		t.Fatalf("更新项目目标失败: %v", err)
	}
	conversation, err := service.db.GetConversation(ctx, "conv-tools", "user-1")
	if err != nil {
		t.Fatalf("读取会话失败: %v", err)
	}
	conversation.Kind = "retest"
	router := &fixedRouterModel{content: `{"mode":"clarify","confidence":1,"reason":"不应调用"}`}
	service.model = router

	plan := service.resolveMissionPlan(
		ctx,
		"conv-tools",
		"user-1",
		"assistant-button-retest",
		*project,
		*conversation,
		nil,
		"请复测漏洞 #vuln-button-retest\n复测任务 ID："+run.ID+"\n授权目标：http://10.8.0.61",
		nil,
		RunOptions{},
	)
	if router.routerCalls != 0 {
		t.Fatalf("复测按钮会话不应调用通用意图路由，实际调用 %d 次", router.routerCalls)
	}
	if plan.Mode != missionModeRetest ||
		plan.Source != "retest_button" ||
		len(plan.VulnerabilityIDs) != 1 ||
		plan.VulnerabilityIDs[0] != "vuln-button-retest" ||
		len(plan.RetestIDs) != 1 ||
		plan.RetestIDs[0] != run.ID ||
		!plan.Bounded ||
		len(plan.PentestTargets) != 1 ||
		plan.PentestTargets[0] != "10.8.0.61" {
		t.Fatalf("复测按钮计划错误: %+v", plan)
	}
	if !missionToolAllowed(plan, missionPhaseRetest, "project_get_retest_context") {
		t.Fatal("复测阶段必须允许调用 project_get_retest_context")
	}
}

func TestRetestButtonMissionPlanReportsMissingTarget(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          "vuln-button-no-target",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "无目标复测",
		Status:      "open",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	run, err := service.db.CreateVulnerabilityRetestRun(
		ctx,
		"vuln-button-no-target",
		"user-1",
		execctx.ConversationID(ctx),
		nil,
	)
	if err != nil {
		t.Fatalf("创建复测任务失败: %v", err)
	}
	if err := service.db.SetConversationAgentRole(ctx, "conv-tools", "user-1", SystemRetestAgentID); err != nil {
		t.Fatalf("绑定复测角色失败: %v", err)
	}
	project, err := service.db.GetProject(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目失败: %v", err)
	}
	project.Scope = "10.8.0.61"
	if err := service.db.UpdateProject(ctx, *project); err != nil {
		t.Fatalf("更新项目授权范围失败: %v", err)
	}
	conversation, err := service.db.GetConversation(ctx, "conv-tools", "user-1")
	if err != nil {
		t.Fatalf("读取会话失败: %v", err)
	}
	conversation.Kind = "retest"
	service.model = &fixedRouterModel{content: `{"mode":"general","confidence":1}`}
	plan := service.resolveMissionPlan(
		context.Background(),
		"conv-tools",
		"user-1",
		"assistant-button-no-target",
		*project,
		*conversation,
		nil,
		"请复测漏洞 #vuln-button-no-target\n复测任务 ID："+run.ID,
		nil,
		RunOptions{},
	)
	if plan.Mode != missionModeClarify || plan.Reason != "复测任务未提供授权目标" {
		t.Fatalf("缺少目标时必须返回精确错误: %+v", plan)
	}
}

func TestManualRetestRoleUsesBoundedRetestPlan(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	findingID := "abcdef1234567890abcdef1234567890"
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          findingID,
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "手动复测漏洞",
		Severity:    "high",
		Status:      "open",
		Target:      "http://10.8.0.61/FileService.svc",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	if err := service.db.SetConversationAgentRole(ctx, "conv-tools", "user-1", SystemRetestAgentID); err != nil {
		t.Fatalf("绑定复测角色失败: %v", err)
	}
	project, err := service.db.GetProject(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目失败: %v", err)
	}
	project.Scope = "10.8.0.61"
	if err := service.db.UpdateProject(ctx, *project); err != nil {
		t.Fatalf("更新项目授权范围失败: %v", err)
	}
	conversation, err := service.db.GetConversation(ctx, "conv-tools", "user-1")
	if err != nil {
		t.Fatalf("读取会话失败: %v", err)
	}
	router := &fixedRouterModel{content: `{
		"mode":"retest",
		"tasks":["retest"],
		"vulnerability_ids":["abcdef1234567890abcdef1234567890"],
		"pentest_targets":["10.8.0.61"],
		"confidence":95
	}`}
	service.model = router
	plan := service.resolveMissionPlan(
		ctx,
		"conv-tools",
		"user-1",
		"assistant-manual-retest",
		*project,
		*conversation,
		nil,
		"请复测漏洞 "+findingID+"，授权目标 http://10.8.0.61",
		nil,
		RunOptions{},
	)
	if router.routerCalls != 0 ||
		plan.Mode != missionModeRetest ||
		plan.Source != "retest_role" ||
		!plan.Bounded ||
		len(plan.VulnerabilityIDs) != 1 ||
		plan.VulnerabilityIDs[0] != findingID {
		t.Fatalf("手动选择复测角色时应直接生成有界复测任务: calls=%d plan=%+v", router.routerCalls, plan)
	}
	plan = service.hydrateMissionPlan(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		nil,
		plan,
	)
	if len(plan.RetestIDs) != 1 || plan.Mode != missionModeRetest {
		t.Fatalf("手动复测任务未创建正式 retest run: %+v", plan)
	}
}

func TestManualRetestRoleRequiresValidFindingID(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if err := service.db.SetConversationAgentRole(ctx, "conv-tools", "user-1", SystemRetestAgentID); err != nil {
		t.Fatalf("绑定复测角色失败: %v", err)
	}
	project, err := service.db.GetProject(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目失败: %v", err)
	}
	conversation, err := service.db.GetConversation(ctx, "conv-tools", "user-1")
	if err != nil {
		t.Fatalf("读取会话失败: %v", err)
	}
	router := &fixedRouterModel{content: `{"mode":"pentest","confidence":95}`}
	service.model = router
	plan := service.resolveMissionPlan(
		ctx,
		"conv-tools",
		"user-1",
		"assistant-manual-retest-invalid",
		*project,
		*conversation,
		nil,
		"请复测漏洞 abcdef1234567890abcdef1234567890",
		nil,
		RunOptions{},
	)
	if router.routerCalls != 0 ||
		plan.Mode != missionModeClarify ||
		!strings.Contains(plan.Reason, "有效 finding ID") {
		t.Fatalf("无效 finding ID 必须精确澄清且不得进入通用路由: calls=%d plan=%+v", router.routerCalls, plan)
	}
}

func TestRetestTerminalResultStopsImmediately(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	findingID := "5776b8b1cdb18b57d6a0e36cecddfd90"
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID:          findingID,
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Title:       "FileService 未授权访问复测",
		Severity:    "high",
		Status:      "open",
		Target:      "http://10.8.0.61/FileService.svc",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	run, err := service.db.CreateVulnerabilityRetestRun(
		ctx,
		findingID,
		"user-1",
		execctx.ConversationID(ctx),
		nil,
	)
	if err != nil {
		t.Fatalf("创建复测任务失败: %v", err)
	}
	plan := missionPlan{
		Mode:             missionModeRetest,
		VulnerabilityIDs: []string{findingID},
		RetestIDs:        []string{run.ID},
		Stages:           []string{missionPhaseRetest},
		Bounded:          true,
	}
	ctx = withMissionObjectiveState(ctx)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan:      plan,
		Phase:     missionPhaseRetest,
		AgentMode: agentModeFast,
	})
	if _, err := invokeProjectTool(t, service, ctx, "project_retest_finding", map[string]interface{}{
		"retest_id": run.ID,
		"result":    "insufficient_evidence",
		"notes":     "缺少有效登录 token 和真实 fileId，无法完成认证后越权验证",
	}); err != nil {
		t.Fatalf("insufficient_evidence 应能写回复测记录: %v", err)
	}
	completed, completedFindingID, _ := missionObjectiveCompletion(ctx)
	if !completed || completedFindingID != findingID {
		t.Fatalf("复测终态写回后应标记任务完成: completed=%v finding=%s", completed, completedFindingID)
	}
	event, err := service.db.GetVulnerabilityRetest(ctx, run.ID, "user-1")
	if err != nil || event.Result != "inconclusive" || event.Status != "completed" {
		t.Fatalf("复测结果应规范化为 inconclusive 并完成: %+v err=%v", event, err)
	}
	if allowed, _ := service.missionToolDecision(ctx, "exec", map[string]interface{}{
		"command": "curl http://10.8.0.61/FileService.svc",
	}); allowed {
		t.Fatal("复测终态写回后不应继续执行新的探测")
	}
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Minute),
		&runCapture{},
		"复测结论为 insufficient_evidence。",
	)
	if !decision.Allowed || !decision.ObjectiveCompleted {
		t.Fatalf("复测终态写回后应立即最终化: %+v", decision)
	}
}
