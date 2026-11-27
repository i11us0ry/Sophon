package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/execctx"
)

func TestRunCaptureCarriesLoadedSkillAcrossSegments(t *testing.T) {
	capture := &runCapture{}
	segment := &runCapture{}
	segment.recordToolCall("skill-call", readSkillToolName)
	segment.recordSkillCall("skill-call", `{"name":"dotnet-code-audit"}`)
	segment.recordSkillResult("skill-call", "技能正文：先建立路由和鉴权映射。")
	segment.recordToolResult("skill-call")
	capture.mergeEvidence(segment)

	loaded := capture.loadedSkillContext()
	if !strings.Contains(loaded, "dotnet-code-audit") ||
		!strings.Contains(loaded, "先建立路由和鉴权映射") {
		t.Fatalf("自动续段时应保留已加载技能正文: %q", loaded)
	}
	if strings.Contains(loaded, "[工具 ") {
		t.Fatalf("失败结果不应作为技能正文保留: %q", loaded)
	}
}

func TestFinalizationOnlyBlocksPendingToolCalls(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID:         "goal-final",
		ProjectID:  "project-tools",
		Kind:       "goal",
		Title:      "验证高危漏洞",
		Status:     "open",
		Confidence: 90,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("创建目标失败: %v", err)
	}

	runStartedAt := time.Now().UTC().Add(-time.Second)
	capture := &runCapture{}
	capture.recordToolCall("call-1", "exec")

	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		capture,
	)
	if decision.Allowed {
		t.Fatalf("工具尚未返回时不应允许最终化")
	}
	reasons := strings.Join(decision.Reasons, "\n")
	if !strings.Contains(reasons, "尚未返回结果") {
		t.Fatalf("最终化原因缺少未返回工具提示：%s", reasons)
	}
	for _, unexpected := range []string{"目标未完成", "项目资产为空", "没有记录任何测试维度"} {
		if strings.Contains(reasons, unexpected) {
			t.Fatalf("普通主 Agent 不应被项目级流程阻塞 %q：%s", unexpected, reasons)
		}
	}

	capture.recordToolResult("call-1")
	decision = service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		capture,
	)
	if !decision.Allowed {
		t.Fatalf("工具返回后普通主 Agent 应立即允许收尾: %+v", decision)
	}
}

func TestFinalizationDoesNotInjectQuestionPause(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	finalText := "如需我继续，可验证下一高价值方向。"
	runStartedAt := time.Now().UTC().Add(-time.Second)

	decision := service.checkFinalization(
		execctx.WithAutoContinue(ctx, true),
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		&runCapture{},
		finalText,
	)
	if !decision.Allowed || decision.PauseOnQuestion || decision.PendingUserConfirmation {
		t.Fatalf("主 Agent 的最终措辞不应触发平台暂停: %+v", decision)
	}

	decision = service.checkFinalization(
		execctx.WithAutoContinue(ctx, false),
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		&runCapture{},
		finalText,
	)
	if !decision.Allowed || decision.PauseOnQuestion || decision.PendingUserConfirmation {
		t.Fatalf("关闭自动继续也不应由最终措辞强制暂停: %+v", decision)
	}
}

func TestFinalizationIgnoresUnrelatedProjectWorkForScopedMission(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.AddMessage(ctx, database.Message{
		ID: "scope-user", ConversationID: "conv-tools", Role: "user",
		Content: "只测试 falcon.example.com 的 user_info 接口", CreatedAt: now,
	}); err != nil {
		t.Fatalf("写入用户消息失败: %v", err)
	}
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-falcon-scope", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "Falcon", Kind: "url", Value: "https://falcon.example.com",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建 Falcon 资产失败: %v", err)
	}
	if _, err := service.db.ExecContext(ctx, `INSERT INTO project_test_results (
		id, project_id, asset_id, dimension, technique, status, required, created_at, updated_at
	) VALUES ('scope-test', 'project-tools', 'asset-falcon-scope', '认证', 'anonymous', 'tested_clean', 1, ?, ?)`,
		now.Unix(), now.Unix(),
	); err != nil {
		t.Fatalf("创建范围内测试结果失败: %v", err)
	}
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID: "unrelated-open-intent", ProjectID: "project-tools", Kind: "intent",
		Title: "测试 unrelated.example.com", Status: "open", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建无关意图失败: %v", err)
	}
	runStartedAt := time.Now().UTC().Add(-time.Second)
	executionID := service.db.StartToolExecution(
		ctx, "conv-tools", "user-1", "exec", map[string]interface{}{"command": "curl https://falcon.example.com/"},
	)
	service.db.FinishToolExecution(ctx, executionID, "200", nil)
	capture := &runCapture{}
	capture.recordToolCall("call-scope", "exec")
	capture.recordToolResult("call-scope")
	decision := service.checkFinalization(
		ctx, "conv-tools", "project-tools", "user-1", runStartedAt, capture,
		"范围内测试已闭环。",
	)
	if !decision.Allowed {
		t.Fatalf("无关项目意图不应阻塞当前 Falcon 任务: %+v", decision)
	}
}

func TestFinalizationRequiresFinalText(t *testing.T) {
	decision := requireFinalText(finalizationDecision{Allowed: true}, "  ")
	if decision.Allowed {
		t.Fatalf("空最终文本不应允许完成: %+v", decision)
	}
	if len(decision.Reasons) != 1 || decision.Reasons[0] != emptyFinalTextReason {
		t.Fatalf("空最终文本原因异常: %+v", decision.Reasons)
	}

	decision = clearFinalTextRequirement(decision)
	if !decision.Allowed || len(decision.Reasons) != 0 {
		t.Fatalf("生成最终文本后应清除空文本阻塞: %+v", decision)
	}

	decision = requireFinalText(finalizationDecision{
		Allowed: false,
		Reasons: []string{"存在未完成目标"},
	}, "")
	decision = clearFinalTextRequirement(decision)
	if decision.Allowed || len(decision.Reasons) != 1 {
		t.Fatalf("清除空文本原因时不能丢失其他阻塞原因: %+v", decision)
	}
}

type emptyThenFinalModel struct {
	calls int
}

func (m *emptyThenFinalModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *emptyThenFinalModel) Generate(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.Message, error) {
	return m.next(), nil
}

func (m *emptyThenFinalModel) Stream(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	return schema.StreamReaderFromArray([]*schema.Message{m.next()}), nil
}

func (m *emptyThenFinalModel) next() *schema.Message {
	m.calls++
	if m.calls == 1 {
		return schema.AssistantMessage("", nil)
	}
	return schema.AssistantMessage("强制总结已生成。", nil)
}

type generalIntentEmptyThenFinalModel struct {
	emptyThenFinalModel
}

func (m *generalIntentEmptyThenFinalModel) WithTools(_ []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func (m *generalIntentEmptyThenFinalModel) Generate(
	_ context.Context,
	messages []*schema.Message,
	_ ...model.Option,
) (*schema.Message, error) {
	for _, message := range messages {
		if message != nil && message.Role == schema.System &&
			strings.Contains(message.Content, "任务意图路由器") {
			return schema.AssistantMessage(`{
				"mode":"general",
				"tasks":["general"],
				"confidence":95,
				"reason":"普通生成任务"
			}`, nil), nil
		}
	}
	return schema.AssistantMessage("", nil), nil
}

func (m *generalIntentEmptyThenFinalModel) Stream(
	_ context.Context,
	_ []*schema.Message,
	_ ...model.Option,
) (*schema.StreamReader[*schema.Message], error) {
	return schema.StreamReaderFromArray([]*schema.Message{m.next()}), nil
}

func TestRunForcesSummaryWhenFinalTextIsEmpty(t *testing.T) {
	service, serviceCtx := openProjectToolService(t, true)
	service.model = &generalIntentEmptyThenFinalModel{}
	service.cfg = config.Config{AgentMaxIterations: 1}
	project, err := service.db.GetProject(serviceCtx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取项目失败: %v", err)
	}
	project.Scope = "example.com"
	project.UpdatedAt = time.Now().UTC()
	if err := service.db.UpdateProject(serviceCtx, *project); err != nil {
		t.Fatalf("更新项目范围失败: %v", err)
	}
	if err := service.db.AddMessage(serviceCtx, database.Message{
		ID:             "msg-final-user",
		ConversationID: "conv-tools",
		Role:           "user",
		Content:        "生成一份普通测试总结",
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("创建用户消息失败: %v", err)
	}

	if err := service.db.AddMessage(serviceCtx, database.Message{
		ID:             "msg-final-summary",
		ConversationID: "conv-tools",
		Role:           "assistant",
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("创建助手消息失败: %v", err)
	}

	result, err := service.Run(
		serviceCtx,
		"conv-tools",
		"user-1",
		"msg-final-summary",
		nil,
	)
	if err != nil {
		t.Fatalf("Run 失败: %v", err)
	}
	if !strings.HasPrefix(result, "强制总结已生成。") ||
		!strings.Contains(result, "已达到 Agent 总迭代预算（1/1），本轮在强制总结后停止。") {
		t.Fatalf("最终文本异常: %q", result)
	}
}

func TestFinalizationPromptsRejectFalseDependencyBlockers(t *testing.T) {
	rule := "不得把输入格式、路径、资源限制或工具实现错误写成“依赖缺失”"
	for name, prompt := range map[string]string{
		"finalization": finalizationSynthesisPrompt,
		"iterations":   iterationBudgetSynthesisPrompt,
		"tokens":       tokenBudgetSynthesisPrompt,
	} {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(prompt, rule) {
				t.Fatalf("%s 缺少工具错误分类约束", name)
			}
		})
	}
}

func TestTaskFinalizationRequiresAuditStateChange(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	runStartedAt := time.Now().UTC().Add(-time.Second)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_audit", map[string]interface{}{
		"action":              "scope",
		"included_categories": []string{"文件上传"},
		"evidence":            "用户要求静态审计源码",
	}); err != nil {
		t.Fatalf("记录审计范围失败: %v", err)
	}
	capture := &runCapture{}
	capture.recordToolCall("call-read-only", "exec")
	capture.recordToolResult("call-read-only")
	execution := missionExecution{
		Plan:  missionPlan{Mode: missionModeGeneral},
		Phase: missionPhaseGeneral,
	}
	decision := checkTaskOnlyFinalization(
		service,
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		&finalizationDecision{Allowed: true},
		capture,
		execution,
	)
	if decision.Allowed ||
		!strings.Contains(strings.Join(decision.Reasons, "\n"), "没有新增项目事实、审计单元、测试结果或漏洞") {
		t.Fatalf("仅读取源码不应通过代码审计最终化: %+v", decision)
	}

	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "asset-final-audit",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "源码包",
		Kind:        "source",
		Value:       "source.zip",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建审计资产失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_audit", map[string]interface{}{
		"action":           "cell",
		"asset_id":         "asset-final-audit",
		"service":          "UploadService",
		"entry":            "processUpload",
		"shape":            "file-write",
		"surface":          "spring-mvc",
		"coverage_status":  "tested",
		"conclusion_state": "NOT_EXPLOITABLE",
		"result":           "物理文件名由 UUID 生成，原始文件名不参与路径",
		"evidence":         "UploadService.java:120",
	}); err != nil {
		t.Fatalf("记录审计结论失败: %v", err)
	}
	decision = checkTaskOnlyFinalization(
		service,
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		&finalizationDecision{Allowed: true},
		capture,
		execution,
	)
	if !decision.Allowed {
		t.Fatalf("写入实质性审计单元后应允许最终化: %+v", decision)
	}
}

func TestFinalizationAllowsOpenOptionalHypotheses(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-optional", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "目标", Kind: "url", Value: "https://optional.example",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ID: "optional-test", ProjectID: "project-tools", AssetID: "asset-optional",
		Dimension: "后续验证", Technique: "optional", Status: "untested",
		ParentID: "finding-parent", Required: false, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建可选假设失败: %v", err)
	}
	executionID := service.db.StartToolExecution(
		ctx,
		"conv-tools",
		"user-1",
		"exec",
		map[string]interface{}{"command": "id"},
	)
	service.db.FinishToolExecution(ctx, executionID, "uid=0", nil)
	runStartedAt := time.Now().UTC().Add(-time.Second)
	capture := &runCapture{}
	capture.recordToolCall("optional-call", "exec")
	capture.recordToolResult("optional-call")
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		capture,
	)
	if !decision.Allowed {
		t.Fatalf("可选假设不应阻止最终化: %+v", decision)
	}
	if decision.TestOpen != 0 {
		t.Fatalf("可选假设不应计为必需未完成测试: %+v", decision)
	}
}

func TestFinalizationDoesNotRequireContinueOnActionableQuestion(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-question", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "未测试接口", Kind: "url", Value: "https://question.example.com",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	executionID := service.db.StartToolExecution(
		ctx,
		"conv-tools",
		"user-1",
		"exec",
		map[string]interface{}{"command": "curl https://question.example.com"},
	)
	service.db.FinishToolExecution(ctx, executionID, "200 OK", nil)

	capture := &runCapture{}
	capture.recordToolCall("question-call", "exec")
	capture.recordToolResult("question-call")
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		capture,
		"已写回事实和测试结果，未新增漏洞。需要我继续别的方向吗？",
	)
	if !decision.Allowed || decision.PendingUserConfirmation {
		t.Fatalf("主 Agent 可选择在交付后结束，不应被强制续跑: %+v", decision)
	}
}

func TestFinalizationIgnoresUnrelatedBlockedIntent(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID:         "intent-blocked-final",
		ProjectID:  "project-tools",
		Kind:       "intent",
		Title:      "被 WAF 阻断的验证方向",
		Status:     "blocked",
		Confidence: 70,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("创建 blocked 意图失败: %v", err)
	}
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		&runCapture{},
	)
	if !decision.Allowed || decision.DerivableBlockedIntents != 0 {
		t.Fatalf("项目中的其他 blocked 意图不应阻塞当前请求: %+v", decision)
	}
}

func TestFinalizationIgnoresCapacityBlockedIntent(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID:         "intent-capacity-final",
		ProjectID:  "project-tools",
		Kind:       "intent",
		Title:      "等待容量释放",
		Status:     "capacity_blocked",
		Confidence: 70,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("创建容量受限意图失败: %v", err)
	}
	decision := service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		time.Now().UTC().Add(-time.Second),
		&runCapture{},
	)
	if !decision.Allowed || decision.CapacityBlockedIntents != 0 {
		t.Fatalf("容量受限意图不应阻塞当前请求: %+v", decision)
	}
}

func TestMissionProgressTracksCoverageChanges(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	before := service.missionProgress(ctx, "project-tools", "user-1")
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-progress", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "进度目标", Kind: "url", Value: "https://progress.example.com",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ID: "progress-test", ProjectID: "project-tools", AssetID: "asset-progress",
		Dimension: "认证测试", Status: "tested_clean",
		Result: "未发现绕过", Evidence: "对照响应一致", Confidence: 90,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("写入测试结果失败: %v", err)
	}
	after := service.missionProgress(ctx, "project-tools", "user-1")
	if after == before {
		t.Fatalf("新增资产和测试结果后进度快照不应相同: before=%+v after=%+v", before, after)
	}
	if after.AssetsTested == before.AssetsTested || after.TestsCovered == before.TestsCovered {
		t.Fatalf("进度快照未记录覆盖变化: before=%+v after=%+v", before, after)
	}
}
