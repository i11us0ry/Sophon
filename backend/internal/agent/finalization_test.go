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

func TestFinalizationRequiresGoalsEvidenceAndCompletedTools(t *testing.T) {
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
		t.Fatalf("目标未完成、证据不足且工具未返回时不应允许最终化")
	}
	reasons := strings.Join(decision.Reasons, "\n")
	for _, want := range []string{"尚未返回结果", "目标未完成", "项目资产为空", "证据不足", "没有记录任何测试维度"} {
		if !strings.Contains(reasons, want) {
			t.Fatalf("最终化原因缺少 %q：%s", want, reasons)
		}
	}

	capture.recordToolResult("call-1")
	executionID := service.db.StartToolExecution(
		ctx,
		"conv-tools",
		"user-1",
		"exec",
		map[string]interface{}{"command": "id"},
	)
	service.db.FinishToolExecution(ctx, executionID, "uid=0", nil)
	if _, err := invokeProjectTool(t, service, ctx, "project_update_goal", map[string]interface{}{
		"goal_id": "goal-final",
		"status":  "met",
	}); err != nil {
		t.Fatalf("更新目标状态失败: %v", err)
	}

	decision = service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		capture,
	)
	if decision.Allowed {
		t.Fatalf("没有登记资产时不应允许最终化: %+v", decision)
	}
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "asset-final",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "测试资产",
		Kind:        "url",
		Value:       "https://example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_test", map[string]interface{}{
		"asset_id":   "asset-final",
		"dimension":  "SQL注入",
		"status":     "tested_clean",
		"result":     "参数化查询验证无注入",
		"evidence":   "布尔对照响应一致",
		"confidence": 90,
	}); err != nil {
		t.Fatalf("记录测试结果失败: %v", err)
	}

	decision = service.checkFinalization(
		ctx,
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		capture,
	)
	if !decision.Allowed {
		t.Fatalf("目标完成且证据齐全后应允许最终化: %+v", decision)
	}
	if !decision.EvidenceVerified {
		t.Fatalf("应记录已完成工具证据: %+v", decision)
	}
}

func TestFinalizationPauseOnQuestionMode(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	finalText := "如需我继续，可验证下一高价值方向。"
	runStartedAt := time.Now().UTC().Add(-time.Second)

	autoDecision := service.checkFinalization(
		execctx.WithAutoContinue(ctx, true),
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		&runCapture{},
		finalText,
	)
	if autoDecision.PauseOnQuestion {
		t.Fatalf("自动继续模式不应因提问暂停")
	}

	pauseDecision := service.checkFinalization(
		execctx.WithAutoContinue(ctx, false),
		"conv-tools",
		"project-tools",
		"user-1",
		runStartedAt,
		&runCapture{},
		finalText,
	)
	if !pauseDecision.PauseOnQuestion || !pauseDecision.PendingUserConfirmation {
		t.Fatalf("遇到问题暂停模式应识别提问并暂停: %+v", pauseDecision)
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
		Content:        "执行安全测试 example.com",
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
	if result != "强制总结已生成。" {
		t.Fatalf("最终文本异常: %q", result)
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

func TestFinalizationAutoContinuesOnActionableQuestion(t *testing.T) {
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
	if decision.Allowed {
		t.Fatalf("仍有可执行目标时不应允许确认式提问结束任务: %+v", decision)
	}
	if !decision.PendingUserConfirmation {
		t.Fatalf("应标记为确认式提问: %+v", decision)
	}
	if !strings.Contains(strings.Join(decision.Reasons, "\n"), "禁止询问用户是否继续") {
		t.Fatalf("最终化原因应要求自动续跑: %+v", decision.Reasons)
	}
}

func TestFinalizationBlocksUnresolvedBlockedIntent(t *testing.T) {
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
	if decision.DerivableBlockedIntents != 1 {
		t.Fatalf("应识别未派生替代路径的 blocked 意图: %+v", decision)
	}
	if decision.Allowed {
		t.Fatalf("存在未处理的 blocked 意图时不应允许最终化: %+v", decision)
	}
	if !strings.Contains(strings.Join(decision.Reasons, "\n"), "blocked 意图尚未派生替代路径") {
		t.Fatalf("最终化原因缺少 blocked 提示: %+v", decision.Reasons)
	}
}

func TestFinalizationReportsCapacityBlockedIntent(t *testing.T) {
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
	if decision.CapacityBlockedIntents != 1 || decision.Allowed {
		t.Fatalf("容量受限意图不应被当作已完成: %+v", decision)
	}
	if !strings.Contains(strings.Join(decision.Reasons, "\n"), "容量受限") {
		t.Fatalf("最终化原因缺少容量受限提示: %+v", decision.Reasons)
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
