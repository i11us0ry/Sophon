package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestProjectSituationIncludesGoalsIntentsFactsFindings(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "目标IP", "value": "10.0.0.1", "confidence": 95,
	}); err != nil {
		t.Fatalf("记录事实失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "admin", "value": "admin/123456", "fact_type": "credential", "confidence": 99,
	}); err != nil {
		t.Fatalf("记录凭据失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_insert_assets", map[string]interface{}{
		"assets_json": `[{"name":"待测主机","kind":"ip","value":"10.0.0.2","criticality":"high"}]`,
	}); err != nil {
		t.Fatalf("写入资产失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title": "验证 SQL 注入", "status": "running",
	}); err != nil {
		t.Fatalf("写入意图失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title": "SQL 注入", "severity": "critical", "target": "https://a.com/x?id=1",
		"poc": "id=1 AND 1=1", "evidence": "HTTP 200，注入回显",
		"evidence_refs": []string{completedToolRef(t, service, ctx, "sqlmap")},
	})); err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	failedID := service.db.StartToolExecution(ctx, "conv-tools", "user-1", "nmap", map[string]interface{}{})
	service.db.FinishToolExecution(ctx, failedID, "", errors.New("connection timeout"))
	probeID := service.db.StartToolExecution(ctx, "conv-tools", "user-1", "exec", map[string]interface{}{
		"command": "curl -sk https://falcon.example.com/rc_oa_gateway/user/session.json",
	})
	service.db.FinishToolExecution(ctx, probeID, "200", nil)

	situation := service.projectSituationForContext(
		ctx,
		"project-tools",
		"user-1",
		"conv-tools",
	)
	for _, want := range []string{
		"当前项目任务态势包",
		"目标：",
		"当前意图：[running] 验证 SQL 注入",
		"Todo",
		"已知凭据与账号",
		"admin/123456",
		"事实索引",
		"目标IP",
		"漏洞摘要",
		"[critical/open/verified]",
		"SQL 注入",
		"https://a.com/x?id=1",
		"未测试资产",
		"10.0.0.2",
		"最近失败工具",
		"nmap",
		"最近网络探测账本",
		"falcon.example.com",
		"/rc_oa_gateway/user/session.json",
	} {
		if !strings.Contains(situation, want) {
			t.Fatalf("态势快照缺少 %q：\n%s", want, situation)
		}
	}
}

func TestProjectSituationReportsAttachmentsWithoutImposingWorkflow(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if err := service.db.AddAttachment(ctx, database.Attachment{
		ID:             "attachment-source",
		ConversationID: "conv-tools",
		FileName:       "WebSite.zip",
		MimeType:       "application/zip",
		StoragePath:    "conv-tools/attachment-source_WebSite.zip",
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("创建源码附件失败: %v", err)
	}
	situation := service.projectSituationForContext(ctx, "project-tools", "user-1", "conv-tools")
	if !strings.Contains(situation, "项目已有上传附件") {
		t.Fatalf("项目无资产但有附件时应报告附件状态：\n%s", situation)
	}
	if strings.Contains(situation, "必须先调用 project_insert_assets 登记目标") {
		t.Fatalf("源码审计模式不应要求先登记网络资产：\n%s", situation)
	}
}

func TestProjectSituationTruncatesLongFact(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	longValue := strings.Repeat("数", 500)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "超长事实", "value": longValue,
	}); err != nil {
		t.Fatalf("记录事实失败: %v", err)
	}
	situation := service.projectSituation(ctx, "project-tools", "user-1")
	if strings.Contains(situation, longValue) {
		t.Fatalf("长事实不应注入完整文本")
	}
	if !strings.Contains(situation, "…") {
		t.Fatalf("长事实应带截断标记：\n%s", situation)
	}
	if len([]rune(situation)) > situationTotalRunes+50 {
		t.Fatalf("态势快照超过预算：%d 字", len([]rune(situation)))
	}
}

func TestProjectSituationDoesNotReportFalsePentestAuthorization(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	ctx = withMissionExecution(ctx, missionExecution{
		Plan:  missionPlan{Mode: missionModeGeneral},
		Phase: missionPhaseGeneral,
	})
	situation := service.projectSituationForContext(
		ctx,
		"project-tools",
		"user-1",
		"conv-tools",
	)
	if strings.Contains(situation, "渗透授权：未授予") {
		t.Fatalf("普通任务不应误报渗透授权状态：\n%s", situation)
	}
	if !strings.Contains(situation, "仅作为背景，不属于本轮执行范围") {
		t.Fatalf("应保留历史目标范围提示：\n%s", situation)
	}
}

func TestProjectSituationListsAuditWorkspaceArtifacts(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	workspace := filepath.Join(t.TempDir(), "tmp", "workspace", "conv-tools")
	service.cfg.Storage.ArtifactRoot = filepath.Dir(filepath.Dir(filepath.Dir(workspace)))
	auditOut := filepath.Join(workspace, "audit_out")
	if err := os.MkdirAll(auditOut, 0o700); err != nil {
		t.Fatalf("创建审计目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(auditOut, "Entry.txt"), []byte("bytecode"), 0o600); err != nil {
		t.Fatalf("写入审计产物失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "sink_hits.json"), []byte(`{"hits":[]}`), 0o600); err != nil {
		t.Fatalf("写入候选索引失败: %v", err)
	}

	situation := service.projectSituationForContext(ctx, "project-tools", "user-1", "conv-tools")
	for _, want := range []string{
		"Java 审计工作台",
		"audit_out/",
		"sink_hits.json",
		"优先复用",
	} {
		if !strings.Contains(situation, want) {
			t.Fatalf("态势包缺少审计工作台信息 %q：\n%s", want, situation)
		}
	}
}

func TestProjectSituationShowsLongRunningIntentAge(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID:         "intent-stale",
		ProjectID:  "project-tools",
		Kind:       "intent",
		Title:      "已经否定的文件写入方向",
		Status:     "open",
		Confidence: 70,
		CreatedAt:  now.Add(-3 * time.Hour),
		UpdatedAt:  now.Add(-3 * time.Hour),
	}); err != nil {
		t.Fatalf("创建旧 intent 失败: %v", err)
	}

	situation := service.projectSituation(ctx, "project-tools", "user-1")
	if !strings.Contains(situation, "当前意图：[open]") ||
		!strings.Contains(situation, "已持续") ||
		!strings.Contains(situation, "小时") {
		t.Fatalf("态势包应显示长期未收敛 intent 的持续时间：\n%s", situation)
	}
}

func TestProjectSituationExcludesAuditCellsFromCriticalContext(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	for _, fact := range []database.ProjectFact{
		{
			ID: "fact-critical", ProjectID: "project-tools", Key: "note/critical-control",
			Summary: "必须遵守的关键控制", FactType: "note", Priority: 95, Pinned: true,
			Confidence: 95, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "fact-audit-cell", ProjectID: "project-tools", Key: "business/audit-cell-test",
			Summary: "审计矩阵单元不应进入关键上下文", FactType: "constraint",
			MemoryKind: "constraint", Priority: 90, Confidence: 90, CreatedAt: now, UpdatedAt: now,
		},
	} {
		if _, err := service.db.UpsertProjectFact(ctx, fact); err != nil {
			t.Fatalf("写入事实失败: %v", err)
		}
	}
	situation := service.projectSituation(ctx, "project-tools", "user-1")
	start := strings.Index(situation, "关键约束记忆")
	end := strings.Index(situation, "事实索引")
	if start < 0 || end <= start {
		t.Fatalf("态势包缺少关键约束记忆或事实索引：\n%s", situation)
	}
	critical := situation[start:end]
	if strings.Contains(critical, "business/audit-cell-test") {
		t.Fatalf("审计矩阵单元不应进入关键上下文：\n%s", critical)
	}
	if !strings.Contains(critical, "note/critical-control") {
		t.Fatalf("普通关键事实应进入关键上下文：\n%s", critical)
	}
}

func TestMainAgentInstructionIncludesSituation(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "目标IP", "value": "10.0.0.1",
	}); err != nil {
		t.Fatalf("记录事实失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title": "SQL 注入", "severity": "high", "target": "https://a.com/x?id=1",
		"poc": "id=1 AND 1=1", "evidence": "HTTP 200，注入回显",
		"evidence_refs": []string{completedToolRef(t, service, ctx, "sqlmap")},
	})); err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	messages, err := service.buildModelMessages(ctx, "conv-tools", "user-1")
	if err != nil {
		t.Fatalf("组装模型消息失败: %v", err)
	}
	if len(messages) == 0 {
		t.Fatalf("模型消息为空")
	}
	system := messages[0].Content
	if !strings.Contains(system, "项目工具能力") {
		t.Fatalf("稳定前缀应包含项目工具能力说明：\n%s", system)
	}
	if strings.Contains(system, "项目写回纪律（强制）") {
		t.Fatalf("稳定前缀不应注入固定写回流程：\n%s", system)
	}
	state := lastStateMessage(t, messages)
	for _, want := range []string{
		"当前项目任务态势包",
		"事实索引",
		"漏洞摘要",
	} {
		if !strings.Contains(state, want) {
			t.Fatalf("主 Agent 状态包缺少 %q：\n%s", want, state)
		}
	}
}

func TestSubAgentInstructionIncludesSituation(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key": "目标IP", "value": "10.0.0.1",
	}); err != nil {
		t.Fatalf("记录事实失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title": "SQL 注入", "severity": "high", "target": "https://a.com/x?id=1",
		"poc": "id=1 AND 1=1", "evidence": "HTTP 200，注入回显",
		"evidence_refs": []string{completedToolRef(t, service, ctx, "sqlmap")},
	})); err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	runner := newSubAgentRunner(service)
	instruction := runner.instruction(ctx)
	for _, want := range []string{
		"当前项目任务态势包",
		"事实索引",
		"漏洞摘要",
		"项目工具能力",
	} {
		if !strings.Contains(instruction, want) {
			t.Fatalf("子 Agent 提示缺少 %q：\n%s", want, instruction)
		}
	}
}
