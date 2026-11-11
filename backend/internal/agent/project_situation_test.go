package agent

import (
	"errors"
	"strings"
	"testing"
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
	if !strings.Contains(system, "项目写回纪律") {
		t.Fatalf("稳定前缀应包含写回纪律：\n%s", system)
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
		"项目写回纪律",
	} {
		if !strings.Contains(instruction, want) {
			t.Fatalf("子 Agent 提示缺少 %q：\n%s", want, instruction)
		}
	}
}
