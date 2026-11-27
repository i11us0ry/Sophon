package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func standardFindingArgs(args map[string]interface{}) map[string]interface{} {
	defaults := map[string]interface{}{
		"description":        "目标接口参数未经过安全处理并直接进入数据库查询，形成 SQL 注入测试链路。",
		"vulnerability_type": "SQL 注入",
		"preconditions":      "使用授权测试账号和独立测试数据，无需修改业务数据。",
		"poc": "GET /item?id=1%20AND%201=1 HTTP/1.1\n" +
			"Host: evidence.example\n" +
			"Accept: */*",
		"evidence":       "响应状态码和返回内容证明条件表达式生效。",
		"impact":         "直接危害：可读取测试数据库数据；数据安全：存在敏感数据暴露风险。",
		"recommendation": "使用参数化查询并限制数据库账号权限。",
		"residual_notes": "只读验证，未修改业务数据，无数据残留。",
	}
	for key, value := range defaults {
		existing, ok := args[key]
		if !ok || existing == nil || strings.TrimSpace(fmt.Sprint(existing)) == "" {
			args[key] = value
		}
	}
	poc := strings.TrimSpace(fmt.Sprint(args["poc"]))
	hasBurpPacket := strings.Contains(poc, " HTTP/1.") &&
		strings.Contains(strings.ToLower(poc), "\nhost:")
	if !hasBurpPacket {
		poc = "```http\nGET /test HTTP/1.1\nHost: evidence.example\n\nPayload: " + poc + "\n```"
	}
	pythonPattern := regexp.MustCompile("(?ms)^```(?:python3?|py|bash|sh|powershell|pwsh)[ \t]*\n.*?^```[ \t]*$")
	if !pythonPattern.MatchString(poc) {
		poc += "\n\n```python\nimport requests\nresponse = requests.get('https://evidence.example', timeout=15)\nprint(response.status_code, len(response.content), response.text[:200])\n```"
	}
	args["poc"] = poc
	return args
}

func completedToolRef(
	t *testing.T,
	service *Service,
	ctx context.Context,
	toolName string,
) string {
	t.Helper()
	id := service.db.StartToolExecution(
		ctx,
		"conv-tools",
		"user-1",
		toolName,
		map[string]interface{}{"target": "https://evidence.example"},
	)
	service.db.FinishToolExecution(ctx, id, "completed evidence", nil)
	return "tool:" + id
}

func TestProjectFindingRequiresEvidenceBeforeAssetWrite(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", map[string]interface{}{
		"title":              "无证据漏洞",
		"severity":           "high",
		"vulnerability_type": "SQL 注入",
		"target":             "https://evidence.example/login?id=1",
		"poc":                "id=1 AND 1=1\n利用脚本（优先 Python）：\n```python\nprint('test')\n```",
		"impact":             "可读取数据库数据",
	}); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("无证据漏洞应被拒绝: %v", err)
	}
	assets, err := service.db.ListProjectAssets(ctx, "project-tools", "user-1")
	if err != nil {
		t.Fatalf("读取资产失败: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("证据校验失败前不应创建资产: %+v", assets)
	}
}

func TestProjectFindingRequiresPOCForHighSeverity(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	evidenceRef := completedToolRef(t, service, ctx, "http-probe")
	service.model = &vulnerabilityReviewTestModel{
		content: `{"description":"未修复正文","preconditions":"否","reproduction_steps":"","evidence":"HTTP 500","impact":"可读取数据库数据","recommendation":"参数化查询","residual_notes":"无"}`,
	}
	output, err := invokeProjectTool(t, service, ctx, "project_report_finding", map[string]interface{}{
		"title":              "高危无 POC",
		"severity":           "high",
		"vulnerability_type": "SQL 注入",
		"target":             "https://evidence.example/login?id=1",
		"evidence":           "HTTP 500",
		"evidence_refs":      []string{evidenceRef},
		"impact":             "可读取数据库数据",
	})
	if err != nil || !strings.Contains(output, "漏洞已安全保存为草稿") {
		t.Fatalf("漏洞编写修复失败后应保留草稿: output=%q err=%v", output, err)
	}
	drafts, total, err := service.db.ListVulnerabilityReportDrafts(ctx, "project-tools", "user-1", 10, 0)
	if err != nil || total != 1 || len(drafts) != 1 || drafts[0].Status != database.VulnerabilityDraftStatusNeedsInput {
		t.Fatalf("漏洞编写失败后草稿状态错误: total=%d drafts=%+v err=%v", total, drafts, err)
	}
	findings, findingTotal, err := service.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Limit:       10,
	})
	if err != nil || findingTotal != 0 || len(findings) != 0 {
		t.Fatalf("未通过正文校验时不应写入正式漏洞: total=%d findings=%+v err=%v", findingTotal, findings, err)
	}
}

func TestProjectFindingAllowsObservedStaticCodeEvidence(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	args := standardFindingArgs(map[string]interface{}{
		"title":              "Servlet 免登录文件写入链",
		"severity":           "high",
		"vulnerability_type": "文件上传",
		"target":             "source:seeyon20250422",
		"verification_state": "observed",
		"poc":                "HtmlOfficeServlet.doPost -> SAVEASIMG -> FILENAME -> transferTo；仅用源码调用链和反编译证据证明。",
		"evidence":           "免登录 Servlet 名单包含 htmlofficeservlet，SAVEASIMG 分支 FILENAME 可控，写入后缀黑名单未覆盖 .jspx。",
		"evidence_refs": []string{
			completedToolRef(t, service, ctx, "java_decompile"),
		},
	})
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", args); err != nil {
		t.Fatalf("observed 静态代码漏洞应允许写回: %v", err)
	}
	findings, _, err := service.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Limit:       10,
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("读取静态漏洞失败: %+v err=%v", findings, err)
	}
	if findings[0].VerificationState != "observed" {
		t.Fatalf("静态漏洞状态应为 observed，实际 %q", findings[0].VerificationState)
	}
}

func TestProjectFindingSurvivesReviewServiceUnavailable(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	service.vulnerabilityReviewHook = func(context.Context, database.Vulnerability) error {
		return &VulnerabilityReviewUnavailableError{Reason: "审核模型返回格式无效"}
	}
	args := standardFindingArgs(map[string]interface{}{
		"title":              "审核不可用时的 SQL 注入",
		"severity":           "high",
		"vulnerability_type": "SQL 注入",
		"target":             "https://review-unavailable.example/item?id=1",
		"evidence_refs": []string{
			completedToolRef(t, service, ctx, "sqlmap"),
		},
	})
	out, err := invokeProjectTool(t, service, ctx, "project_report_finding", args)
	if err != nil {
		t.Fatalf("审核服务临时不可用不应丢弃 finding: %v", err)
	}
	if !strings.Contains(out, "已暂存为待审核") || !strings.Contains(out, "审核服务暂不可用") {
		t.Fatalf("finding 结果应提示待复核: %q", out)
	}
	findings, _, err := service.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Limit:       10,
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("审核不可用时 finding 未保存: %+v err=%v", findings, err)
	}
	if findings[0].Status != "pending_review" {
		t.Fatalf("审核不可用时 finding 状态应为 pending_review: %+v", findings[0])
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	for _, node := range nodes {
		if node.Kind == "finding" {
			t.Fatalf("待审核 finding 不应提前生成攻击路径节点: %+v", node)
		}
	}
}

func TestProjectFindingRequiresStandardReportFields(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	args := standardFindingArgs(map[string]interface{}{
		"title":    "标准报告缺字段",
		"severity": "high",
		"target":   "https://evidence.example/login?id=1",
		"evidence": "HTTP 500",
		"evidence_refs": []string{
			completedToolRef(t, service, ctx, "http-probe"),
		},
	})
	delete(args, "residual_notes")
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", args); err != nil {
		t.Fatalf("未复测时应自动记录为“无”: %v", err)
	}
	findings, _, err := service.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Limit:       10,
	})
	if err != nil || len(findings) != 1 || findings[0].RetestNotes != "无" {
		t.Fatalf("复测备注默认值错误: %+v err=%v", findings, err)
	}
}

func TestProjectFindingRejectsFakeToolEvidence(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", map[string]interface{}{
		"title":              "伪造证据",
		"severity":           "high",
		"vulnerability_type": "SQL 注入",
		"target":             "https://evidence.example/login?id=1",
		"poc":                "```http\nGET /login?id=1%20AND%201=1 HTTP/1.1\nHost: evidence.example\nUser-Agent: curl/8\n```\n\n```python\nimport requests\nprint(requests.get('https://evidence.example/login?id=1', timeout=10).status_code)\n```",
		"impact":             "可读取数据库数据",
		"evidence":           "看起来存在漏洞",
		"evidence_refs":      []string{"tool:not-a-real-execution"},
	}); err == nil || !strings.Contains(err.Error(), "工具执行无效") {
		t.Fatalf("伪造工具证据应被拒绝: %v", err)
	}
}

func TestProjectFindingSuggestsToolEvidenceCandidates(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	actualRef := completedToolRef(t, service, ctx, "http-probe")
	_, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title":         "错误工具证据",
		"severity":      "high",
		"target":        "https://evidence.example/login?id=1",
		"evidence_refs": []string{actualRef, "tool:missing-execution"},
	}))
	if err == nil {
		t.Fatal("无效工具证据应被拒绝")
	}
	for _, want := range []string{"可恢复候选", actualRef, "http-probe"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("工具证据错误缺少 %q: %v", want, err)
		}
	}
}

func TestProjectFindingSuggestsFactEvidenceCandidates(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"key":     "business/evidence-candidate",
		"summary": "可供漏洞证据引用的事实",
	}); err != nil {
		t.Fatalf("创建候选事实失败: %v", err)
	}
	facts, err := service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil || len(facts) != 1 {
		t.Fatalf("读取候选事实失败: %+v err=%v", facts, err)
	}
	_, err = invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title":         "错误事实证据",
		"severity":      "high",
		"target":        "https://evidence.example/login?id=1",
		"evidence_refs": []string{"fact:missing-evidence"},
	}))
	if err == nil {
		t.Fatal("无效事实证据应被拒绝")
	}
	for _, want := range []string{"可恢复候选", "fact:" + facts[0].ID, facts[0].Key} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("事实证据错误缺少 %q: %v", want, err)
		}
	}
}

func TestProjectFindingSuggestsArtifactEvidenceCandidates(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	root := t.TempDir()
	service.cfg.Storage.ArtifactRoot = root
	artifactDir := filepath.Join(root, "data", "conversation_artifacts", "conv-tools", "tool_results")
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatalf("创建 artifact 目录失败: %v", err)
	}
	artifactPath := filepath.Join(artifactDir, "evidence.txt")
	if err := os.WriteFile(artifactPath, []byte("evidence"), 0o600); err != nil {
		t.Fatalf("写入 artifact 文件失败: %v", err)
	}
	_, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title":         "错误文件证据",
		"severity":      "high",
		"target":        "https://evidence.example/login?id=1",
		"evidence_refs": []string{"artifact:/not-allowed/evidence.txt"},
	}))
	if err == nil {
		t.Fatal("无效 artifact 证据应被拒绝")
	}
	for _, want := range []string{"可恢复候选", "artifact:" + artifactPath} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("文件证据错误缺少 %q: %v", want, err)
		}
	}
}

func TestProjectRecordTestRejectsCrossProjectFinding(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateProject(ctx, database.Project{
		ID: "other-project", OwnerUserID: "user-1", Name: "其他项目",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建其他项目失败: %v", err)
	}
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID: "other-finding", ProjectID: "other-project", OwnerUserID: "user-1",
		Title: "其他项目漏洞", Severity: "high", Status: "open",
		Evidence: "evidence", VerificationState: "verified", Confidence: 90,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建其他项目漏洞失败: %v", err)
	}
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-cross-test", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "测试资产", Kind: "url", Value: "https://cross.example",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_test", map[string]interface{}{
		"asset_id":      "asset-cross-test",
		"dimension":     "SQL注入",
		"status":        "confirmed",
		"result":        "确认漏洞",
		"evidence":      "证据",
		"finding_id":    "other-finding",
		"evidence_refs": []string{completedToolRef(t, service, ctx, "sqlmap")},
	}); err == nil || !strings.Contains(err.Error(), "不属于当前项目") {
		t.Fatalf("跨项目 finding 应被拒绝: %v", err)
	}
}

func TestProjectFindingFingerprintMergesDuplicateEvidence(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	firstRef := completedToolRef(t, service, ctx, "sqlmap")
	secondRef := completedToolRef(t, service, ctx, "sqlmap")
	args := standardFindingArgs(map[string]interface{}{
		"title":              "SQL 注入",
		"severity":           "high",
		"target":             "https://merge.example/login?id=1",
		"vulnerability_type": "SQL Injection",
		"poc":                "id=1 AND 1=1",
		"evidence":           "第一份响应证据",
		"evidence_refs":      []string{firstRef},
	})
	first, err := invokeProjectTool(t, service, ctx, "project_report_finding", args)
	if err != nil || !strings.Contains(first, "已上报漏洞") {
		t.Fatalf("首次上报失败: %q err=%v", first, err)
	}
	args["title"] = "数字型 SQL 注入"
	args["evidence"] = "第二份独立响应证据"
	args["evidence_refs"] = []string{secondRef}
	second, err := invokeProjectTool(t, service, ctx, "project_report_finding", args)
	if err != nil || !strings.Contains(second, "已合并重复漏洞") {
		t.Fatalf("重复漏洞应合并: %q err=%v", second, err)
	}
	findings, total, err := service.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Limit:       10,
	})
	if err != nil || total != 1 || len(findings) != 1 {
		t.Fatalf("重复上报应只保留一条漏洞: total=%d findings=%+v err=%v", total, findings, err)
	}
	if len(findings[0].EvidenceRefs) != 2 {
		t.Fatalf("合并后证据引用应去重保留: %+v", findings[0].EvidenceRefs)
	}
	if findings[0].Fingerprint == "" || findings[0].VerificationState != "observed" {
		t.Fatalf("漏洞指纹或验证状态缺失: %+v", findings[0])
	}
	tests, err := service.db.ListProjectTestResults(ctx, "project-tools", 20)
	foundConfirmed := false
	for _, item := range tests {
		if item.Status == "confirmed" && item.FindingID != "" {
			foundConfirmed = true
			break
		}
	}
	if err != nil || !foundConfirmed {
		t.Fatalf("漏洞上报应写入 confirmed 测试结果: %+v err=%v", tests, err)
	}
}

func TestProjectUpdateFindingCannotConfirmWithoutEvidence(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateVulnerability(ctx, database.Vulnerability{
		ID: "finding-no-evidence", ProjectID: "project-tools", OwnerUserID: "user-1",
		Title: "待确认漏洞", Severity: "medium", Status: "open",
		Target: "https://confirm.example/item?id=1", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建无证据漏洞失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_update_finding", map[string]interface{}{
		"finding_id": "finding-no-evidence",
		"status":     "confirmed",
	}); err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("无证据漏洞不得更新为 confirmed: %v", err)
	}
}

func TestProjectRecordTestRequiresEvidenceAndSurfacesSuspiciousResult(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-test-result", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "测试资产", Kind: "url", Value: "https://coverage.example",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_test", map[string]interface{}{
		"asset_id":  "asset-test-result",
		"dimension": "SQL注入",
		"status":    "tested_clean",
		"result":    "无差异",
	}); err == nil || !strings.Contains(err.Error(), "证据") {
		t.Fatalf("无证据的 tested_clean 应被拒绝: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_test", map[string]interface{}{
		"asset_id":   "asset-test-result",
		"dimension":  "SQL注入",
		"status":     "suspicious",
		"result":     "响应长度存在差异，需要进一步验证",
		"confidence": 60,
	}); err != nil {
		t.Fatalf("记录可疑测试失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_next_targets", map[string]interface{}{})
	if err != nil || !strings.Contains(out, "可疑结果待验证") {
		t.Fatalf("可疑测试应进入未覆盖队列: %q err=%v", out, err)
	}
}
