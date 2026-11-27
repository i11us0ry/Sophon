package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

func TestProjectHypothesisPlannerWorkerFlow(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-hypothesis", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "假设目标", Kind: "url", Value: "https://hypothesis.example/item?id=1",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[
			{"asset_id":"asset-hypothesis","dimension":"SQL注入","technique":"time-based","rationale":"参数疑似拼接 SQL","expected_evidence":"稳定延时差异","priority":90},
			{"asset_id":"asset-hypothesis","dimension":"权限上下文","technique":"auth-context","rationale":"接口可能缺少鉴权","expected_evidence":"匿名访问敏感数据","priority":80}
		]`,
	})
	if err != nil || !strings.Contains(out, "写入 2 个") {
		t.Fatalf("规划假设失败: %q err=%v", out, err)
	}
	items, err := service.db.ListProjectHypotheses(ctx, "project-tools", "untested", 10)
	if err != nil || len(items) != 2 || items[0].Priority != 90 {
		t.Fatalf("假设队列错误: %+v err=%v", items, err)
	}
	for _, item := range items {
		if item.IntentID == "" {
			t.Fatalf("Hypothesis 未关联 Graph Intent: %+v", item)
		}
		if item.OriginConversationID != "conv-tools" {
			t.Fatalf("Hypothesis 未记录来源会话: %+v", item)
		}
		node, err := service.db.GetProjectGraphNode(ctx, item.IntentID, "project-tools")
		if err != nil || node == nil || node.Kind != "intent" {
			t.Fatalf("Graph Intent 不存在: intent=%s node=%+v err=%v", item.IntentID, node, err)
		}
	}
	started, err := invokeProjectTool(t, service, ctx, "project_start_hypothesis", map[string]interface{}{
		"hypothesis_id": items[0].ID,
	})
	if err != nil || !strings.Contains(started, "attempts=1") {
		t.Fatalf("领取假设失败: %q err=%v", started, err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_complete_hypothesis", map[string]interface{}{
		"hypothesis_id": items[0].ID,
		"status":        "tested_clean",
		"result":        "多次延时测试稳定一致",
		"evidence":      "time-based 对照响应无差异",
		"confidence":    90,
	}); err != nil {
		t.Fatalf("完成假设失败: %v", err)
	}
	coverage, err := service.db.ProjectCoverage(ctx, "project-tools", "user-1")
	if err != nil || coverage.TestsTotal != 2 || coverage.TestsCovered != 1 {
		t.Fatalf("假设完成后的覆盖率错误: %+v err=%v", coverage, err)
	}
	intentNode, err := service.db.GetProjectGraphNode(ctx, items[0].IntentID, "project-tools")
	if err != nil || intentNode == nil || intentNode.Status != "done" {
		t.Fatalf("完成 Hypothesis 后 Graph Intent 应同步 done: %+v err=%v", intentNode, err)
	}
}

func TestProjectPlanHypothesesLinksParentIDs(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-parent-hypothesis", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "父节点目标", Kind: "url", Value: "https://parent.example/upload",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID: "fact-parent-hypothesis", ProjectID: "project-tools",
		Kind: "fact", Title: "上传入口事实", Status: "confirmed",
		AssetID: "asset-parent-hypothesis", Confidence: 95,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建父事实失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[{
			"asset_id":"asset-parent-hypothesis",
			"parent_ids":["fact-parent-hypothesis"],
			"dimension":"上传入口路径穿越复核",
			"technique":"path-traversal",
			"rationale":"父事实确认入口可达",
			"expected_evidence":"目录外文件可读取",
			"priority":90
		}]`,
	})
	if err != nil || !strings.Contains(out, "写入 1 个") {
		t.Fatalf("规划带父节点的假设失败: %q err=%v", out, err)
	}
	items, err := service.db.ListProjectHypotheses(ctx, "project-tools", "untested", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("读取假设失败: %+v err=%v", items, err)
	}
	edges, err := service.db.ListProjectGraphEdges(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取血缘边失败: %v", err)
	}
	found := false
	for _, edge := range edges {
		if edge.SrcID == "fact-parent-hypothesis" &&
			edge.DstID == items[0].IntentID &&
			edge.Rel == "derived_from" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("缺少父事实到假设的 derived_from 边: %+v", edges)
	}
}

func TestProjectPlanHypothesesRejectsMoreThanFour(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	_, err := invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[
			{"dimension":"方向1"},
			{"dimension":"方向2"},
			{"dimension":"方向3"},
			{"dimension":"方向4"},
			{"dimension":"方向5"}
		]`,
	})
	if err == nil || !strings.Contains(err.Error(), "1-4") {
		t.Fatalf("超过 4 个假设应被拒绝: %v", err)
	}
}

func TestProjectPlanHypothesesSkipsNormalizedDuplicateDimensions(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-plan-dedupe", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "去重目标", Kind: "url", Value: "https://dedupe.example/upload",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[
			{"asset_id":"asset-plan-dedupe","dimension":"文件上传","technique":"upload-handler","priority":90},
			{"asset_id":"asset-plan-dedupe","dimension":" 文件-上传 ","technique":"upload-extension","priority":80}
		]`,
	})
	if err != nil || !strings.Contains(out, "写入 1 个") || !strings.Contains(out, "跳过 1 个") {
		t.Fatalf("规范化重复假设应被跳过: %q err=%v", out, err)
	}
	out, err = invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[
			{"asset_id":"asset-plan-dedupe","dimension":"文件 / 上传","technique":"another-upload-check","priority":95}
		]`,
	})
	if err != nil || !strings.Contains(out, "写入 0 个") || !strings.Contains(out, "跳过 1 个") {
		t.Fatalf("已有活跃假设应阻止再次规划: %q err=%v", out, err)
	}
	items, err := service.db.ListProjectHypotheses(ctx, "project-tools", "untested", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("重复假设数量错误: %+v err=%v", items, err)
	}
}

func TestWorkerCannotCompleteAnotherHypothesis(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-worker-scope", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "Worker 边界目标", Kind: "url", Value: "https://worker-scope.example/item",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	current, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID: "project-tools", AssetID: "asset-worker-scope",
		Dimension: "当前 Worker 假设", Technique: "current",
		Status: "running", IntentID: "intent-current",
		OriginConversationID: "conv-tools", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建当前假设失败: %v", err)
	}
	other, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID: "project-tools", AssetID: "asset-worker-scope",
		Dimension: "其他 Worker 假设", Technique: "other",
		Status: "running", IntentID: "intent-other",
		OriginConversationID: "conv-tools", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建其他假设失败: %v", err)
	}
	workerCtx := execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID: "worker-scope", Kind: "worker",
		HypothesisID: current.ID, IntentID: current.IntentID,
	})
	if _, err := invokeProjectTool(t, service, workerCtx, "project_complete_hypothesis", map[string]interface{}{
		"hypothesis_id": other.ID,
		"status":        "blocked",
		"result":        "不应允许写回其他假设",
	}); err == nil || !strings.Contains(err.Error(), "当前 Worker") {
		t.Fatalf("Worker 操作其他假设应被拒绝，实际: %v", err)
	}
	if _, err := invokeProjectTool(t, service, workerCtx, "project_complete_hypothesis", map[string]interface{}{
		"hypothesis_id": current.ID,
		"status":        "blocked",
		"result":        "当前假设已阻断",
	}); err != nil {
		t.Fatalf("Worker 操作当前假设应允许: %v", err)
	}
}

func TestProjectRecordTestReusesCurrentWorkerHypothesis(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-record-current", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "上传目标", Kind: "url", Value: "https://record.example/upload",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	original, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID: "project-tools", AssetID: "asset-record-current",
		Dimension: "文件上传-ScpSupRegHandler 上传/写盘面单独闭环（事实清单漏项）",
		Technique: "static-dataflow", Status: "untested", Priority: 90,
	})
	if err != nil {
		t.Fatalf("创建原始假设失败: %v", err)
	}
	claimed, err := service.db.ClaimNextProjectHypothesis(ctx, "project-tools")
	if err != nil || claimed == nil {
		t.Fatalf("领取原始假设失败: %+v err=%v", claimed, err)
	}
	workerCtx := execctx.WithSubagent(ctx, execctx.SubagentInfo{
		ID: "sub-record-current", Kind: "worker", HypothesisID: claimed.ID,
	})
	out, err := invokeProjectTool(t, service, workerCtx, "project_record_test", map[string]interface{}{
		"asset_id":   "asset-record-current",
		"dimension":  "文件上传-ScpSupRegHandler 上传/写盘面单独闭环",
		"technique":  "shortened-copy",
		"status":     "suspicious",
		"result":     "需要继续确认落点",
		"confidence": 70,
	})
	if err != nil || !strings.Contains(out, claimed.ID) {
		t.Fatalf("当前 Worker 写回应复用原假设: %q err=%v", out, err)
	}
	items, err := service.db.ListProjectTestResults(ctx, "project-tools", 20)
	if err != nil || len(items) != 1 {
		t.Fatalf("当前 Worker 不应创建重复假设: %+v err=%v", items, err)
	}
	saved, err := service.db.GetProjectTestResultByID(ctx, "project-tools", original.ID)
	if err != nil || saved == nil || saved.Status != "suspicious" ||
		saved.Dimension != original.Dimension {
		t.Fatalf("原假设写回错误: %+v err=%v", saved, err)
	}
}

func TestProjectRecordTestRejectsOverlappingActiveHypothesis(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-record-overlap", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "上传目标", Kind: "url", Value: "https://record-overlap.example/upload",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	active, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID: "project-tools", AssetID: "asset-record-overlap",
		Dimension: "文件上传-ScpSupRegHandler 上传/写盘面单独闭环（事实清单漏项）",
		Technique: "static-dataflow", Status: "untested", Priority: 90,
	})
	if err != nil {
		t.Fatalf("创建活跃假设失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_test", map[string]interface{}{
		"asset_id":  "asset-record-overlap",
		"dimension": "文件上传-ScpSupRegHandler 上传/写盘面单独闭环",
		"technique": "shortened-copy",
		"status":    "suspicious",
		"result":    "重复测试",
	}); err == nil || !strings.Contains(err.Error(), active.ID) {
		t.Fatalf("重叠活跃假设应阻止新建测试结果: %v", err)
	}
	items, err := service.db.ListProjectTestResults(ctx, "project-tools", 20)
	if err != nil || len(items) != 1 {
		t.Fatalf("拒绝重复后假设数量错误: %+v err=%v", items, err)
	}
}

func TestProjectPlanHypothesesAllowsSourceAuditWithoutAsset(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if err := service.db.AddAttachment(ctx, database.Attachment{
		ID:             "source-audit-attachment",
		ConversationID: "conv-tools",
		FileName:       "WebSite.zip",
		StoragePath:    "conv-tools/source-audit-attachment_WebSite.zip",
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatalf("创建源码附件失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[
			{"dimension":"源码命令执行审计","technique":"source-review","rationale":"已上传源码但项目没有网络资产","expected_evidence":"入口到命令执行 Sink 的代码链","priority":90}
		]`,
	})
	if err != nil {
		t.Fatalf("源码审计不应因缺少网络资产而失败: %v", err)
	}
	if !strings.Contains(out, "写入 1 个") {
		t.Fatalf("源码假设未写入: %q", out)
	}
	items, err := service.db.ListProjectHypotheses(ctx, "project-tools", "untested", 10)
	if err != nil || len(items) != 1 || items[0].AssetID != "" {
		t.Fatalf("源码假设资产范围错误: %+v err=%v", items, err)
	}
}

func TestProjectPlanHypothesesRejectsUnscopedAuditWhenAssetsExist(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-plan-existing", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "已有目标", Kind: "url", Value: "https://planned.example",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建已有资产失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[{"dimension":"无归属审计","technique":"source-review"}]`,
	}); err == nil || !strings.Contains(err.Error(), "asset_id 不能为空") {
		t.Fatalf("已有资产时不应接受无归属假设: %v", err)
	}
}

func TestProjectFindingSeedsFollowUpHypotheses(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title":              "SQL 注入",
		"severity":           "high",
		"target":             "https://followup.example/item?id=1",
		"vulnerability_type": "SQL Injection",
		"poc":                "id=1 AND SLEEP(3)",
		"evidence":           "SQL 注入响应证据",
		"evidence_refs":      []string{completedToolRef(t, service, ctx, "sqlmap")},
		"test_technique":     "boolean",
	})); err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	items, err := service.db.ListProjectHypotheses(ctx, "project-tools", "untested", 20)
	if err != nil {
		t.Fatalf("读取后续假设失败: %v", err)
	}
	if len(items) < 3 {
		t.Fatalf("SQL 注入应生成多个后续假设: %+v", items)
	}
	foundParent := false
	foundTechnique := false
	for _, item := range items {
		if item.ParentID != "" {
			foundParent = true
			if item.Required {
				t.Fatalf("自动后续假设应为 optional: %+v", item)
			}
		}
		if item.Technique == "time-based" || item.Technique == "stacked-query" {
			foundTechnique = true
		}
	}
	if !foundParent || !foundTechnique {
		t.Fatalf("后续假设缺少父漏洞或技术变体: %+v", items)
	}
}

func TestMainAddGoalAndIntentCreateWorkerQueueEntries(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_add_goal", map[string]interface{}{
		"title":  "获取服务器权限",
		"detail": "取得可复现的命令执行证据",
	}); err != nil {
		t.Fatalf("新增 Goal 失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title":    "验证上传链",
		"detail":   "检查上传入口与落盘路径",
		"priority": 90,
	}); err != nil {
		t.Fatalf("新增 Intent 失败: %v", err)
	}
	items, err := service.db.ListProjectHypotheses(ctx, "project-tools", "untested", 20)
	if err != nil {
		t.Fatalf("读取 Worker 队列失败: %v", err)
	}
	found := false
	for _, item := range items {
		if item.Dimension == "验证上传链" && item.IntentID != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Main 新增 Intent 未进入 Worker 队列: %+v", items)
	}
}

func TestLowConfidenceObservedFindingDoesNotSeedFollowUps(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	service.seedFollowUpHypotheses(ctx, "project-tools", database.Vulnerability{
		ID:                "finding-low-noise",
		ProjectID:         "project-tools",
		AssetID:           "asset-low-noise",
		Title:             "普通观察项",
		VulnerabilityType: "business-logic",
		Severity:          "medium",
		Status:            "open",
		VerificationState: "observed",
		Confidence:        60,
	})
	items, err := service.db.ListProjectHypotheses(ctx, "project-tools", "untested", 20)
	if err != nil {
		t.Fatalf("读取后续假设失败: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("低置信普通 finding 不应自动生成后续假设: %+v", items)
	}
}

func TestTerminalHighSeverityFindingDoesNotSeedFollowUps(t *testing.T) {
	for _, status := range []string{"fixed", "false_positive", "ignored", "closed", "dismissed", "resolved"} {
		if shouldGenerateFollowUps(database.Vulnerability{
			Status:            status,
			VerificationState: "verified",
			Severity:          "critical",
		}) {
			t.Fatalf("终止状态 %s 不应生成后续方向", status)
		}
	}
}

func TestUploadHypothesisRejectsBundledHandlers(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-upload-split", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "上传目标", Kind: "url", Value: "https://upload.example",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	_, err := invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[{
			"asset_id":"asset-upload-split",
			"dimension":"文件上传/覆盖写",
			"technique":"ScpSupRegHandler + FileUpload.ashx + MOBFileUpload 组合审计",
			"rationale":"多个上传入口需要一起审计",
			"expected_evidence":"所有入口 clean",
			"priority":90
		}]`,
	})
	if err == nil || !strings.Contains(err.Error(), "单独建立假设") {
		t.Fatalf("多个高风险上传入口应被拒绝合并: %v", err)
	}
}

func TestUploadCleanEvidenceGate(t *testing.T) {
	superficial := "ScpSupRegHandler.SaveAttach 固定扩展名白名单（无 aspx/config）"
	if err := validateUploadCleanEvidence(superficial, superficial, []string{"fact:upload-matrix"}); err == nil ||
		!strings.Contains(err.Error(), "证据不足") {
		t.Fatalf("缺少方法级证据的上传 clean 必须被拒绝: %v", err)
	}
	vulnerable := "ScpSupRegHandler.ProcessRequest 未发现 Token/Session 鉴权；SaveAttach IL_02A0 使用 Request.Files.FileName，IL_02BC 调用 SaveAs；Path.Combine 后无 GetFullPath 根目录约束；扩展名白名单不含 aspx"
	vulnerableEvidence := "handler IL_0000 至 IL_02BC，入口文件 Common.config:350；目录参数 dbId_v/FID 需继续验证路径穿越"
	if err := validateUploadCleanEvidence(vulnerable, vulnerableEvidence, []string{"artifact:out/scpsupreg.ann.il"}); err == nil ||
		!strings.Contains(err.Error(), "不能 tested_clean") {
		t.Fatalf("证据已显示未授权写入时不能标记 clean: %v", err)
	}
	safeResult := "FileUpload.ProcessRequest IL_0100 先校验 Token/Session；IL_0200 使用 Request.Files.FileName 后通过 GUID 随机改名；SaveAs 前执行 GetFullPath 并校验固定根目录；扩展名白名单仅允许 jpg/png"
	safeEvidence := "鉴权、文件名、路径、扩展名与 SaveAs Sink 已逐项闭合，入口 FileUpload.ashx:42"
	if err := validateUploadCleanEvidence(safeResult, safeEvidence, []string{"artifact:out/fileupload.ann.il"}); err != nil {
		t.Fatalf("具备完整负向证据的上传 clean 应通过: %v", err)
	}
}

func TestCompleteHypothesisRejectsScpSupSuperficialClean(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-scpsup-clean", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "SRM 上传", Kind: "url", Value: "https://scpsup.example",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[{
			"asset_id":"asset-scpsup-clean",
			"dimension":"文件上传/ScpSupRegHandler",
			"technique":"未授权上传与路径审计",
			"rationale":"Common.config 暴露 SRM/ScpSupRegHandler",
			"expected_evidence":"ProcessRequest 鉴权、SaveAttach IL 和落盘路径",
			"priority":95
		}]`,
	}); err != nil {
		t.Fatalf("创建上传假设失败: %v", err)
	}
	items, err := service.db.ListProjectHypotheses(ctx, "project-tools", "untested", 10)
	if err != nil || len(items) == 0 {
		t.Fatalf("读取上传假设失败: %+v err=%v", items, err)
	}
	hypothesisID := items[0].ID
	if _, err := invokeProjectTool(t, service, ctx, "project_start_hypothesis", map[string]interface{}{
		"hypothesis_id": hypothesisID,
	}); err != nil {
		t.Fatalf("领取上传假设失败: %v", err)
	}
	_, err = invokeProjectTool(t, service, ctx, "project_complete_hypothesis", map[string]interface{}{
		"hypothesis_id": hypothesisID,
		"status":        "tested_clean",
		"result":        "ScpSupRegHandler 扩展名白名单没有 aspx，因此安全",
		"evidence":      "仅检查扩展名白名单",
		"evidence_refs": []string{"fact:upload-matrix"},
		"confidence":    82,
	})
	if err == nil || !strings.Contains(err.Error(), "证据不足") {
		t.Fatalf("浅层上传结论必须被拒绝: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_complete_hypothesis", map[string]interface{}{
		"hypothesis_id": hypothesisID,
		"status":        "suspicious",
		"result":        "未授权上传和路径控制仍需方法级补证",
		"evidence":      "已发现 SaveAttach 使用原始文件名，尚未闭合完整调用链",
		"confidence":    80,
	}); err != nil {
		t.Fatalf("证据不足时应允许标记 suspicious: %v", err)
	}
}

func TestRequalifyLegacyUploadCleanHypotheses(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-upload-requalify", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "上传历史复核", Kind: "url", Value: "https://upload-requalify.example",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	superficial, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID:    "project-tools",
		AssetID:      "asset-upload-requalify",
		Dimension:    "文件上传/ScpSupRegHandler",
		Technique:    "历史 clean",
		Status:       "tested_clean",
		Result:       "扩展名白名单没有 aspx，因此安全",
		Evidence:     "仅检查白名单",
		EvidenceRefs: []string{"fact:upload-matrix"},
		Confidence:   82,
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("创建历史 clean 失败: %v", err)
	}
	safe, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID: "project-tools",
		AssetID:   "asset-upload-requalify",
		Dimension: "文件上传/FileUpload.ashx",
		Technique: "完整负向证据",
		Status:    "tested_clean",
		Result:    "FileUpload.ProcessRequest IL_0100 校验 Token；IL_0200 使用 Request.Files.FileName 后随机改名；SaveAs 前 GetFullPath 校验根目录；扩展名白名单",
		Evidence:  "鉴权、文件名、路径、扩展名和 Sink 已闭合，FileUpload.ashx:42",
		EvidenceRefs: []string{
			"artifact:out/fileupload.ann.il",
		},
		Confidence: 88,
		CreatedAt:  now.Add(time.Millisecond),
	})
	if err != nil {
		t.Fatalf("创建完整 clean 失败: %v", err)
	}
	nonUpload, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID:    "project-tools",
		AssetID:      "asset-upload-requalify",
		Dimension:    "反序列化",
		Technique:    "Web.config handler 面盘点，包含 UploadFiles 字样",
		Status:       "tested_clean",
		Result:       "反序列化面已闭合",
		Evidence:     "仅说明配置面，与该规则无关",
		EvidenceRefs: []string{"fact:deserialization-matrix"},
		Confidence:   88,
		CreatedAt:    now.Add(2 * time.Millisecond),
	})
	if err != nil {
		t.Fatalf("创建非上传 clean 失败: %v", err)
	}
	requalified, err := service.RequalifyLegacyUploadCleanHypotheses(ctx)
	if err != nil || requalified != 1 {
		t.Fatalf("历史上传 clean 复核失败: count=%d err=%v", requalified, err)
	}
	superficialAfter, err := service.db.GetProjectTestResultByID(ctx, "project-tools", superficial.ID)
	if err != nil || superficialAfter.Status != "suspicious" {
		t.Fatalf("浅层 clean 应降级为 suspicious: %+v err=%v", superficialAfter, err)
	}
	safeAfter, err := service.db.GetProjectTestResultByID(ctx, "project-tools", safe.ID)
	if err != nil || safeAfter.Status != "tested_clean" {
		t.Fatalf("完整 clean 不应被降级: %+v err=%v", safeAfter, err)
	}
	nonUploadAfter, err := service.db.GetProjectTestResultByID(ctx, "project-tools", nonUpload.ID)
	if err != nil || nonUploadAfter.Status != "tested_clean" {
		t.Fatalf("非上传假设不应被历史门禁降级: %+v err=%v", nonUploadAfter, err)
	}
}

func TestRepeatedAssetAccessFailuresBlockAllAssetIntents(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-access-block", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "WAF 目标", Kind: "url", Value: "https://waf.example/",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[
			{"asset_id":"asset-access-block","dimension":"入口 A","technique":"http","rationale":"验证入口 A","expected_evidence":"请求结果","priority":90},
			{"asset_id":"asset-access-block","dimension":"入口 B","technique":"http","rationale":"验证入口 B","expected_evidence":"请求结果","priority":80},
			{"asset_id":"asset-access-block","dimension":"入口 C","technique":"http","rationale":"验证入口 C","expected_evidence":"请求结果","priority":70}
		]`,
	})
	if err != nil || !strings.Contains(out, "写入 3 个") {
		t.Fatalf("规划假设失败: %q err=%v", out, err)
	}
	items, err := service.db.ListProjectHypotheses(ctx, "project-tools", "untested", 10)
	if err != nil || len(items) != 3 {
		t.Fatalf("读取假设失败: %+v err=%v", items, err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_complete_hypothesis", map[string]interface{}{
		"hypothesis_id": items[0].ID,
		"status":        "blocked",
		"block_kind":    "waf",
		"state_reason":  "请求被 WAF Challenge 拦截",
		"result":        "入口 A 返回 WAF Challenge",
	}); err != nil {
		t.Fatalf("第一次阻断写回失败: %v", err)
	}
	work, err := service.db.GetProjectAssetWork(ctx, "project-tools", "user-1", "asset-access-block")
	if err != nil {
		t.Fatalf("读取资产工作项失败: %v", err)
	}
	if work != nil && work.WorkState == database.AssetWorkBlocked {
		t.Fatalf("单次阻断不应直接阻断资产: %+v", work)
	}
	var runningWorkerCancelled bool
	runningWorker := service.registerWorkerControl("conv-tools", items[2].ID, func() {
		runningWorkerCancelled = true
	})
	runningWorker.bindAsset("project-tools", "asset-access-block")
	out, err = invokeProjectTool(t, service, ctx, "project_complete_hypothesis", map[string]interface{}{
		"hypothesis_id": items[1].ID,
		"status":        "blocked",
		"block_kind":    "target_unreachable",
		"state_reason":  "连接目标持续超时",
		"result":        "入口 B 连续连接超时",
	})
	if err != nil || !strings.Contains(out, "已阻断该资产 3 个未完成意图") {
		t.Fatalf("第二次阻断未触发资产熔断: %q err=%v", out, err)
	}
	if !runningWorkerCancelled {
		t.Fatal("资产级阻断后应取消同资产运行中的 Worker")
	}
	work, err = service.db.GetProjectAssetWork(ctx, "project-tools", "user-1", "asset-access-block")
	if err != nil || work == nil || work.WorkState != database.AssetWorkBlocked {
		t.Fatalf("资产工作项应被阻断: %+v err=%v", work, err)
	}
	if !strings.Contains(work.StateReason, "连续 2 次访问受阻") {
		t.Fatalf("资产阻断原因不完整: %q", work.StateReason)
	}
	nodes, err := service.db.ListProjectGraphNodesByAsset(ctx, "project-tools", "asset-access-block")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	intentCount := 0
	for _, node := range nodes {
		if node.Kind != "intent" {
			continue
		}
		intentCount++
		if node.Status != "blocked" || !strings.Contains(node.Detail, "资产连续 2 次访问受阻") {
			t.Fatalf("资产内意图应全部阻断并注明原因: %+v", node)
		}
	}
	if intentCount != 3 {
		t.Fatalf("意图数量异常: %d", intentCount)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_complete_hypothesis", map[string]interface{}{
		"hypothesis_id": items[2].ID,
		"status":        "tested_clean",
		"result":        "运行中的 Worker 完成了当前请求",
		"evidence":      "HTTP 200",
	}); err != nil {
		t.Fatalf("运行中假设完成失败: %v", err)
	}
	inFlightIntent, err := service.db.GetProjectGraphNode(ctx, items[2].IntentID, "project-tools")
	if err != nil || inFlightIntent == nil || inFlightIntent.Status != "blocked" {
		t.Fatalf("资产阻断后运行中的 Worker 不应重新打开意图: %+v err=%v", inFlightIntent, err)
	}
	out, err = invokeProjectTool(t, service, ctx, "project_plan_hypotheses", map[string]interface{}{
		"hypotheses_json": `[{"asset_id":"asset-access-block","dimension":"入口 D","technique":"http","rationale":"不应继续规划","expected_evidence":"请求结果"}]`,
	})
	if err != nil || !strings.Contains(out, "跳过 1 个") {
		t.Fatalf("已阻断资产不应继续规划: %q err=%v", out, err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title":    "不应新增的意图",
		"asset_id": "asset-access-block",
	}); err == nil || !strings.Contains(err.Error(), "资产级访问阻断") {
		t.Fatalf("已阻断资产不应允许新增意图: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_sync_graph", map[string]interface{}{}); err != nil {
		t.Fatalf("同步攻击路径失败: %v", err)
	}
	nodes, err = service.db.ListProjectGraphNodesByAsset(ctx, "project-tools", "asset-access-block")
	if err != nil {
		t.Fatalf("重新读取攻击路径失败: %v", err)
	}
	for _, node := range nodes {
		if node.Source == "blocked-follow-up" {
			t.Fatalf("资产级阻断后不应派生普通替代意图: %+v", node)
		}
	}
}

func TestStaleAccessFailuresDoNotBlockAsset(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-stale-access", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "陈旧阻断目标", Kind: "url", Value: "https://stale.example/",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	for index, item := range []struct {
		id        string
		intentID  string
		dimension string
	}{
		{id: "stale-test-a", intentID: "stale-intent-a", dimension: "陈旧入口 A"},
		{id: "stale-test-b", intentID: "stale-intent-b", dimension: "陈旧入口 B"},
	} {
		if _, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
			ID:          item.id,
			ProjectID:   "project-tools",
			AssetID:     "asset-stale-access",
			Dimension:   item.dimension,
			Technique:   "http",
			Status:      "blocked",
			StateReason: formatAccessBlockStateReason("waf", "历史 WAF 拦截", ""),
			Result:      "历史 WAF 拦截",
			IntentID:    item.intentID,
			CreatedAt:   now.Add(-time.Duration(index+1) * time.Hour),
			UpdatedAt:   now.Add(-time.Duration(index+1) * time.Hour),
		}); err != nil {
			t.Fatalf("创建陈旧测试结果失败: %v", err)
		}
		staleAt := now.Add(-11 * time.Minute).Unix()
		if _, err := service.db.ExecContext(
			ctx,
			`UPDATE project_test_results SET last_finished_at = ?, updated_at = ? WHERE id = ?`,
			staleAt,
			staleAt,
			item.id,
		); err != nil {
			t.Fatalf("更新陈旧时间失败: %v", err)
		}
	}
	blocked, _, err := service.blockAssetAfterRepeatedAccessFailure(
		ctx,
		"project-tools",
		"user-1",
		"asset-stale-access",
	)
	if err != nil {
		t.Fatalf("检查陈旧资产阻断失败: %v", err)
	}
	if blocked {
		t.Fatal("超过时间窗口的历史失败不应触发资产阻断")
	}
}

func TestUserStoppedAssetCannotOverwriteStoppedHypothesis(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-user-stopped-writeback", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "用户停止写回", Kind: "url", Value: "https://user-stop.example/",
		Status: "active", Criticality: "high", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	item, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID:   "project-tools",
		AssetID:     "asset-user-stopped-writeback",
		Dimension:   "已停止测试",
		Technique:   "http",
		Status:      "stopped",
		StateReason: database.AssetUserStopReason,
		IntentID:    "intent-user-stopped-writeback",
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("创建已停止测试失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_complete_hypothesis", map[string]interface{}{
		"hypothesis_id": item.ID,
		"status":        "tested_clean",
		"result":        "不应覆盖停止状态",
		"evidence":      "HTTP 200",
	}); err == nil || !strings.Contains(err.Error(), "用户停止探测") {
		t.Fatalf("用户停止资产后不应允许覆盖测试状态: %v", err)
	}
}
