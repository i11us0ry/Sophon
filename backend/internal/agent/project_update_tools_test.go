package agent

import (
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

func TestProjectUpdateIntentTool(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title": "信息收集", "status": "open",
	}); err != nil {
		t.Fatalf("写入意图失败: %v", err)
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	intentID := ""
	for _, node := range nodes {
		if node.Kind == "intent" {
			intentID = node.ID
		}
	}
	if intentID == "" {
		t.Fatalf("未找到意图节点: %+v", nodes)
	}

	out, err := invokeProjectTool(t, service, ctx, "project_update_intent", map[string]interface{}{
		"intent_id": intentID, "status": "running", "detail": "开始扫描端口",
	})
	if err != nil {
		t.Fatalf("更新意图失败: %v", err)
	}
	if !strings.Contains(out, "已更新") {
		t.Fatalf("更新结果异常: %q", out)
	}
	node, err := service.db.GetProjectGraphNode(ctx, intentID, "project-tools")
	if err != nil || node.Status != "running" || node.Detail != "开始扫描端口" {
		t.Fatalf("意图未更新: %+v, err=%v", node, err)
	}

	if _, err := invokeProjectTool(t, service, ctx, "project_update_intent", map[string]interface{}{
		"intent_id": intentID, "status": "invalid",
	}); err == nil {
		t.Fatalf("非法状态应被拒绝")
	}
}

func TestProjectUpdateGoalTool(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_sync_graph", map[string]interface{}{}); err != nil {
		t.Fatalf("同步攻击路径失败: %v", err)
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	goalID := ""
	for _, node := range nodes {
		if node.Kind == "goal" {
			goalID = node.ID
			break
		}
	}
	if goalID == "" {
		t.Fatalf("未找到目标节点: %+v", nodes)
	}

	out, err := invokeProjectTool(t, service, ctx, "project_update_goal", map[string]interface{}{
		"goal_id": goalID, "status": "abandoned", "detail": "目标不再适用",
	})
	if err != nil {
		t.Fatalf("更新目标失败: %v", err)
	}
	if !strings.Contains(out, "status abandoned") {
		t.Fatalf("更新结果异常: %q", out)
	}
	node, err := service.db.GetProjectGraphNode(ctx, goalID, "project-tools")
	if err != nil || node.Status != "abandoned" || node.Detail != "目标不再适用" {
		t.Fatalf("目标未更新: %+v, err=%v", node, err)
	}

	if _, err := invokeProjectTool(t, service, ctx, "project_update_goal", map[string]interface{}{
		"goal_id": goalID, "status": "met", "detail": "绕过证据直接完成",
	}); err == nil || !strings.Contains(err.Error(), "project_prove_goal") {
		t.Fatalf("直接标记 Goal met 应被拒绝: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_update_goal", map[string]interface{}{
		"goal_id": goalID, "status": "invalid",
	}); err == nil {
		t.Fatalf("非法目标状态应被拒绝")
	}
}

func TestProjectProveGoalRequiresConfirmedEvidence(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	for _, node := range []database.GraphNode{
		{
			ID: "goal-prove", ProjectID: "project-tools", Kind: "goal",
			Title: "证明目标", Status: "open", Confidence: 80,
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "fact-prove", ProjectID: "project-tools", Kind: "fact",
			Title: "确认证据", Detail: "真实执行结果", Status: "confirmed",
			Confidence: 95, CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := service.db.CreateProjectGraphNode(ctx, node); err != nil {
			t.Fatalf("创建证据节点失败: %v", err)
		}
	}

	if _, err := invokeProjectTool(t, service, ctx, "project_prove_goal", map[string]interface{}{
		"goal_id": "goal-prove", "evidence_id": "missing-evidence",
		"reason": "不存在证据",
	}); err == nil {
		t.Fatal("不存在的证据不应证明 Goal")
	}
	out, err := invokeProjectTool(t, service, ctx, "project_prove_goal", map[string]interface{}{
		"goal_id": "goal-prove", "evidence_id": "fact-prove",
		"reason": "确认证据直接证明目标结果",
	})
	if err != nil || !strings.Contains(out, "status met") {
		t.Fatalf("证明 Goal 失败: %q err=%v", out, err)
	}
	goal, err := service.db.GetProjectGraphNode(ctx, "goal-prove", "project-tools")
	if err != nil || goal.Status != "met" || !strings.Contains(goal.Detail, "fact-prove") {
		t.Fatalf("Goal 未更新为 met: %+v err=%v", goal, err)
	}
	edges, err := service.db.ListProjectGraphEdges(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取证据连线失败: %v", err)
	}
	found := false
	for _, edge := range edges {
		if edge.SrcID == "fact-prove" && edge.DstID == "goal-prove" && edge.Rel == "proves" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("缺少 evidence -> Goal 的 proves 连线: %+v", edges)
	}
}

func TestProjectProveGoalRejectsActiveRequiredHypotheses(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	for _, node := range []database.GraphNode{
		{
			ID: "goal-required", ProjectID: "project-tools", Kind: "goal",
			Title: "等待必需任务", Status: "open", Confidence: 80,
			CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "fact-required", ProjectID: "project-tools", Kind: "fact",
			Title: "候选证据", Status: "confirmed", Confidence: 95,
			CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := service.db.CreateProjectGraphNode(ctx, node); err != nil {
			t.Fatalf("创建 Goal 测试节点失败: %v", err)
		}
	}
	item, err := service.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
		ProjectID: "project-tools", Dimension: "仍运行的必需任务",
		Technique: "required", Status: "untested", Required: true,
		OriginConversationID: "conv-tools", CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建必需任务失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_prove_goal", map[string]interface{}{
		"goal_id": "goal-required", "evidence_id": "fact-required",
		"reason": "尝试提前证明",
	}); err == nil || !strings.Contains(err.Error(), "必需任务") {
		t.Fatalf("存在必需任务时不应允许证明 Goal: %v", err)
	}
	item.Status = "tested_clean"
	item.ExecutionState = ""
	item.OutcomeState = ""
	item.Result = "必需任务已收敛"
	if _, err := service.db.UpsertProjectTestResult(ctx, *item); err != nil {
		t.Fatalf("完成必需任务失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_prove_goal", map[string]interface{}{
		"goal_id": "goal-required", "evidence_id": "fact-required",
		"reason": "必需任务已全部完成",
	}); err != nil {
		t.Fatalf("必需任务完成后应允许证明 Goal: %v", err)
	}
}

func TestProjectUpdateFindingTool(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title": "SQL 注入", "severity": "high",
		"target": "https://a.com/login?id=1",
		"poc":    "id=1 AND 1=1", "impact": "数据库数据泄露",
		"evidence":      "HTTP 200，注入回显",
		"evidence_refs": []string{completedToolRef(t, service, ctx, "sqlmap")},
	})); err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	findings, _, err := service.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Limit:       10,
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("读取漏洞失败: %+v, err=%v", findings, err)
	}
	findingID := findings[0].ID

	if _, err := invokeProjectTool(t, service, ctx, "project_update_finding", map[string]interface{}{
		"finding_id":    findingID,
		"status":        "fixed",
		"poc":           "```http\nGET /item?id=1%20AND%201=2 HTTP/1.1\nHost: evidence.example\n```\n\n```python\nimport requests\nprint(requests.get('https://evidence.example/item?id=1', timeout=10).status_code)\n```",
		"impact":        "修复前可读取数据库数据",
		"evidence_refs": []string{completedToolRef(t, service, ctx, "retest")},
		"retest_notes":  "已验证修复",
	}); err != nil {
		t.Fatalf("更新漏洞失败: %v", err)
	}
	item, err := service.db.GetVulnerability(ctx, findingID, "user-1")
	if err != nil ||
		item.Status != "fixed" ||
		item.AssetID == "" ||
		!strings.Contains(item.ReproductionSteps, "```python") ||
		item.Impact != "修复前可读取数据库数据" ||
		len(item.EvidenceRefs) != 1 ||
		!strings.HasPrefix(item.EvidenceRefs[0], "tool:") ||
		item.RetestNotes != "已验证修复" {
		t.Fatalf("漏洞未更新: %+v, err=%v", item, err)
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	for _, node := range nodes {
		if node.Kind == "finding" && node.SourceRefID == item.ID && node.Status != "dismissed" {
			t.Fatalf("已修复漏洞的 finding 节点应变为 dismissed: %+v", node)
		}
	}
}

func TestProjectRetestFindingTool(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title": "复测工具验证", "severity": "high",
		"target":        "https://example.com/retest",
		"poc":           "curl /retest?id=1 AND 1=1",
		"evidence":      "HTTP 200，注入回显",
		"evidence_refs": []string{completedToolRef(t, service, ctx, "sqlmap")},
	})); err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	findings, _, err := service.db.ListVulnerabilitiesFiltered(ctx, database.VulnerabilityFilter{
		OwnerUserID: "user-1",
		ProjectID:   "project-tools",
		Limit:       10,
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("读取漏洞失败: %+v err=%v", findings, err)
	}
	run, err := service.db.CreateVulnerabilityRetestRun(
		ctx,
		findings[0].ID,
		"user-1",
		execctx.ConversationID(ctx),
		nil,
	)
	if err != nil {
		t.Fatalf("创建复测运行失败: %v", err)
	}
	out, err := invokeProjectTool(t, service, ctx, "project_retest_finding", map[string]interface{}{
		"retest_id": run.ID,
		"result":    "fixed",
		"notes":     "重新执行原 POC 已无法复现",
		"evidence":  "HTTP 200，无注入回显",
	})
	if err != nil || !strings.Contains(out, "fixed") {
		t.Fatalf("提交复测工具结果失败: %q err=%v", out, err)
	}
	item, err := service.db.GetVulnerability(ctx, findings[0].ID, "user-1")
	if err != nil || item.Status != "fixed" {
		t.Fatalf("复测工具未更新漏洞: %+v err=%v", item, err)
	}
}
