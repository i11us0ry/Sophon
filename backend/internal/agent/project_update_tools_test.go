package agent

import (
	"strings"
	"testing"

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
		"goal_id": goalID, "status": "met", "detail": "已由工具验证完成",
	})
	if err != nil {
		t.Fatalf("更新目标失败: %v", err)
	}
	if !strings.Contains(out, "status met") {
		t.Fatalf("更新结果异常: %q", out)
	}
	node, err := service.db.GetProjectGraphNode(ctx, goalID, "project-tools")
	if err != nil || node.Status != "met" || node.Detail != "已由工具验证完成" {
		t.Fatalf("目标未更新: %+v, err=%v", node, err)
	}

	if _, err := invokeProjectTool(t, service, ctx, "project_update_goal", map[string]interface{}{
		"goal_id": goalID, "status": "invalid",
	}); err == nil {
		t.Fatalf("非法目标状态应被拒绝")
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
		"poc":           "id=1 AND 1=2",
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
		item.ReproductionSteps != "id=1 AND 1=2" ||
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
