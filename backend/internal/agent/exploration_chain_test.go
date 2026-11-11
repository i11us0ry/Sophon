package agent

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestExplorationChainPersistsExplicitRelations(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID:          "asset-chain",
		ProjectID:   "project-tools",
		OwnerUserID: "user-1",
		Name:        "链路测试资产",
		Kind:        "url",
		Value:       "https://chain.example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	goal, err := service.db.UpsertProjectGraphNode(ctx, database.GraphNode{
		ID:         "goal-chain",
		ProjectID:  "project-tools",
		Kind:       "goal",
		Title:      "验证链路目标",
		Status:     "open",
		Confidence: 90,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("创建目标失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"asset_id": "asset-chain",
		"key":      "endpoint",
		"summary":  "发现可测试接口",
	}); err != nil {
		t.Fatalf("记录来源事实失败: %v", err)
	}
	facts, err := service.db.ListProjectFacts(ctx, "project-tools")
	if err != nil || len(facts) != 1 {
		t.Fatalf("读取来源事实失败: %+v, err=%v", facts, err)
	}
	sourceFactID := facts[0].ID

	if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"asset_id":         "asset-chain",
		"title":            "验证 SQL 注入",
		"goal_id":          goal.ID,
		"source_fact_id":   sourceFactID,
		"success_criteria": "获得可复现的注入证据",
	}); err != nil {
		t.Fatalf("写入意图失败: %v", err)
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	intentID := ""
	sourceFactNodeID := ""
	for _, node := range nodes {
		if node.Kind == "intent" && node.Title == "验证 SQL 注入" {
			intentID = node.ID
		}
		if node.Kind == "fact" && node.SourceRefID == sourceFactID {
			sourceFactNodeID = node.ID
		}
	}
	if intentID == "" {
		t.Fatalf("未找到意图节点: %+v", nodes)
	}
	if sourceFactNodeID == "" {
		t.Fatalf("未找到来源事实节点: %+v", nodes)
	}

	if _, err := invokeProjectTool(t, service, ctx, "project_record_fact", map[string]interface{}{
		"asset_id":  "asset-chain",
		"intent_id": intentID,
		"key":       "chain/sql-result",
		"summary":   "SQL 注入验证成功",
	}); err != nil {
		t.Fatalf("记录结果事实失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_sync_graph", map[string]interface{}{}); err != nil {
		t.Fatalf("同步攻击路径失败: %v", err)
	}
	nodes, err = service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("重新读取攻击路径失败: %v", err)
	}
	factNodeID := ""
	for _, node := range nodes {
		if node.Kind == "fact" && node.Title == "chain/sql-result" {
			factNodeID = node.ID
			break
		}
	}
	if factNodeID == "" {
		t.Fatalf("未找到结果事实节点: %+v", nodes)
	}

	edges, err := service.db.ListProjectGraphEdges(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径连线失败: %v", err)
	}
	for _, want := range []database.GraphEdge{
		{SrcID: goal.ID, DstID: intentID, Rel: "spawns"},
		{SrcID: sourceFactNodeID, DstID: intentID, Rel: "derived_from"},
		{SrcID: intentID, DstID: factNodeID, Rel: "yields"},
	} {
		if !hasGraphEdge(edges, want) {
			t.Fatalf("缺少显式链路 %s --%s--> %s: %+v", want.SrcID, want.Rel, want.DstID, edges)
		}
		if !hasGraphNode(nodes, want.SrcID) || !hasGraphNode(nodes, want.DstID) {
			t.Fatalf("链路存在悬空节点 %s --%s--> %s: %+v", want.SrcID, want.Rel, want.DstID, edges)
		}
	}
}

func TestFindingSpawnsFollowUpIntents(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title": "验证 SQL 注入",
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
			break
		}
	}
	if intentID == "" {
		t.Fatalf("未找到意图节点: %+v", nodes)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title":         "SQL 注入",
		"severity":      "high",
		"target":        "https://chain.example.com/item?id=1",
		"poc":           "id=1 AND 1=1",
		"evidence_refs": []string{completedToolRef(t, service, ctx, "sqlmap")},
		"intent_id":     intentID,
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
	finding := findings[0]
	if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"asset_id":          finding.AssetID,
		"title":             "验证漏洞后续利用",
		"source_finding_id": finding.ID,
	}); err != nil {
		t.Fatalf("从漏洞派生意图失败: %v", err)
	}
	nodes, err = service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("重新读取攻击路径失败: %v", err)
	}
	findingNodeID := ""
	derivedIntentID := ""
	followUps := make(map[string]database.GraphNode)
	for _, node := range nodes {
		if node.Kind == "finding" && node.SourceRefID == finding.ID {
			findingNodeID = node.ID
		}
		if node.Kind == "intent" && node.Title == "验证漏洞后续利用" {
			derivedIntentID = node.ID
		}
		if node.Kind == "intent" && node.Source == "finding-follow-up" {
			followUps[node.ID] = node
		}
	}
	if findingNodeID == "" {
		t.Fatalf("未找到漏洞节点: %+v", nodes)
	}
	if derivedIntentID == "" {
		t.Fatalf("未找到从漏洞派生的意图节点: %+v", nodes)
	}
	if len(followUps) == 0 || len(followUps) > maxFollowUpPerFinding {
		t.Fatalf("派生意图数量异常: %d", len(followUps))
	}
	edges, err := service.db.ListProjectGraphEdges(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径连线失败: %v", err)
	}
	if !hasGraphEdge(edges, database.GraphEdge{SrcID: intentID, DstID: findingNodeID, Rel: "yields"}) {
		t.Fatalf("缺少 intent->finding yields 边: %+v", edges)
	}
	if !hasGraphEdge(edges, database.GraphEdge{
		SrcID: findingNodeID,
		DstID: derivedIntentID,
		Rel:   "derived_from",
	}) {
		t.Fatalf("source_finding_id 应连接到漏洞图节点: %+v", edges)
	}
	if hasGraphEdge(edges, database.GraphEdge{
		SrcID: finding.ID,
		DstID: derivedIntentID,
		Rel:   "derived_from",
	}) {
		t.Fatalf("source_finding_id 不应直接使用业务漏洞 ID 建边: %+v", edges)
	}
	for intentNodeID := range followUps {
		if !hasGraphEdge(edges, database.GraphEdge{
			SrcID: findingNodeID,
			DstID: intentNodeID,
			Rel:   "derived_from",
		}) {
			t.Fatalf("缺少 finding->intent derived_from 边: %s", intentNodeID)
		}
	}
}

func TestFindingFollowUpRespectsProjectIntentCap(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	assetIDs := make([]string, 0, maxActiveIntentsPerProject/maxActiveIntentsPerAsset+1)
	for index := 0; index < maxActiveIntentsPerProject/maxActiveIntentsPerAsset+1; index++ {
		assetID := fmt.Sprintf("asset-intent-project-cap-%02d", index)
		assetIDs = append(assetIDs, assetID)
		if err := service.db.CreateAsset(ctx, database.Asset{
			ID:          assetID,
			ProjectID:   "project-tools",
			OwnerUserID: "user-1",
			Name:        fmt.Sprintf("项目级上限资产 %02d", index),
			Kind:        "url",
			Value:       fmt.Sprintf("https://intent-cap-%02d.example.com", index),
			Status:      "active",
			Criticality: "medium",
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			t.Fatalf("创建资产 %d 失败: %v", index, err)
		}
	}
	for index := 0; index < maxActiveIntentsPerProject; index++ {
		assetID := assetIDs[index/maxActiveIntentsPerAsset]
		if _, err := service.db.UpsertProjectGraphNode(ctx, database.GraphNode{
			ID:         fmt.Sprintf("intent-cap-%03d", index),
			ProjectID:  "project-tools",
			Kind:       "intent",
			Title:      fmt.Sprintf("项目级意图 %03d", index),
			Status:     "open",
			Confidence: 70,
			AssetID:    assetID,
			CreatedAt:  now,
			UpdatedAt:  now,
		}); err != nil {
			t.Fatalf("写入项目级意图 %d 失败: %v", index, err)
		}
	}
	findingAssetID := assetIDs[len(assetIDs)-1]
	finding := &database.Vulnerability{
		ID:                "finding-project-cap",
		ProjectID:         "project-tools",
		AssetID:           findingAssetID,
		OwnerUserID:       "user-1",
		Title:             "SQL 注入",
		VulnerabilityType: "SQL注入",
		Severity:          "high",
		Status:            "open",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := service.spawnFindingFollowUpIntents(ctx, "project-tools", finding); err != nil {
		t.Fatalf("项目级意图达到上限时不应报错: %v", err)
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	for _, node := range nodes {
		if node.Kind == "intent" && node.Source == "finding-follow-up" {
			t.Fatalf("达到项目级上限后不应继续派生意图: %+v", node)
		}
	}
}

func TestBlockedIntentSpawnsAlternative(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title": "验证受保护接口",
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
			break
		}
	}
	if intentID == "" {
		t.Fatalf("未找到意图节点: %+v", nodes)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_update_intent", map[string]interface{}{
		"intent_id": intentID,
		"status":    "blocked",
		"detail":    "WAF 持续拦截",
	}); err != nil {
		t.Fatalf("更新 blocked 意图失败: %v", err)
	}
	intent, err := service.db.GetProjectGraphNode(ctx, intentID, "project-tools")
	if err != nil || intent.Status != "blocked" {
		t.Fatalf("blocked 意图状态异常: %+v, err=%v", intent, err)
	}
	nodes, err = service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("重新读取攻击路径失败: %v", err)
	}
	alternativeID := ""
	for _, node := range nodes {
		if node.Kind == "intent" && node.Source == "blocked-follow-up" {
			alternativeID = node.ID
			break
		}
	}
	if alternativeID == "" {
		t.Fatalf("blocked 意图未派生替代路径: %+v", nodes)
	}
	edges, err := service.db.ListProjectGraphEdgesFromNode(ctx, "project-tools", intentID)
	if err != nil {
		t.Fatalf("读取派生边失败: %v", err)
	}
	if !hasGraphEdge(edges, database.GraphEdge{
		SrcID: intentID,
		DstID: alternativeID,
		Rel:   "derived_from",
	}) {
		t.Fatalf("缺少 blocked->alternative 派生边: %+v", edges)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_update_intent", map[string]interface{}{
		"intent_id": intentID,
		"status":    "blocked",
	}); err != nil {
		t.Fatalf("重复更新 blocked 意图失败: %v", err)
	}
	nodes, err = service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("重复更新后读取攻击路径失败: %v", err)
	}
	alternatives := 0
	for _, node := range nodes {
		if node.Kind == "intent" && node.Source == "blocked-follow-up" {
			alternatives++
		}
	}
	if alternatives != 1 {
		t.Fatalf("blocked 替代派生应保持幂等，实际 %d", alternatives)
	}
}

func TestRecoverBlockedIntentAlternatives(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateProjectGraphNode(ctx, database.GraphNode{
		ID:         "blocked-recovery",
		ProjectID:  "project-tools",
		Kind:       "intent",
		Title:      "历史 blocked 意图",
		Status:     "blocked",
		Confidence: 70,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("创建历史 blocked 意图失败: %v", err)
	}
	created, err := service.RecoverBlockedIntentAlternatives(ctx)
	if err != nil {
		t.Fatalf("恢复 blocked 意图失败: %v", err)
	}
	if created != 1 {
		t.Fatalf("历史 blocked 意图应派生 1 条替代路径，实际 %d", created)
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	found := false
	for _, node := range nodes {
		if node.Source == "blocked-follow-up" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("启动恢复未创建替代意图: %+v", nodes)
	}
}

func TestIntentSourceRejectsCrossAssetFact(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	for _, asset := range []database.Asset{
		{
			ID: "asset-source-a", ProjectID: "project-tools", OwnerUserID: "user-1",
			Name: "来源 A", Kind: "url", Value: "https://a.example.com",
			Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "asset-source-b", ProjectID: "project-tools", OwnerUserID: "user-1",
			Name: "来源 B", Kind: "url", Value: "https://b.example.com",
			Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
		},
	} {
		if err := service.db.CreateAsset(ctx, asset); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}
	fact, err := service.db.UpsertProjectFact(ctx, database.ProjectFact{
		ID: "fact-cross-asset", ProjectID: "project-tools", AssetID: "asset-source-b",
		FactType: "general", Key: "target/cross", Value: "B 资产事实", Summary: "B 资产事实",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建事实失败: %v", err)
	}
	_, err = invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title": "跨资产意图", "asset_id": "asset-source-a", "source_fact_id": fact.ID,
	})
	if err == nil || !strings.Contains(err.Error(), "不属于同一资产") {
		t.Fatalf("跨资产来源事实应被拒绝: %v", err)
	}
}

func TestIntentSourceRejectsArchivedFact(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	fact, err := service.db.UpsertProjectFact(ctx, database.ProjectFact{
		ID: "fact-archived", ProjectID: "project-tools", FactType: "general",
		Key: "target/archived", Value: "已归档", Summary: "已归档",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建事实失败: %v", err)
	}
	if _, err := service.db.ExecContext(
		ctx,
		`UPDATE project_facts SET valid_to = ?, superseded_by = ? WHERE id = ?`,
		now.Unix(),
		"newer-fact",
		fact.ID,
	); err != nil {
		t.Fatalf("归档事实失败: %v", err)
	}
	_, err = invokeProjectTool(t, service, ctx, "project_add_intent", map[string]interface{}{
		"title": "归档事实意图", "source_fact_id": fact.ID,
	})
	if err == nil || !strings.Contains(err.Error(), "已失效") {
		t.Fatalf("归档事实不应作为活跃来源: %v", err)
	}
}

func TestFindingFollowUpDoesNotReopenTerminalIntent(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title": "SQL 注入", "severity": "high", "target": "https://a.com/x?id=1",
		"poc": "id=1 AND 1=1", "evidence_refs": []string{completedToolRef(t, service, ctx, "sqlmap")},
	})); err != nil {
		t.Fatalf("上报漏洞失败: %v", err)
	}
	nodes, err := service.db.ListProjectGraphNodes(ctx, "project-tools")
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	followUpID := ""
	for _, node := range nodes {
		if node.Kind == "intent" && node.Source == "finding-follow-up" {
			followUpID = node.ID
			break
		}
	}
	if followUpID == "" {
		t.Fatalf("未找到漏洞后续意图: %+v", nodes)
	}
	followUp, err := service.db.GetProjectGraphNode(ctx, followUpID, "project-tools")
	if err != nil {
		t.Fatalf("读取后续意图失败: %v", err)
	}
	followUp.Status = "done"
	if err := service.db.UpdateProjectGraphNode(ctx, *followUp); err != nil {
		t.Fatalf("完成后续意图失败: %v", err)
	}
	if _, err := invokeProjectTool(t, service, ctx, "project_report_finding", standardFindingArgs(map[string]interface{}{
		"title": "SQL 注入", "severity": "high", "target": "https://a.com/x?id=1",
		"poc": "id=1 AND 1=1", "evidence_refs": []string{completedToolRef(t, service, ctx, "sqlmap")},
	})); err != nil {
		t.Fatalf("重复上报漏洞失败: %v", err)
	}
	followUp, err = service.db.GetProjectGraphNode(ctx, followUpID, "project-tools")
	if err != nil {
		t.Fatalf("重新读取后续意图失败: %v", err)
	}
	if followUp.Status != "done" {
		t.Fatalf("重复上报不应重开已完成后续意图: %+v", followUp)
	}
}

func TestBlockedIntentWithTerminalChildStillSpawnsAlternative(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	blocked := database.GraphNode{
		ID: "blocked-parent", ProjectID: "project-tools", Kind: "intent",
		Title: "阻塞父意图", Status: "blocked", CreatedAt: now, UpdatedAt: now,
	}
	doneChild := database.GraphNode{
		ID: "done-child", ProjectID: "project-tools", Kind: "intent",
		Title: "已结束子意图", Status: "done", CreatedAt: now, UpdatedAt: now,
	}
	if _, err := service.db.UpsertProjectGraphNode(ctx, blocked); err != nil {
		t.Fatalf("创建阻塞意图失败: %v", err)
	}
	if _, err := service.db.UpsertProjectGraphNode(ctx, doneChild); err != nil {
		t.Fatalf("创建子意图失败: %v", err)
	}
	if err := service.db.CreateProjectGraphEdge(ctx, database.GraphEdge{
		ID: "blocked-to-done", ProjectID: "project-tools",
		SrcID: blocked.ID, DstID: doneChild.ID, Rel: "derived_from", CreatedAt: now,
	}); err != nil {
		t.Fatalf("创建派生边失败: %v", err)
	}
	created, err := service.spawnBlockedIntentAlternatives(ctx, "project-tools", &blocked)
	if err != nil {
		t.Fatalf("派生替代路径失败: %v", err)
	}
	if created != 1 {
		t.Fatalf("终态子节点不能算有效替代，应新建 1 条，实际 %d", created)
	}
}

func TestBlockedIntentMarksCapacityBlockedWhenQuotaFull(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	now := time.Now().UTC()
	if err := service.db.CreateAsset(ctx, database.Asset{
		ID: "asset-capacity-blocked", ProjectID: "project-tools", OwnerUserID: "user-1",
		Name: "容量测试", Kind: "url", Value: "https://capacity.example.com",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	for index := 0; index < maxActiveIntentsPerAsset; index++ {
		if _, err := service.db.UpsertProjectGraphNode(ctx, database.GraphNode{
			ID:        fmt.Sprintf("open-capacity-%02d", index),
			ProjectID: "project-tools",
			Kind:      "intent",
			Title:     fmt.Sprintf("占用额度 %02d", index),
			Status:    "open",
			AssetID:   "asset-capacity-blocked",
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			t.Fatalf("创建活跃意图失败: %v", err)
		}
	}
	blocked := database.GraphNode{
		ID: "blocked-capacity", ProjectID: "project-tools", Kind: "intent",
		Title: "容量阻塞意图", Status: "blocked", AssetID: "asset-capacity-blocked",
		CreatedAt: now, UpdatedAt: now,
	}
	if _, err := service.db.UpsertProjectGraphNode(ctx, blocked); err != nil {
		t.Fatalf("创建阻塞意图失败: %v", err)
	}
	if _, err := service.spawnBlockedIntentAlternatives(ctx, "project-tools", &blocked); err != nil {
		t.Fatalf("容量满时派生不应报错: %v", err)
	}
	stored, err := service.db.GetProjectGraphNode(ctx, blocked.ID, "project-tools")
	if err != nil {
		t.Fatalf("读取阻塞意图失败: %v", err)
	}
	if stored.Status != "capacity_blocked" {
		t.Fatalf("容量满时应标记 capacity_blocked: %+v", stored)
	}
}

func hasGraphEdge(edges []database.GraphEdge, want database.GraphEdge) bool {
	for _, edge := range edges {
		if edge.SrcID == want.SrcID && edge.DstID == want.DstID && edge.Rel == want.Rel {
			return true
		}
	}
	return false
}

func hasGraphNode(nodes []database.GraphNode, id string) bool {
	for _, node := range nodes {
		if node.ID == id {
			return true
		}
	}
	return false
}
