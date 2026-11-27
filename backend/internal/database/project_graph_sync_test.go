package database

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openGraphSyncTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "graph-sync.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestFactMaterializationIncludesTestedAuditCells(t *testing.T) {
	if !factMaterializationValue(ProjectFact{
		SubjectType: "audit_cell",
		ObjectKey:   "tested",
	}) {
		t.Fatal("已测试审计单元应进入攻击路径候选")
	}
	if factMaterializationValue(ProjectFact{
		SubjectType: "audit_cell",
		ObjectKey:   "not_audited",
	}) {
		t.Fatal("未审计单元不应作为攻击路径证据")
	}
}

func TestGraphFindingStatusFailsClosedForUnknownValues(t *testing.T) {
	if got := graphFindingStatus("future-unknown-status"); got != "open" {
		t.Fatalf("未知漏洞状态不应默认确认，实际 %s", got)
	}
	if got := graphFindingStatus("confirmed"); got != "confirmed" {
		t.Fatalf("confirmed 应保持确认状态，实际 %s", got)
	}
}

func TestSyncProjectGraphCreatesSkeletonAndBackfill(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "proj-sync",
		OwnerUserID: "user-1",
		Name:        "同步测试",
		Goals:       "获取边界权限\n横向移动；拿到数据库",
		Scope:       "10.0.0.0/24",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, fact := range []ProjectFact{
		{ID: newID(), ProjectID: project.ID, FactType: "general", Key: "目标IP", Value: "10.0.0.1", Confidence: 90, CreatedAt: now, UpdatedAt: now},
		{ID: newID(), ProjectID: project.ID, FactType: "general", Key: "开放端口", Value: "22,80", Confidence: 80, CreatedAt: now, UpdatedAt: now},
	} {
		if _, err := db.UpsertProjectFact(ctx, fact); err != nil {
			t.Fatalf("写入项目事实失败: %v", err)
		}
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID:          newID(),
		ProjectID:   project.ID,
		OwnerUserID: "user-1",
		Title:       "SQL 注入",
		Severity:    "high",
		Status:      "open",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("写入漏洞失败: %v", err)
	}

	result, err := db.SyncProjectGraph(ctx, project)
	if err != nil {
		t.Fatalf("补全攻击路径失败: %v", err)
	}
	if result.CreatedNodes != 7 {
		t.Fatalf("首次补全应创建 7 个节点（begin1+goal3+fact2+finding1），实际 %d", result.CreatedNodes)
	}
	if result.CreatedEdges != 6 {
		t.Fatalf("首次补全应创建 6 条连线（begin→goal3 + fact2 + finding1），实际 %d", result.CreatedEdges)
	}

	nodes, err := db.ListProjectGraphNodes(ctx, project.ID)
	if err != nil {
		t.Fatalf("读取攻击路径失败: %v", err)
	}
	kinds := map[string]int{}
	beginID := ""
	for _, node := range nodes {
		kinds[node.Kind]++
		if node.Kind == "begin" {
			beginID = node.ID
		}
	}
	if kinds["begin"] != 1 || kinds["goal"] != 3 || kinds["fact"] != 2 || kinds["finding"] != 1 {
		t.Fatalf("节点分布异常: %+v", kinds)
	}

	edges, err := db.ListProjectGraphEdges(ctx, project.ID)
	if err != nil {
		t.Fatalf("读取连线失败: %v", err)
	}
	goalLinks := 0
	for _, edge := range edges {
		if edge.SrcID == beginID && edge.Rel == "aims" {
			goalLinks++
		}
	}
	if goalLinks != 3 {
		t.Fatalf("起点应连到 3 个目标，实际 %d", goalLinks)
	}

	second, err := db.SyncProjectGraph(ctx, project)
	if err != nil {
		t.Fatalf("重复补全失败: %v", err)
	}
	if second.CreatedNodes != 0 || second.CreatedEdges != 0 {
		t.Fatalf("重复补全应幂等: %+v", second)
	}
}

func TestSyncProjectGraphStoresSafetyConstraintsAsFacts(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID: "proj-constraints", OwnerUserID: "user-1", Name: "constraints",
		Goals: `资产扩展：可以扫描端口
漏洞目标：验证 SQL 注入
权限目标：获取 shell
安全红线：
- 禁止删除操作
- 禁止修改密码`,
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SyncProjectGraph(ctx, project); err != nil {
		t.Fatal(err)
	}
	nodes, err := db.ListProjectGraphNodes(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	goals := 0
	constraints := 0
	for _, node := range nodes {
		if node.Kind == "goal" {
			goals++
			if strings.Contains(node.Title, "安全红线") || strings.Contains(node.Title, "禁止修改密码") {
				t.Fatalf("安全红线不应成为 Goal: %+v", node)
			}
		}
		if node.Kind == "fact" && node.Source == "project-constraint" {
			constraints++
		}
	}
	if goals != 3 || constraints != 2 {
		t.Fatalf("目标/约束拆分错误: goals=%d constraints=%d nodes=%+v", goals, constraints, nodes)
	}
	stored, err := db.GetProject(ctx, project.ID, project.OwnerUserID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Constraints != "禁止删除操作\n禁止修改密码" {
		t.Fatalf("项目约束投影错误: %q", stored.Constraints)
	}
}

func TestSyncProjectGraphPreservesExplicitIntentFactYield(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "proj-explicit-yield",
		OwnerUserID: "user-1",
		Name:        "显式因果边",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	fact, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID:        "fact-explicit-yield",
		ProjectID: project.ID,
		FactType:  "general",
		Key:       "chain/result",
		Value:     "验证结果",
		Summary:   "验证结果",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("写入事实失败: %v", err)
	}
	intent, err := db.UpsertProjectGraphNode(ctx, GraphNode{
		ID:         "intent-explicit-yield",
		ProjectID:  project.ID,
		Kind:       "intent",
		Title:      "验证显式链路",
		Status:     "done",
		Confidence: 70,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("写入意图失败: %v", err)
	}
	factNode, err := db.UpsertProjectGraphNode(ctx, GraphNode{
		ID:          "fact-node-explicit-yield",
		ProjectID:   project.ID,
		Kind:        "fact",
		Title:       fact.Key,
		Detail:      fact.Summary,
		Status:      "confirmed",
		Confidence:  fact.Confidence,
		AssetID:     fact.AssetID,
		Source:      "agent",
		SourceRefID: fact.ID,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("写入事实节点失败: %v", err)
	}
	if err := db.CreateProjectGraphEdge(ctx, GraphEdge{
		ID:        "edge-explicit-yield",
		ProjectID: project.ID,
		SrcID:     intent.ID,
		DstID:     factNode.ID,
		Rel:       "yields",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("写入显式因果边失败: %v", err)
	}
	if _, err := db.SyncProjectGraph(ctx, project); err != nil {
		t.Fatalf("同步攻击路径失败: %v", err)
	}
	edges, err := db.ListProjectGraphEdges(ctx, project.ID)
	if err != nil {
		t.Fatalf("读取连线失败: %v", err)
	}
	yieldCount := 0
	for _, edge := range edges {
		if edge.DstID == factNode.ID && edge.Rel == "yields" {
			yieldCount++
			if edge.SrcID != intent.ID {
				t.Fatalf("显式因果边被同步覆盖: %+v", edge)
			}
		}
	}
	if yieldCount != 1 {
		t.Fatalf("事实节点应保留唯一显式 yields 边，实际 %d", yieldCount)
	}
}

func TestSyncProjectGraphDoesNotAddRepeatedFindingProvesEdges(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID: "proj-proves-prune", OwnerUserID: "user-1", Name: "proves-prune",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateVulnerability(ctx, Vulnerability{
		ID: "finding-proves", ProjectID: project.ID, OwnerUserID: "user-1",
		Title: "测试漏洞", Severity: "high", Status: "open", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	first, err := db.UpsertProjectGraphNode(ctx, GraphNode{
		ID: "intent-first", ProjectID: project.ID, Kind: "intent", Title: "第一个意图",
		Status: "open", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("创建首个意图失败: %v", err)
	}
	if _, err := db.SyncProjectGraph(ctx, project); err != nil {
		t.Fatalf("首次同步失败: %v", err)
	}
	if _, err := db.UpsertProjectGraphNode(ctx, GraphNode{
		ID: "intent-second", ProjectID: project.ID, Kind: "intent", Title: "第二个意图",
		Status: "open", CreatedAt: now.Add(time.Second), UpdatedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("创建第二个意图失败: %v", err)
	}
	if _, err := db.SyncProjectGraph(ctx, project); err != nil {
		t.Fatalf("第二次同步失败: %v", err)
	}
	edges, err := db.ListProjectGraphEdges(ctx, project.ID)
	if err != nil {
		t.Fatalf("读取图边失败: %v", err)
	}
	var findingNodeID string
	nodes, err := db.ListProjectGraphNodes(ctx, project.ID)
	if err != nil {
		t.Fatalf("读取节点失败: %v", err)
	}
	for _, node := range nodes {
		if node.Kind == "finding" {
			findingNodeID = node.ID
			break
		}
	}
	if findingNodeID == "" {
		t.Fatal("未找到 finding 节点")
	}
	proves := make([]GraphEdge, 0)
	for _, edge := range edges {
		if edge.Rel == "proves" && edge.DstID == findingNodeID {
			proves = append(proves, edge)
		}
	}
	if len(proves) != 1 {
		t.Fatalf("finding 应只保留一条 proves 边，实际 %+v", proves)
	}
	if proves[0].SrcID != first.ID {
		t.Fatalf("已有 proves 边不应被新意图替换，期望 %s，实际 %+v", first.ID, proves[0])
	}
}
