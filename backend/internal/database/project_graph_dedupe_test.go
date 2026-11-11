package database

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestGraphMigrationDeduplicatesExistingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dedupe.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "proj-dedupe",
		OwnerUserID: "user-1",
		Name:        "去重测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	// 模拟历史库：去掉唯一索引后写入重复节点与重复连线。
	for _, statement := range []string{
		`DROP INDEX IF EXISTS idx_project_graph_nodes_unique`,
		`DROP INDEX IF EXISTS idx_project_graph_nodes_title_unique`,
		`DROP INDEX IF EXISTS idx_project_graph_nodes_ref_unique`,
		`DROP INDEX IF EXISTS idx_project_graph_edges_unique`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatalf("删除唯一索引失败: %v", err)
		}
	}
	keep := GraphNode{
		ID: "node-keep", ProjectID: "proj-dedupe", Kind: "fact", Title: "服务指纹",
		Detail: "nginx/1.15", Status: "confirmed", Confidence: 80, Source: "auto-sync",
		CreatedAt: now, UpdatedAt: now,
	}
	duplicate := keep
	duplicate.ID = "node-dup"
	goal := GraphNode{
		ID: "node-goal", ProjectID: "proj-dedupe", Kind: "goal", Title: "目标",
		Status: "open", Confidence: 80, CreatedAt: now, UpdatedAt: now,
	}
	for _, node := range []GraphNode{keep, duplicate, goal} {
		if err := db.CreateProjectGraphNode(ctx, node); err != nil {
			t.Fatalf("写入节点失败: %v", err)
		}
	}
	for _, edge := range []GraphEdge{
		{ID: "edge-1", ProjectID: "proj-dedupe", SrcID: "node-goal", DstID: "node-dup", Rel: "yields", CreatedAt: now},
		{ID: "edge-2", ProjectID: "proj-dedupe", SrcID: "node-goal", DstID: "node-dup", Rel: "yields", CreatedAt: now},
	} {
		// 历史库没有唯一索引，这里用原生 INSERT 造重复连线。
		if _, err := db.ExecContext(
			ctx,
			`INSERT INTO project_graph_edges (id, project_id, src_id, dst_id, rel, created_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			edge.ID,
			edge.ProjectID,
			edge.SrcID,
			edge.DstID,
			edge.Rel,
			edge.CreatedAt.Unix(),
		); err != nil {
			t.Fatalf("写入连线失败: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("重新打开数据库失败: %v", err)
	}
	defer reopened.Close()

	nodes, err := reopened.ListProjectGraphNodes(ctx, "proj-dedupe")
	if err != nil {
		t.Fatalf("读取节点失败: %v", err)
	}
	factCount := 0
	for _, node := range nodes {
		if node.Kind == "fact" && node.Title == "服务指纹" {
			factCount++
		}
	}
	if factCount != 1 {
		t.Fatalf("重复事实节点应合并为 1 条，实际 %d", factCount)
	}
	edges, err := reopened.ListProjectGraphEdges(ctx, "proj-dedupe")
	if err != nil {
		t.Fatalf("读取连线失败: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("重复连线应合并为 1 条，实际 %d", len(edges))
	}
	if edges[0].DstID != "node-keep" {
		t.Fatalf("连线应重映射到保留节点，实际 %+v", edges[0])
	}
	if err := reopened.CreateProjectGraphNode(ctx, duplicate); err == nil {
		t.Fatalf("唯一索引应阻止重复节点写入")
	}
}

func TestUpsertProjectGraphNodeAndEdgeAreIdempotent(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "proj-upsert",
		OwnerUserID: "user-1",
		Name:        "upsert 测试",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}

	var waitGroup sync.WaitGroup
	for index := 0; index < 8; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, _ = db.UpsertProjectGraphNode(ctx, GraphNode{
				ID: newID(), ProjectID: "proj-upsert", Kind: "fact", Title: "并发事实",
				Detail: "v", Status: "confirmed", Confidence: 80,
				CreatedAt: now, UpdatedAt: now,
			})
		}()
	}
	waitGroup.Wait()
	nodes, err := db.ListProjectGraphNodes(ctx, "proj-upsert")
	if err != nil {
		t.Fatalf("读取节点失败: %v", err)
	}
	count := 0
	for _, node := range nodes {
		if node.Title == "并发事实" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("并发 upsert 后应只有 1 条节点，实际 %d", count)
	}

	goal := GraphNode{
		ID: newID(), ProjectID: "proj-upsert", Kind: "goal", Title: "目标",
		Status: "open", CreatedAt: now, UpdatedAt: now,
	}
	saved, err := db.UpsertProjectGraphNode(ctx, goal)
	if err != nil {
		t.Fatalf("写入目标节点失败: %v", err)
	}
	factID := nodes[0].ID
	for index := 0; index < 3; index++ {
		if err := db.CreateProjectGraphEdge(ctx, GraphEdge{
			ID: newID(), ProjectID: "proj-upsert", SrcID: saved.ID, DstID: factID,
			Rel: "yields", CreatedAt: now,
		}); err != nil {
			t.Fatalf("写入连线失败: %v", err)
		}
	}
	edges, err := db.ListProjectGraphEdges(ctx, "proj-upsert")
	if err != nil {
		t.Fatalf("读取连线失败: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("重复连线应幂等，实际 %d", len(edges))
	}
}
