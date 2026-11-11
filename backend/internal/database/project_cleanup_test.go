package database

import (
	"context"
	"testing"
	"time"
)

func TestCleanupOrphanProjectData(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProjectGraphNode(ctx, GraphNode{
		ID:        "orphan-node",
		ProjectID: "missing-project",
		Kind:      "fact",
		Title:     "孤立节点",
		Status:    "confirmed",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建孤立节点失败: %v", err)
	}
	if err := db.CreateProjectGraphEdge(ctx, GraphEdge{
		ID:        "orphan-edge",
		ProjectID: "missing-project",
		SrcID:     "orphan-node",
		DstID:     "orphan-node",
		Rel:       "spawns",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("创建孤立连线失败: %v", err)
	}

	if err := db.cleanupOrphanProjectData(ctx); err != nil {
		t.Fatalf("清理孤立数据失败: %v", err)
	}
	var nodes int
	var edges int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes WHERE project_id = 'missing-project'`,
	).Scan(&nodes); err != nil {
		t.Fatalf("统计孤立节点失败: %v", err)
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_edges WHERE project_id = 'missing-project'`,
	).Scan(&edges); err != nil {
		t.Fatalf("统计孤立连线失败: %v", err)
	}
	if nodes != 0 || edges != 0 {
		t.Fatalf("孤立数据未清理: nodes=%d edges=%d", nodes, edges)
	}
}
