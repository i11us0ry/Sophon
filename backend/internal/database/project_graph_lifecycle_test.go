package database

import (
	"context"
	"testing"
	"time"
)

func TestDeletingProjectRecordsKeepsGraphConsistent(t *testing.T) {
	db := openGraphSyncTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	project := Project{
		ID:          "project-graph-lifecycle",
		OwnerUserID: "user-1",
		Name:        "攻击路径生命周期",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateProject(ctx, project); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}

	fact, err := db.UpsertProjectFact(ctx, ProjectFact{
		ID:         newID(),
		ProjectID:  project.ID,
		FactType:   "general",
		Key:        "fact-key",
		Value:      "fact-value",
		Confidence: 90,
		CreatedAt:  now,
		UpdatedAt:  now,
	})
	if err != nil {
		t.Fatalf("写入事实失败: %v", err)
	}
	if err := db.CreateProjectGraphNode(ctx, GraphNode{
		ID: newID(), ProjectID: project.ID, Kind: "fact", Title: fact.Key,
		Status: "confirmed", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建事实节点失败: %v", err)
	}
	if err := db.DeleteProjectFact(ctx, fact.ID, project.ID); err != nil {
		t.Fatalf("删除事实失败: %v", err)
	}
	if countGraphNodes(ctx, t, db, project.ID, "fact", fact.Key) != 0 {
		t.Fatalf("事实节点应被删除")
	}

	asset := Asset{
		ID: newID(), ProjectID: project.ID, OwnerUserID: "user-1",
		Name: "asset", Kind: "url", Value: "https://example.com",
		Status: "active", Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateAsset(ctx, asset); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	node := GraphNode{
		ID: newID(), ProjectID: project.ID, Kind: "finding", Title: "asset-node",
		AssetID: asset.ID, Status: "confirmed", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateProjectGraphNode(ctx, node); err != nil {
		t.Fatalf("创建资产节点失败: %v", err)
	}
	if err := db.DeleteAsset(ctx, asset.ID, "user-1"); err != nil {
		t.Fatalf("删除资产失败: %v", err)
	}
	storedNode, err := db.GetProjectGraphNode(ctx, node.ID, project.ID)
	if err != nil || storedNode.AssetID != "" {
		t.Fatalf("资产删除后节点引用应被清空: %+v err=%v", storedNode, err)
	}

	vulnerability := Vulnerability{
		ID: newID(), ProjectID: project.ID, OwnerUserID: "user-1",
		Title: "finding-title", Severity: "high", Status: "open",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateVulnerability(ctx, vulnerability); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	if err := db.CreateProjectGraphNode(ctx, GraphNode{
		ID: newID(), ProjectID: project.ID, Kind: "finding", Title: vulnerability.Title,
		Status: "confirmed", Source: "vulnerability", SourceRefID: vulnerability.ID,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞节点失败: %v", err)
	}
	if err := db.DeleteVulnerability(ctx, vulnerability.ID, "user-1"); err != nil {
		t.Fatalf("删除漏洞失败: %v", err)
	}
	if countGraphNodes(ctx, t, db, project.ID, "finding", vulnerability.Title) != 0 {
		t.Fatalf("漏洞节点应被删除")
	}
}

func countGraphNodes(
	ctx context.Context,
	t *testing.T,
	db *DB,
	projectID string,
	kind string,
	title string,
) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes
		 WHERE project_id = ? AND kind = ? AND title = ?`,
		projectID,
		kind,
		title,
	).Scan(&count); err != nil {
		t.Fatalf("统计图节点失败: %v", err)
	}
	return count
}
