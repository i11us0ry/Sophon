package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateProjectIntentWithHypothesisRollsBackOnInvalidResult(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "intent-transaction.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-intent-transaction", OwnerUserID: "user-1",
		Name: "意图事务", Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	nodeID := "intent-transaction"
	_, err = db.CreateProjectIntentWithHypothesis(
		ctx,
		GraphNode{
			ID: nodeID, ProjectID: "project-intent-transaction", Kind: "intent",
			Title: "事务意图", Status: "open", Confidence: 70, Source: "planner",
			CreatedAt: now, UpdatedAt: now,
		},
		nil,
		ProjectTestResult{
			ProjectID: "project-intent-transaction", Dimension: "事务假设",
			Technique: "transaction", Status: "invalid", IntentID: nodeID,
			CreatedAt: now,
		},
	)
	if err == nil {
		t.Fatal("非法测试状态应导致事务失败")
	}
	var nodeCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes WHERE id = ? AND project_id = ?`,
		nodeID,
		"project-intent-transaction",
	).Scan(&nodeCount); err != nil {
		t.Fatalf("读取意图节点数量失败: %v", err)
	}
	var resultCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_test_results WHERE project_id = ?`,
		"project-intent-transaction",
	).Scan(&resultCount); err != nil {
		t.Fatalf("读取测试假设数量失败: %v", err)
	}
	if nodeCount != 0 || resultCount != 0 {
		t.Fatalf("事务失败后不应留下部分数据: nodes=%d results=%d", nodeCount, resultCount)
	}
}
