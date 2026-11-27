package database

import (
	"context"
	"os"
	"testing"
)

func TestExternalDatabaseMigration(t *testing.T) {
	path := os.Getenv("SOPHON_MIGRATION_TEST_DB")
	if path == "" {
		t.Skip("未设置 SOPHON_MIGRATION_TEST_DB")
	}
	db, err := Open(path)
	if err != nil {
		t.Fatalf("迁移外部数据库失败: %v", err)
	}
	defer db.Close()
	ctx := context.Background()

	var duplicateFindingRefs int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM (
			SELECT project_id, source_ref_id
			FROM project_graph_nodes
			WHERE kind = 'finding' AND source_ref_id <> ''
			GROUP BY project_id, source_ref_id
			HAVING COUNT(*) > 1
		)`,
	).Scan(&duplicateFindingRefs); err != nil {
		t.Fatal(err)
	}
	if duplicateFindingRefs != 0 {
		t.Fatalf("迁移后仍有重复 finding 引用: %d", duplicateFindingRefs)
	}

	var normalizedAssets int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM assets WHERE quality_status = ?`,
		AssetQualityDuplicate,
	).Scan(&normalizedAssets); err != nil {
		t.Fatal(err)
	}
	var findingStatusMismatches int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM vulnerabilities v
		 JOIN project_graph_nodes n
		   ON n.project_id = v.project_id AND n.kind = 'finding' AND n.source_ref_id = v.id
		 WHERE n.status <> CASE
			WHEN v.status = 'pending_review' THEN 'open'
			WHEN v.status IN ('fixed', 'ignored', 'false_positive') THEN 'dismissed'
			WHEN v.status = 'confirmed' THEN 'confirmed'
			ELSE 'open'
		 END`,
	).Scan(&findingStatusMismatches); err != nil {
		t.Fatal(err)
	}
	var constraintNodes int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes WHERE source = 'project-constraint'`,
	).Scan(&constraintNodes); err != nil {
		t.Fatal(err)
	}
	t.Logf(
		"migration copy checked: duplicate_findings=%d finding_status_mismatches=%d duplicate_assets=%d constraint_nodes=%d",
		duplicateFindingRefs,
		findingStatusMismatches,
		normalizedAssets,
		constraintNodes,
	)
}
