package database

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestProjectFinalizationMetricsAreNotTruncated(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "finalization-metrics.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC().Unix()
	if err := db.CreateProject(ctx, Project{
		ID: "project-finalization", OwnerUserID: "user-1",
		Name: "最终化全量指标", Status: "active",
		CreatedAt: time.Unix(now, 0), UpdatedAt: time.Unix(now, 0),
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("开始事务失败: %v", err)
	}
	for index := 0; index < 501; index++ {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO project_test_results (
				id, project_id, dimension, technique, status, required, created_at, updated_at
			) VALUES (?, ?, ?, ?, 'untested', 1, ?, ?)`,
			fmt.Sprintf("test-%03d", index),
			"project-finalization",
			fmt.Sprintf("dimension-%03d", index),
			"technique",
			now,
			now,
		); err != nil {
			_ = tx.Rollback()
			t.Fatalf("插入测试结果失败: %v", err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO vulnerabilities (
				id, project_id, owner_user_id, title, severity, status, created_at, updated_at
			) VALUES (?, ?, 'user-1', ?, 'high', 'confirmed', ?, ?)`,
			fmt.Sprintf("finding-%03d", index),
			"project-finalization",
			fmt.Sprintf("finding %03d", index),
			now,
			now,
		); err != nil {
			_ = tx.Rollback()
			t.Fatalf("插入漏洞失败: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交事务失败: %v", err)
	}

	metrics, err := db.ProjectFinalizationMetrics(
		ctx,
		"project-finalization",
		"user-1",
	)
	if err != nil {
		t.Fatalf("读取最终化指标失败: %v", err)
	}
	if metrics.TestsTotal != 501 || metrics.TestsOpenRequired != 501 {
		t.Fatalf("测试指标被截断: %+v", metrics)
	}
	if metrics.FindingsConfirmedWithoutEvidence != 501 {
		t.Fatalf("漏洞证据指标被截断: %+v", metrics)
	}
}

func TestProjectFinalizationMetricsForAssetsScopesCoverage(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "finalization-scope.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-scope", OwnerUserID: "user-1", Name: "范围最终化",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, item := range []Asset{
		{ID: "asset-falcon", ProjectID: "project-scope", OwnerUserID: "user-1", Name: "falcon", Kind: "url", Value: "https://falcon.example.com"},
		{ID: "asset-other", ProjectID: "project-scope", OwnerUserID: "user-1", Name: "other", Kind: "url", Value: "https://other.example.com"},
	} {
		item.Status = "active"
		item.Criticality = "medium"
		item.CreatedAt = now
		item.UpdatedAt = now
		if err := db.CreateAsset(ctx, item); err != nil {
			t.Fatalf("创建资产失败: %v", err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO project_test_results (
		id, project_id, asset_id, dimension, technique, status, required, created_at, updated_at
	) VALUES
		('test-falcon', 'project-scope', 'asset-falcon', '认证', 'anonymous', 'untested', 1, ?, ?),
		('test-other', 'project-scope', 'asset-other', '认证', 'anonymous', 'untested', 1, ?, ?)`,
		now.Unix(), now.Unix(), now.Unix(), now.Unix(),
	); err != nil {
		t.Fatalf("创建测试结果失败: %v", err)
	}
	metrics, err := db.ProjectFinalizationMetricsForAssets(
		ctx,
		"project-scope",
		"user-1",
		[]string{"asset-falcon"},
	)
	if err != nil {
		t.Fatalf("读取范围最终化指标失败: %v", err)
	}
	if metrics.AssetsTotal != 1 || metrics.TestsTotal != 1 || metrics.TestsOpenRequired != 1 {
		t.Fatalf("最终化范围未按目标资产收窄: %+v", metrics)
	}
}
