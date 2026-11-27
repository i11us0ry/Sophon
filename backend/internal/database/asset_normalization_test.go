package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestAssetNormalizationRejectsEquivalentURLs(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-normalization.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	asset := Asset{
		ID:          "asset-normal-1",
		ProjectID:   "project-normal",
		OwnerUserID: "user-1",
		Name:        "normal",
		Kind:        "url",
		Value:       "HTTPS://Example.COM:443/path#fragment",
		Status:      "active",
		Source:      AssetSourceManual,
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := db.CreateAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	duplicate := asset
	duplicate.ID = "asset-normal-2"
	duplicate.Value = "https://example.com/path"
	if err := db.CreateAsset(ctx, duplicate); err != ErrAssetDuplicate {
		t.Fatalf("规范化后相同 URL 应拒绝重复，实际 %v", err)
	}
	stored, err := db.GetAsset(ctx, asset.ID, asset.OwnerUserID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.NormalizedValue != "https://example.com/path" {
		t.Fatalf("规范化值错误: %+v", stored)
	}
}

func TestAssetBackfillMarksLegacyDuplicateWithoutFailingStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asset-normalization-restart.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-restart", OwnerUserID: "user-1", Name: "restart",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateAsset(ctx, Asset{
		ID: "asset-existing", ProjectID: "project-restart", OwnerUserID: "user-1",
		Name: "existing", Kind: "domain", Value: "example.com", Status: "active",
		Source: AssetSourceManual, Criticality: "medium", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO assets (
			id, project_id, owner_user_id, name, kind, value, normalized_value,
			quality_status, status, source, criticality, risk_score, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, '', '', 'active', 'manual', 'medium', 0, ?, ?)`,
		"asset-legacy-duplicate",
		"project-restart",
		"user-1",
		"legacy",
		"domain",
		"EXAMPLE.COM.",
		now.Unix(),
		now.Unix(),
	); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("空值重复资产不应导致启动迁移失败: %v", err)
	}
	defer reopened.Close()
	var quality string
	if err := reopened.QueryRowContext(
		context.Background(),
		`SELECT quality_status FROM assets WHERE id = 'asset-legacy-duplicate'`,
	).Scan(&quality); err != nil {
		t.Fatal(err)
	}
	if quality != AssetQualityDuplicate {
		t.Fatalf("历史重复资产应标记 duplicate，实际 %s", quality)
	}
}

func TestSuspiciousRepeatedWWWIsMarked(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "asset-suspicious.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	asset := Asset{
		ID: "asset-www", ProjectID: "project-www", OwnerUserID: "user-1",
		Name: "www", Kind: "domain", Value: "www.www.example.com",
		Status: "active", Source: AssetSourceManual, Criticality: "medium",
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateAsset(context.Background(), asset); err != nil {
		t.Fatal(err)
	}
	items, _, err := db.ListAssetsFiltered(context.Background(), AssetFilter{
		OwnerUserID: "user-1",
		ProjectID:   "project-www",
		Limit:       10,
	})
	if err != nil || len(items) != 1 {
		t.Fatalf("读取资产失败: %+v %v", items, err)
	}
	if items[0].QualityStatus != "" {
		// 列表查询暂不投影质量字段，直接通过 SQL 验证持久化结果。
	}
	var quality string
	if err := db.QueryRowContext(
		context.Background(),
		`SELECT quality_status FROM assets WHERE id = ?`,
		asset.ID,
	).Scan(&quality); err != nil {
		t.Fatal(err)
	}
	if quality != AssetQualitySuspicious {
		t.Fatalf("重复 www 应标记 suspicious，实际 %s", quality)
	}
}
