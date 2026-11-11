package handler

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestProjectReferenceValidation(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-reference.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-user-1",
		OwnerUserID: "user-1",
		Name:        "用户1项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, database.Asset{
		ID:          "asset-user-2",
		ProjectID:   "project-user-2",
		OwnerUserID: "user-2",
		Name:        "用户2资产",
		Kind:        "url",
		Value:       "https://example.com",
		Status:      "active",
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}

	handler := &BusinessHandler{db: db}
	if err := handler.validateProjectReference(ctx, "user-2", "project-user-1"); err == nil {
		t.Fatalf("其他用户项目引用应被拒绝")
	}
	if err := handler.validateProjectReference(ctx, "user-1", "project-user-1"); err != nil {
		t.Fatalf("本人项目引用应通过: %v", err)
	}
	if err := handler.validateAssetReference(
		ctx,
		"user-1",
		"asset-user-2",
		"project-user-1",
	); err == nil {
		t.Fatalf("其他用户资产引用应被拒绝")
	}
}
