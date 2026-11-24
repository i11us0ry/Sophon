package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenBackfillsProjectFactBodyFromSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "facts.db")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	ctx := context.Background()
	nowTime := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-1",
		OwnerUserID: "user-1",
		Name:        "历史事实回填测试",
		Status:      "active",
		CreatedAt:   nowTime,
		UpdatedAt:   nowTime,
	}); err != nil {
		_ = db.Close()
		t.Fatalf("创建项目失败: %v", err)
	}
	now := nowTime.Unix()
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO project_facts (
			id, project_id, fact_type, key, value, summary, body, confidence, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, '', 80, ?, ?)`,
		"legacy-summary-only",
		"project-1",
		"code-audit",
		"chain/legacy",
		"历史摘要",
		"历史摘要",
		now,
		now,
	); err != nil {
		_ = db.Close()
		t.Fatalf("写入历史事实失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("重新打开数据库失败: %v", err)
	}
	defer reopened.Close()

	var body string
	if err := reopened.QueryRowContext(
		ctx,
		`SELECT body FROM project_facts WHERE id = ?`,
		"legacy-summary-only",
	).Scan(&body); err != nil {
		t.Fatalf("读取回填结果失败: %v", err)
	}
	if body != "历史摘要" {
		t.Fatalf("历史事实正文未回填: %q", body)
	}
}
