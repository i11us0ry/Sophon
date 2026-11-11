package knowledge

import (
	"context"
	"path/filepath"
	"testing"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestKnowledgeSemanticSearch(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "knowledge.db"))
	if err != nil {
		t.Fatalf("Open database: %v", err)
	}
	defer func() { _ = db.Close() }()

	embedder, err := NewEmbedder(config.Config{
		EmbeddingMock:       true,
		EmbeddingDimensions: 128,
	})
	if err != nil {
		t.Fatalf("创建测试 Embedder 失败: %v", err)
	}
	service := NewService(db, embedder)
	_, err = service.CreateItem(
		context.Background(),
		"user-1",
		"web",
		"SQL injection",
		"检查参数化查询、错误回显和数据库注入迹象。",
	)
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}
	_, err = service.CreateItem(
		context.Background(),
		"user-1",
		"network",
		"端口扫描",
		"扫描开放端口和服务版本。",
	)
	if err != nil {
		t.Fatalf("CreateItem: %v", err)
	}

	results, err := service.Search(context.Background(), "user-1", "数据库注入检查", 1)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	if results[0].Title != "SQL injection" {
		t.Fatalf("top result = %q", results[0].Title)
	}
}
