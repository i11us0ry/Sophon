package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"sophon/internal/config"
)

func newDirService(t *testing.T, enabled bool) (*Service, string) {
	t.Helper()
	root := t.TempDir()
	service := NewService(nil, config.StorageConfig{
		ArtifactRoot:     root,
		ActiveGraceHours: 24,
		Categories: map[string]config.StorageCategoryConfig{
			"workspace": {Enabled: enabled, RetentionDays: 30, Path: "tmp/workspace"},
		},
	}, "")
	return service, filepath.Join(root, "tmp", "workspace", "fresh.txt")
}

func writeFreshFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(path, []byte("fresh"), 0o644); err != nil {
		t.Fatalf("写入文件失败: %v", err)
	}
}

func TestPreviewCountsTotalAndCleanRespectsRetention(t *testing.T) {
	service, file := newDirService(t, true)
	writeFreshFile(t, file)

	items, err := service.Preview(context.Background())
	if err != nil {
		t.Fatalf("预览失败: %v", err)
	}
	var files int
	for _, item := range items {
		if item.Name == "workspace" {
			files = item.Files
		}
	}
	if files != 1 {
		t.Fatalf("预览应统计立即清理总量，实际 files=%d", files)
	}

	result, err := service.Clean(context.Background(), []string{"workspace"}, false)
	if err != nil {
		t.Fatalf("按保留期清理失败: %v", err)
	}
	if result.Deleted["workspace"] != 0 {
		t.Fatalf("保留期内文件不应被自动清理: %v", result.Deleted)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("保留期内文件应保留: %v", err)
	}

	result, err = service.Clean(context.Background(), []string{"workspace"}, true)
	if err != nil {
		t.Fatalf("手动清理失败: %v", err)
	}
	if result.Deleted["workspace"] != 1 || result.Bytes["workspace"] != int64(len("fresh")) {
		t.Fatalf("手动清理应删除保留期内文件: %+v", result)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("手动清理后文件应被删除，实际 err=%v", err)
	}
}

func TestForcedCleanSkipsDisabledCategory(t *testing.T) {
	service, file := newDirService(t, false)
	writeFreshFile(t, file)

	result, err := service.Clean(context.Background(), []string{"workspace"}, true)
	if err != nil {
		t.Fatalf("手动清理失败: %v", err)
	}
	if result.Deleted["workspace"] != 0 {
		t.Fatalf("禁用类别不应被清理: %v", result.Deleted)
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("禁用类别文件应保留: %v", err)
	}
}
