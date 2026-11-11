package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateCategoryPath(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "opt", "sophon")
	cases := []struct {
		name     string
		category string
		path     string
		expected bool
	}{
		{name: "workspace 正常", category: "workspace", path: "tmp/workspace", expected: true},
		{name: "artifacts 正常", category: "conversation_artifacts", path: "data/conversation_artifacts", expected: true},
		{name: "uploads 正常", category: "chat_uploads", path: "chat_uploads", expected: true},
		{name: "workspace 子目录", category: "workspace", path: "tmp/workspace/sub", expected: false},
		{name: "尝试后端目录", category: "workspace", path: "backend", expected: false},
		{name: "跳出根目录", category: "workspace", path: "../etc", expected: false},
		{name: "绝对路径", category: "workspace", path: "/etc/passwd", expected: false},
		{name: "空路径", category: "workspace", path: "", expected: false},
		{name: "未知类别", category: "unknown", path: "tmp/workspace", expected: false},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			err := ValidateCategoryPath(root, item.category, item.path)
			if item.expected && err != nil {
				t.Fatalf("期望通过校验，实际报错: %v", err)
			}
			if !item.expected && err == nil {
				t.Fatalf("期望拒绝路径 %q，实际通过", item.path)
			}
		})
	}
}

func TestValidateArtifactRoot(t *testing.T) {
	if err := ValidateArtifactRoot(string(filepath.Separator)); err == nil {
		t.Fatalf("文件系统根目录应被拒绝")
	}
	if err := ValidateArtifactRoot(filepath.Join(t.TempDir(), "storage")); err != nil {
		t.Fatalf("正常绝对路径不应被拒绝: %v", err)
	}
}

func TestCheckNoSymlinkRejectsLink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("当前环境不支持符号链接: %v", err)
	}
	if err := checkNoSymlink(root, "link"); err == nil {
		t.Fatalf("符号链接路径应被拒绝")
	}
	if err := checkNoSymlink(root, "real"); err != nil {
		t.Fatalf("普通目录不应被拒绝: %v", err)
	}
}
