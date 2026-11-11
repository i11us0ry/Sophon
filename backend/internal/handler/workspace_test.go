package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sophon/internal/config"
	storagepkg "sophon/internal/storage"

	"github.com/gin-gonic/gin"
)

func newWorkspaceTestHandler(t *testing.T) (*WorkspaceHandler, string) {
	t.Helper()
	root := t.TempDir()
	workspaceDir := filepath.Join(root, "tmp", "workspace")
	if err := os.MkdirAll(workspaceDir, 0o755); err != nil {
		t.Fatalf("创建工作空间失败: %v", err)
	}
	service := storagepkg.NewService(nil, config.StorageConfig{
		ArtifactRoot: root,
		Categories: map[string]config.StorageCategoryConfig{
			"workspace": {Enabled: true, Path: "tmp/workspace"},
		},
	}, root)
	return NewWorkspaceHandler(service), workspaceDir
}

func workspaceContext(method, target string) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(method, target, nil)
	return ctx, recorder
}

func TestWorkspaceRejectsTraversalAndEscapingSymlink(t *testing.T) {
	handler, workspaceDir := newWorkspaceTestHandler(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("创建外部文件失败: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(workspaceDir, "escape")); err != nil {
		t.Fatalf("创建符号链接失败: %v", err)
	}
	if _, _, _, err := handler.resolve("workspace", "../outside"); err == nil {
		t.Fatalf("包含 .. 的路径应被拒绝")
	}
	if _, _, _, err := handler.resolve("workspace", "/etc/passwd"); err == nil {
		t.Fatalf("绝对路径应被拒绝")
	}
	if _, _, _, err := handler.resolve("workspace", "escape/secret.txt"); err == nil {
		t.Fatalf("逃逸符号链接应被拒绝")
	}
}

func TestWorkspaceListDownloadAndDelete(t *testing.T) {
	handler, workspaceDir := newWorkspaceTestHandler(t)
	if err := os.WriteFile(filepath.Join(workspaceDir, "artifact.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("创建文件失败: %v", err)
	}

	listCtx, listRecorder := workspaceContext(
		http.MethodGet,
		"/workspace/list?category=workspace&path=",
	)
	handler.List(listCtx)
	if listRecorder.Code != http.StatusOK ||
		!strings.Contains(listRecorder.Body.String(), "artifact.txt") {
		t.Fatalf("列表接口异常: status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}

	downloadCtx, downloadRecorder := workspaceContext(
		http.MethodGet,
		"/workspace/download?category=workspace&path=artifact.txt",
	)
	handler.Download(downloadCtx)
	if downloadRecorder.Code != http.StatusOK || downloadRecorder.Body.String() != "hello" {
		t.Fatalf("下载接口异常: status=%d body=%q", downloadRecorder.Code, downloadRecorder.Body.String())
	}

	deleteCtx, deleteRecorder := workspaceContext(
		http.MethodDelete,
		"/workspace/delete?category=workspace&path=artifact.txt",
	)
	handler.Delete(deleteCtx)
	if deleteRecorder.Code != http.StatusOK {
		t.Fatalf("删除接口异常: status=%d body=%s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if _, err := os.Stat(filepath.Join(workspaceDir, "artifact.txt")); !os.IsNotExist(err) {
		t.Fatalf("文件应已删除: %v", err)
	}
}
