package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sophon/internal/config"
	storagepkg "sophon/internal/storage"

	"github.com/gin-gonic/gin"
)

type workspaceContentTestResponse struct {
	Content    string `json:"content"`
	Size       int64  `json:"size"`
	MTime      int64  `json:"mtime"`
	Version    string `json:"version"`
	LineEnding string `json:"lineEnding"`
}

func newWorkspaceContentTestHandler(t *testing.T) (*WorkspaceHandler, string) {
	t.Helper()
	root := t.TempDir()
	service := storagepkg.NewService(nil, config.StorageConfig{
		ArtifactRoot:     root,
		ActiveGraceHours: 24,
		Categories: map[string]config.StorageCategoryConfig{
			"workspace": {Enabled: true, RetentionDays: 30, Path: "tmp/workspace"},
		},
	}, "")
	dir, err := service.CategoryDir("workspace")
	if err != nil {
		t.Fatalf("读取工作空间目录失败: %v", err)
	}
	return NewWorkspaceHandler(service), dir
}

func performWorkspaceContentRequest(
	t *testing.T,
	handler *WorkspaceHandler,
	method string,
	path string,
	body []byte,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/workspace/content", handler.Content)
	router.PUT("/workspace/content", handler.SaveContent)
	request := httptest.NewRequest(
		method,
		"/workspace/content?category=workspace&path="+url.QueryEscape(path),
		bytes.NewReader(body),
	)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestWorkspaceContentReadAndSavePreservesCRLF(t *testing.T) {
	handler, dir := newWorkspaceContentTestHandler(t)
	path := filepath.Join(dir, "sample.txt")
	original := []byte("first\r\nsecond\r\n")
	if err := os.WriteFile(path, original, 0o640); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}

	recorder := performWorkspaceContentRequest(t, handler, http.MethodGet, "sample.txt", nil, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("读取文件状态码错误: %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("文件内容响应必须禁止缓存")
	}
	var current workspaceContentTestResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &current); err != nil {
		t.Fatalf("解析读取响应失败: %v", err)
	}
	if current.Content != string(original) || current.LineEnding != "crlf" {
		t.Fatalf("读取内容或换行格式错误: %+v", current)
	}
	if current.Version != workspaceContentVersion(original) {
		t.Fatalf("文件版本错误: %s", current.Version)
	}

	updatedContent := []byte("first\nsecond changed\n")
	recorder = performWorkspaceContentRequest(
		t,
		handler,
		http.MethodPut,
		"sample.txt",
		updatedContent,
		map[string]string{
			"Content-Type":            "text/plain; charset=utf-8",
			"X-Workspace-Version":     current.Version,
			"X-Workspace-Line-Ending": "crlf",
		},
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("保存文件状态码错误: %d body=%s", recorder.Code, recorder.Body.String())
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取保存结果失败: %v", err)
	}
	if string(stored) != "first\r\nsecond changed\r\n" {
		t.Fatalf("CRLF 保存结果错误: %q", stored)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("读取文件属性失败: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("保存后权限发生变化: %o", info.Mode().Perm())
	}
}

func TestWorkspaceContentSaveRejectsStaleVersion(t *testing.T) {
	handler, dir := newWorkspaceContentTestHandler(t)
	path := filepath.Join(dir, "conflict.txt")
	if err := os.WriteFile(path, []byte("original\n"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}
	oldVersion := workspaceContentVersion([]byte("original\n"))
	if err := os.WriteFile(path, []byte("changed by agent\n"), 0o600); err != nil {
		t.Fatalf("模拟外部修改失败: %v", err)
	}

	recorder := performWorkspaceContentRequest(
		t,
		handler,
		http.MethodPut,
		"conflict.txt",
		[]byte("browser overwrite\n"),
		map[string]string{
			"Content-Type":        "text/plain; charset=utf-8",
			"X-Workspace-Version": oldVersion,
		},
	)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("旧版本保存应返回 409，实际 %d body=%s", recorder.Code, recorder.Body.String())
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取冲突文件失败: %v", err)
	}
	if string(stored) != "changed by agent\n" {
		t.Fatalf("冲突时不得覆盖文件: %q", stored)
	}
}

func TestWorkspaceContentRejectsUnsafeAndUnsupportedFiles(t *testing.T) {
	handler, dir := newWorkspaceContentTestHandler(t)
	if err := os.WriteFile(filepath.Join(dir, "binary.bin"), []byte("text\x00binary"), 0o600); err != nil {
		t.Fatalf("写入二进制文件失败: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "large.txt"),
		[]byte(strings.Repeat("A", workspaceMaxEditBytes+1)),
		0o600,
	); err != nil {
		t.Fatalf("写入大文件失败: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("写入外部文件失败: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Logf("当前平台不支持符号链接测试: %v", err)
	}

	cases := []struct {
		name   string
		path   string
		status int
	}{
		{name: "路径穿越", path: "../outside.txt", status: http.StatusBadRequest},
		{name: "目录", path: ".", status: http.StatusBadRequest},
		{name: "二进制", path: "binary.bin", status: http.StatusUnsupportedMediaType},
		{name: "超大文件", path: "large.txt", status: http.StatusRequestEntityTooLarge},
	}
	if _, err := os.Lstat(filepath.Join(dir, "link.txt")); err == nil {
		cases = append(cases, struct {
			name   string
			path   string
			status int
		}{name: "符号链接", path: "link.txt", status: http.StatusBadRequest})
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			recorder := performWorkspaceContentRequest(t, handler, http.MethodGet, item.path, nil, nil)
			if recorder.Code != item.status {
				t.Fatalf("状态码应为 %d，实际 %d body=%s", item.status, recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestWorkspaceContentSaveValidatesVersionAndSize(t *testing.T) {
	handler, dir := newWorkspaceContentTestHandler(t)
	path := filepath.Join(dir, "valid.txt")
	if err := os.WriteFile(path, []byte("valid\n"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}

	recorder := performWorkspaceContentRequest(
		t,
		handler,
		http.MethodPut,
		"valid.txt",
		[]byte("changed\n"),
		map[string]string{"Content-Type": "text/plain; charset=utf-8"},
	)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("缺少版本应返回 400，实际 %d", recorder.Code)
	}

	recorder = performWorkspaceContentRequest(
		t,
		handler,
		http.MethodPut,
		"valid.txt",
		[]byte(strings.Repeat("B", workspaceMaxEditBytes+1)),
		map[string]string{
			"Content-Type":        "text/plain; charset=utf-8",
			"X-Workspace-Version": workspaceContentVersion([]byte("valid\n")),
		},
	)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大编辑内容应返回 413，实际 %d", recorder.Code)
	}

	recorder = performWorkspaceContentRequest(
		t,
		handler,
		http.MethodPut,
		"valid.txt",
		[]byte(strings.Repeat("C\n", workspaceMaxEditBytes/2)),
		map[string]string{
			"Content-Type":            "text/plain; charset=utf-8",
			"X-Workspace-Version":     workspaceContentVersion([]byte("valid\n")),
			"X-Workspace-Line-Ending": "crlf",
		},
	)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("换行转换后超限应返回 413，实际 %d", recorder.Code)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/workspace/content", handler.SaveContent)
	request := httptest.NewRequest(
		http.MethodPut,
		"/workspace/content?category=reduction&path=valid.txt",
		strings.NewReader("changed\n"),
	)
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	request.Header.Set("X-Workspace-Version", workspaceContentVersion([]byte("valid\n")))
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("非 Agent 工作区应只读，实际 %d", recorder.Code)
	}
}
