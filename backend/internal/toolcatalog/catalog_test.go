package toolcatalog

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCatalogInstallAndVerifyBinary(t *testing.T) {
	payload := []byte("#!/bin/sh\nexit 0\n")
	sum := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	installRoot := filepath.Join(root, "thirdTools")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`
name: demo
version: 1.0.0
description: demo tool
tool_definition: demo.yaml
artifacts:
  %s:
    url: %s
    sha256: %s
    destination: demo-tool
    mode: "0755"
`, CurrentArchitecture(), server.URL, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(filepath.Join(catalogDir, "demo.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "demo.yaml"), []byte("name: demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog := New(catalogDir, installRoot, toolsDir)
	status, err := catalog.Install(context.Background(), "demo", false)
	if err != nil {
		t.Fatalf("安装失败: %v", err)
	}
	if !status.Installed || status.State != "installed" || !status.ToolDefinitionExists {
		t.Fatalf("安装状态错误: %+v", status)
	}
	verified, err := catalog.Verify(context.Background(), "demo")
	if err != nil || verified.State != "installed" {
		t.Fatalf("验证失败: %+v err=%v", verified, err)
	}
}

func TestCatalogRejectsChecksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("bad"))
	}))
	defer server.Close()
	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`
name: demo
version: 1.0.0
description: demo tool
tool_definition: demo.yaml
artifacts:
  %s:
    url: %s
    sha256: %064d
    destination: demo-tool
`, CurrentArchitecture(), server.URL, 0)
	if err := os.WriteFile(filepath.Join(catalogDir, "demo.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog := New(catalogDir, filepath.Join(root, "thirdTools"), filepath.Join(root, "tools"))
	if _, err := catalog.Install(context.Background(), "demo", false); err == nil {
		t.Fatal("错误 SHA256 必须拒绝安装")
	}
}

func TestDownloadBytesRetriesTransientReadFailure(t *testing.T) {
	payload := []byte("retry-success")
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)+1))
			_, _ = w.Write(payload)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	data, err := New("", "", "").downloadBytes(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("瞬时读取失败应自动重试: %v", err)
	}
	if !bytes.Equal(data, payload) || attempts != 2 {
		t.Fatalf("重试结果错误: attempts=%d data=%q", attempts, data)
	}
}

func TestBuildSourceUsesValidatedCache(t *testing.T) {
	payload := []byte("cached-source")
	sum := sha256.Sum256(payload)
	root := t.TempDir()
	installRoot := filepath.Join(root, "thirdTools")
	catalog := New("", installRoot, "")
	build := &BuildSpec{SHA256: hex.EncodeToString(sum[:])}
	if err := catalog.writeSourceCache(build, payload); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		http.Error(w, "network should not be used", http.StatusInternalServerError)
	}))
	defer server.Close()
	build.URL = server.URL
	data, err := catalog.downloadBuildSource(context.Background(), Manifest{Build: build})
	if err != nil {
		t.Fatalf("读取源码缓存失败: %v", err)
	}
	if !bytes.Equal(data, payload) || attempts != 0 {
		t.Fatalf("应优先使用有效缓存: attempts=%d data=%q", attempts, data)
	}
}

func TestNetworkBuildCommandUsesProxyEnvironment(t *testing.T) {
	catalog := New("", t.TempDir(), "")
	catalog.SetProxyEnvironment([]string{"HTTPS_PROXY=http://127.0.0.1:7890"})
	output := filepath.Join(t.TempDir(), "proxy.txt")
	err := catalog.runNetworkBuildCommand(
		context.Background(),
		t.TempDir(),
		"sh",
		"-c",
		`printf '%s' "$HTTPS_PROXY" > `+output,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "http://127.0.0.1:7890" {
		t.Fatalf("构建代理环境未生效: %q", raw)
	}
}

func TestBuildStatusPrefersSystemPathCommand(t *testing.T) {
	root := t.TempDir()
	catalog := New("", filepath.Join(root, "thirdTools"), "")
	status, err := catalog.statusFor(context.Background(), Manifest{
		Name:       "system-command",
		Version:    "1",
		VerifyArgs: nil,
		Build: &BuildSpec{
			Destination:   "missing-tool",
			Directory:     false,
			Recipe:        BuildRecipeCopy,
			URL:           "https://example.com/source.tar.gz",
			SHA256:        strings.Repeat("0", 64),
			Archive:       "tar.gz",
			Command:       "sh",
			CommandTarget: "sh",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed || status.Installable || status.Source != SourceSystem ||
		status.State != "installed" {
		t.Fatalf("PATH 中已有命令时应直接识别: %+v", status)
	}
}

func TestCatalogInstallAndVerifyZIPBinary(t *testing.T) {
	payload := []byte("#!/bin/sh\nexit 0\n")
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	member, err := writer.Create("demo-tool")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archiveData := archive.Bytes()
	archiveSum := sha256.Sum256(archiveData)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archiveData)
	}))
	defer server.Close()

	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	installRoot := filepath.Join(root, "thirdTools")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`
name: demo
version: 1.0.0
description: demo tool
tool_definition: demo.yaml
artifacts:
  %s:
    url: %s
    sha256: %s
    destination: demo-tool
    mode: "0755"
    archive: zip
    member: demo-tool
`, CurrentArchitecture(), server.URL, hex.EncodeToString(archiveSum[:]))
	if err := os.WriteFile(filepath.Join(catalogDir, "demo.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "demo.yaml"), []byte("name: demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	catalog := New(catalogDir, installRoot, toolsDir)
	status, err := catalog.Install(context.Background(), "demo", false)
	if err != nil {
		t.Fatalf("安装失败: %v", err)
	}
	if !status.Installed || status.State != "installed" {
		t.Fatalf("安装状态错误: %+v", status)
	}
	verified, err := catalog.Verify(context.Background(), "demo")
	if err != nil || verified.State != "installed" {
		t.Fatalf("验证失败: %+v err=%v", verified, err)
	}
	if err := os.WriteFile(filepath.Join(installRoot, "demo-tool"), []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	verified, err = catalog.Verify(context.Background(), "demo")
	if err != nil || verified.State != "checksum_mismatch" {
		t.Fatalf("篡改后的文件应校验失败: %+v err=%v", verified, err)
	}
}

func TestCatalogInstallAndVerifyZIPDirectory(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	addZipFile := func(name string, content []byte, mode os.FileMode) {
		t.Helper()
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(mode)
		member, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	addZipFile("demo-1.0.0/bin/demo", []byte("#!/bin/sh\nexit 0\n"), 0o755)
	addZipFile("demo-1.0.0/lib/data.txt", []byte("library"), 0o644)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archiveData := archive.Bytes()
	archiveSum := sha256.Sum256(archiveData)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archiveData)
	}))
	defer server.Close()

	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	installRoot := filepath.Join(root, "thirdTools")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`
name: demo-directory
version: 1.0.0
description: demo directory
tool_definition: demo.yaml
verify_args:
  - "--version"
artifacts:
  %s:
    url: %s
    sha256: %s
    destination: demo-directory
    archive: zip
    directory: true
    strip_components: 1
    entry: bin/demo
`, CurrentArchitecture(), server.URL, hex.EncodeToString(archiveSum[:]))
	if err := os.WriteFile(filepath.Join(catalogDir, "demo.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "demo.yaml"), []byte("name: demo-directory\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	catalog := New(catalogDir, installRoot, toolsDir)
	status, err := catalog.Install(context.Background(), "demo-directory", false)
	if err != nil {
		t.Fatalf("安装失败: %v", err)
	}
	if !status.Installed || !status.Executable || status.State != "installed" {
		t.Fatalf("目录安装状态错误: %+v", status)
	}
	verified, err := catalog.Verify(context.Background(), "demo-directory")
	if err != nil || verified.State != "installed" {
		t.Fatalf("目录验证失败: %+v err=%v", verified, err)
	}
	if err := os.WriteFile(
		filepath.Join(installRoot, "demo-directory", "lib", "data.txt"),
		[]byte("changed"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	verified, err = catalog.Verify(context.Background(), "demo-directory")
	if err != nil || verified.State != "checksum_mismatch" {
		t.Fatalf("目录篡改后应校验失败: %+v err=%v", verified, err)
	}
}

func TestCatalogBuildCopyRecipe(t *testing.T) {
	archiveData := makeTarGZ(t, map[string]tarTestFile{
		"demo-1.0.0/bin/demo":  {data: []byte("#!/bin/sh\nexit 0\n"), mode: 0o755},
		"demo-1.0.0/README.md": {data: []byte("demo"), mode: 0o644},
	})
	archiveSum := sha256.Sum256(archiveData)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archiveData)
	}))
	defer server.Close()

	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	installRoot := filepath.Join(root, "thirdTools")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`
name: source-copy
version: 1.0.0
description: source copy
tool_definition: source-copy.yaml
verify_args:
  - "--version"
build:
  url: %s
  sha256: %s
  archive: tar.gz
  strip_components: 1
  recipe: copy
  destination: source-copy
  directory: true
  entry: bin/demo
`, server.URL, hex.EncodeToString(archiveSum[:]))
	if err := os.WriteFile(filepath.Join(catalogDir, "source-copy.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "source-copy.yaml"), []byte("name: source-copy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	catalog := New(catalogDir, installRoot, toolsDir)
	status, err := catalog.Install(context.Background(), "source-copy", false)
	if err != nil {
		t.Fatalf("源码复制构建失败: %v", err)
	}
	if !status.Installed || !status.Executable || status.Source != SourceSourceBuild {
		t.Fatalf("源码复制构建状态错误: %+v", status)
	}
	verified, err := catalog.Verify(context.Background(), "source-copy")
	if err != nil || verified.State != "installed" {
		t.Fatalf("源码复制构建验证失败: %+v err=%v", verified, err)
	}
}

func TestCatalogBuildGoRecipe(t *testing.T) {
	archiveData := makeTarGZ(t, map[string]tarTestFile{
		"demo-1.0.0/go.mod":  {data: []byte("module demo\n\ngo 1.20\n"), mode: 0o644},
		"demo-1.0.0/main.go": {data: []byte("package main\nfunc main() {}\n"), mode: 0o644},
	})
	archiveSum := sha256.Sum256(archiveData)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archiveData)
	}))
	defer server.Close()

	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	installRoot := filepath.Join(root, "thirdTools")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`
name: source-go
version: 1.0.0
description: source go
tool_definition: source-go.yaml
build:
  url: %s
  sha256: %s
  archive: tar.gz
  strip_components: 1
  recipe: go
  destination: source-go
  package: .
`, server.URL, hex.EncodeToString(archiveSum[:]))
	if err := os.WriteFile(filepath.Join(catalogDir, "source-go.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "source-go.yaml"), []byte("name: source-go\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	status, err := New(catalogDir, installRoot, toolsDir).
		Install(context.Background(), "source-go", false)
	if err != nil {
		t.Fatalf("Go 源码构建失败: %v", err)
	}
	if !status.Installed || !status.Executable || status.Source != SourceSourceBuild {
		t.Fatalf("Go 源码构建状态错误: %+v", status)
	}
}

func TestDirectorySHA256HandlesSafeSymlinksOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不支持当前符号链接测试")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "target"), []byte("demo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(root, "safe-link")); err != nil {
		t.Fatal(err)
	}
	initial, err := directorySHA256(root)
	if err != nil {
		t.Fatalf("目录内安全符号链接应允许: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "__pycache__"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "__pycache__", "demo.pyc"), []byte("cache"), 0o644); err != nil {
		t.Fatal(err)
	}
	withCache, err := directorySHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	if withCache != initial {
		t.Fatal("Python 运行时缓存不应改变目录哈希")
	}
	if err := os.Symlink(filepath.Join(root, ".."), filepath.Join(root, "escape-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := directorySHA256(root); err == nil {
		t.Fatal("越界符号链接必须拒绝")
	}
}

type tarTestFile struct {
	data []byte
	mode os.FileMode
}

func makeTarGZ(t *testing.T, files map[string]tarTestFile) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, file := range files {
		header := &tar.Header{
			Name:     name,
			Mode:     int64(file.mode.Perm()),
			Size:     int64(len(file.data)),
			Typeflag: tar.TypeReg,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}
