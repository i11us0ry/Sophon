package toolcatalog

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogListsDefinitionsAndSources(t *testing.T) {
	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	installRoot := filepath.Join(root, "thirdTools")
	for _, dir := range []string{catalogDir, installRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bundledPath := filepath.Join(installRoot, "demo-bundled")
	if err := os.WriteFile(bundledPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeDefinition(t, toolsDir, "bundled.yaml", `
name: bundled-demo
command: `+bundledPath+`
enabled: true
short_description: bundled demo
`)
	writeDefinition(t, toolsDir, "system.yaml", `
name: system-demo
command: sh
enabled: true
short_description: system demo
`)
	writeDefinition(t, toolsDir, "disabled.yaml", `
name: disabled-demo
command: sh
enabled: false
short_description: disabled demo
`)

	items, err := New(catalogDir, installRoot, toolsDir).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("应列出 3 个工具，实际 %d", len(items))
	}
	byName := make(map[string]Status, len(items))
	for _, item := range items {
		byName[item.Name] = item
	}
	if item := byName["bundled-demo"]; item.Source != SourceBundled ||
		!item.Installed || item.State != "installed" || item.Installable {
		t.Fatalf("平台打包工具状态错误: %+v", item)
	}
	if item := byName["system-demo"]; item.Source != SourceBuiltin ||
		!item.Installed || item.State != "installed" || item.Installable {
		t.Fatalf("平台内置包装状态错误: %+v", item)
	}
	if item := byName["disabled-demo"]; item.Source != SourceDisabled ||
		item.Installed || item.State != "disabled" || item.Installable {
		t.Fatalf("停用工具状态错误: %+v", item)
	}
}

func TestCatalogReportsMissingPythonDependency(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 不可用")
	}
	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDefinition(t, toolsDir, "python.yaml", `
name: python-demo
command: python3
enabled: true
short_description: python demo
requires_python:
  - json
  - sophon_missing_module_for_test
`)

	items, err := New(catalogDir, filepath.Join(root, "thirdTools"), toolsDir).
		List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("应列出 1 个工具，实际 %d", len(items))
	}
	if items[0].Source != SourcePython ||
		items[0].State != "missing_dependency" || items[0].Installable {
		t.Fatalf("Python 依赖状态错误: %+v", items[0])
	}
}

func TestCatalogRejectsInstallForNonArtifactTool(t *testing.T) {
	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDefinition(t, toolsDir, "system.yaml", `
name: system-demo
command: sh
enabled: true
short_description: system demo
`)
	catalog := New(catalogDir, filepath.Join(root, "thirdTools"), toolsDir)
	if _, err := catalog.Install(context.Background(), "system-demo", false); err == nil {
		t.Fatal("非下载型工具不应允许从 Catalog 安装")
	}
}

func TestCatalogFallsBackForUnsupportedManifestArchitecture(t *testing.T) {
	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDefinition(t, toolsDir, "fallback.yaml", `
name: fallback-demo
command: sh
enabled: true
short_description: fallback demo
`)
	manifest := `
name: fallback-demo
version: 1.0.0
description: fallback demo
tool_definition: fallback.yaml
artifacts:
  linux-unsupported:
    url: https://example.com/demo
    sha256: 0000000000000000000000000000000000000000000000000000000000000000
    destination: demo
`
	if err := os.WriteFile(filepath.Join(catalogDir, "fallback.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	items, err := New(catalogDir, filepath.Join(root, "thirdTools"), toolsDir).
		List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("应列出 1 个工具，实际 %d", len(items))
	}
	item := items[0]
	if !item.Installed || item.Installable || item.State != "installed" ||
		!strings.Contains(item.Detail, "不支持当前架构") {
		t.Fatalf("不支持架构时应回退到现有工具状态: %+v", item)
	}
}

func TestCatalogPrefersExistingRuntimeCommand(t *testing.T) {
	root := t.TempDir()
	catalogDir := filepath.Join(root, "tools", "catalog")
	toolsDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(catalogDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeDefinition(t, toolsDir, "runtime.yaml", `
name: runtime-demo
command: "true"
enabled: true
short_description: runtime demo
`)
	manifest := `
name: runtime-demo
version: 1.0.0
description: runtime demo
tool_definition: runtime.yaml
artifacts:
  linux-arm64:
    url: https://example.com/demo.zip
    sha256: 0000000000000000000000000000000000000000000000000000000000000000
    destination: runtime-demo
`
	if err := os.WriteFile(filepath.Join(catalogDir, "runtime.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	items, err := New(catalogDir, filepath.Join(root, "thirdTools"), toolsDir).
		List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("应列出 1 个工具，实际 %d", len(items))
	}
	item := items[0]
	if !item.Installed || item.Installable || item.Source != SourceSystem ||
		item.State != "installed" {
		t.Fatalf("PATH 中已有命令时应优先识别: %+v", item)
	}
}

func TestCatalogIncludesAllRepositoryToolDefinitions(t *testing.T) {
	toolsDir := mergedRepositoryToolDir(t)
	items, err := New(
		filepath.Join(toolsDir, "catalog"),
		filepath.Join("..", "..", "..", "thirdTools"),
		toolsDir,
	).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 30 {
		t.Fatalf("Tool Catalog 应包含 30 个工具定义，实际 %d", len(items))
	}
	installable := make(map[string]bool)
	for _, item := range items {
		if item.Installable {
			installable[item.Name] = true
		}
	}
	for _, name := range []string{
		"suo5", "nuclei", "httpx", "katana", "naabu",
		"dirsearch", "urlfinder", "jadx_decompile", "ksubdomain",
		"hydra", "wafw00f", "whatweb", "john", "impacket", "sqlmap",
	} {
		if !installable[name] {
			t.Fatalf("工具 %s 应支持固定产物安装", name)
		}
	}
	if len(installable) != 15 {
		t.Fatalf("应有 15 个可安装工具，实际 %d", len(installable))
	}
}

func mergedRepositoryToolDir(t *testing.T) string {
	t.Helper()
	target := t.TempDir()
	for _, source := range []string{
		filepath.Join("..", "..", "..", "tools"),
		filepath.Join("..", "..", "..", "customTools", "definitions"),
	} {
		entries, err := os.ReadDir(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".yaml") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(source, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(target, entry.Name()), raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	catalogSource := filepath.Join("..", "..", "..", "tools", "catalog")
	entries, err := os.ReadDir(catalogSource)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "catalog"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(catalogSource, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target, "catalog", entry.Name()), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return target
}

func writeDefinition(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
