package toolrunner

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeToolFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("写入 %s 失败: %v", name, err)
	}
}

func TestLoadDirAndInputSchema(t *testing.T) {
	dir := t.TempDir()
	writeToolFile(t, dir, "README.md", "not a tool")
	writeToolFile(t, dir, "demo.yaml", `
name: "demo"
command: "echo"
enabled: true
short_description: "演示工具"
description: |
  第一行
  第二行
parameters:
  - name: "target"
    type: "string"
    description: "目标"
    required: true
    flag: "-t"
    format: "flag"
  - name: "verbose"
    type: "bool"
    description: "详细输出"
    required: false
    flag: "-v"
`)
	writeToolFile(t, dir, "disabled.yaml", `
name: "disabled"
command: "false"
enabled: false
description: "禁用工具"
`)

	tools, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("应加载 2 个工具，实际 %d", len(tools))
	}
	if tools[0].Name != "demo" || tools[1].Name != "disabled" {
		t.Fatalf("工具应按名称排序: %+v", tools)
	}

	demo := tools[0]
	if demo.Summary() != "演示工具" {
		t.Fatalf("Summary 应优先 short_description: %q", demo.Summary())
	}
	schema := demo.InputSchema()
	properties, ok := schema["properties"].(map[string]any)
	if !ok || len(properties) != 2 {
		t.Fatalf("schema properties 不正确: %+v", schema)
	}
	required, ok := schema["required"].([]string)
	if !ok || !reflect.DeepEqual(required, []string{"target"}) {
		t.Fatalf("required 不正确: %+v", schema["required"])
	}
}

func TestLoadDirParsesRuntimeRequirementsAndTimeout(t *testing.T) {
	dir := t.TempDir()
	writeToolFile(t, dir, "heavy.yaml", `
name: "heavy"
command: "nmap"
enabled: true
description: "重扫描工具"
timeout_seconds: 900
requires_binaries: ["nmap", " nmap ", ""]
requires_python: [" impacket "]
`)
	writeToolFile(t, dir, "clamped.yaml", `
name: "clamped"
command: "echo"
enabled: true
description: "超时上限收敛"
timeout_seconds: 99999
`)

	tools, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	byName := map[string]Tool{}
	for _, item := range tools {
		byName[item.Name] = item
	}
	heavy := byName["heavy"]
	if heavy.TimeoutSeconds != 900 {
		t.Fatalf("timeout_seconds 解析错误: %d", heavy.TimeoutSeconds)
	}
	if !reflect.DeepEqual(heavy.RequiresBinaries, []string{"nmap"}) {
		t.Fatalf("requires_binaries 未去重去空: %#v", heavy.RequiresBinaries)
	}
	if !reflect.DeepEqual(heavy.RequiresPython, []string{"impacket"}) {
		t.Fatalf("requires_python 未清理: %#v", heavy.RequiresPython)
	}
	if clamped := byName["clamped"].TimeoutSeconds; clamped != 3600 {
		t.Fatalf("超长 timeout_seconds 应被收敛到 3600，实际 %d", clamped)
	}
}

func TestSummaryFallsBackToDescription(t *testing.T) {
	item := Tool{Description: "短描述行\n更多详细内容"}
	if item.Summary() != "短描述行" {
		t.Fatalf("Summary 应回退到描述首行: %q", item.Summary())
	}
}
