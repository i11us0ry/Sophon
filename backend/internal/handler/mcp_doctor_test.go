package handler

import (
	"reflect"
	"strings"
	"testing"

	"sophon/internal/toolrunner"
)

func TestRequiredBinariesMergesWrapperScriptAndDeclaration(t *testing.T) {
	def := toolrunner.Tool{
		Name:             "rpcclient",
		Command:          "python3",
		RequiresBinaries: []string{"smbclient", "rpcclient"},
		Args: []string{"-c", `
import subprocess
cmd = ["rpcclient", "-U", "user%pass", target]
subprocess.run(cmd, capture_output=True)
`},
	}
	got := requiredBinaries(def)
	want := []string{"rpcclient", "smbclient"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("外部命令提取错误: %#v", got)
	}
}

func TestRequiredPythonModulesMergesDeclaration(t *testing.T) {
	def := toolrunner.Tool{
		Name:           "pwntools",
		Command:        "python3",
		RequiresPython: []string{"pwn"},
		Args: []string{"-c", `
import sys
import httpx
`},
	}
	got := requiredPythonModules(def)
	want := []string{"httpx", "pwn", "sys"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Python 依赖合并错误: %#v", got)
	}
}

func TestScriptBinariesSkipsInterpreters(t *testing.T) {
	def := toolrunner.Tool{
		Name:    "demo",
		Command: "python3",
		Args: []string{"-c", `
import subprocess
cmd = ["bash", "-lc", "echo hi"]
subprocess.run(["nmap", "-sV", target])
`},
	}
	got := scriptBinaries(def)
	want := []string{"nmap"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("应只提取非解释器命令，实际 %#v", got)
	}
}

func TestClassifyDoctorToolStatuses(t *testing.T) {
	cases := []struct {
		name          string
		yamlEnabled   bool
		registered    bool
		dbEnabled     bool
		commandDetail string
		missingBins   []string
		missingCaps   []string
		missing       []string
		wantStatus    string
	}{
		{"定义停用", false, false, true, "", nil, nil, nil, doctorStatusDisabled},
		{"未注册", true, false, true, "", nil, nil, nil, doctorStatusDisabled},
		{"配置停用", true, true, false, "", nil, nil, nil, doctorStatusDisabled},
		{"命令缺失", true, true, true, "exec: sqlmap: executable file not found in $PATH", nil, nil, nil, doctorStatusMissingBinary},
		{"外部命令缺失", true, true, true, "", []string{"rpcclient"}, nil, nil, doctorStatusMissingDependency},
		{"能力缺失", true, true, true, "", nil, []string{"cap_net_raw"}, nil, doctorStatusMissingDependency},
		{"依赖缺失", true, true, true, "", nil, nil, []string{"httpx"}, doctorStatusMissingDependency},
		{"可用", true, true, true, "", nil, nil, nil, doctorStatusAvailable},
	}
	for _, item := range cases {
		status, detail := classifyDoctorTool(
			item.yamlEnabled,
			item.registered,
			item.dbEnabled,
			item.commandDetail,
			item.missingBins,
			item.missingCaps,
			item.missing,
		)
		if status != item.wantStatus {
			t.Fatalf("%s: 状态应为 %s，实际 %s（%s）", item.name, item.wantStatus, status, detail)
		}
		if strings.TrimSpace(detail) == "" {
			t.Fatalf("%s: 应返回说明文本", item.name)
		}
	}
}

func TestParseCapabilityMask(t *testing.T) {
	mask, err := parseCapabilityMask("00000000a80425fb")
	if err != nil {
		t.Fatalf("解析 capability mask 失败: %v", err)
	}
	if mask&(uint64(1)<<linuxCapabilityBits["cap_net_raw"]) == 0 {
		t.Fatalf("cap_net_raw 位未正确识别: %#x", mask)
	}
}

func TestFilterMissingCapabilities(t *testing.T) {
	got := filterMissingCapabilities(
		[]string{"cap_net_raw", "cap_net_admin"},
		[]string{"cap_net_raw"},
	)
	if !reflect.DeepEqual(got, []string{"cap_net_raw"}) {
		t.Fatalf("能力过滤错误: %#v", got)
	}
}

func TestPythonImportsSkipsOptionalDependencies(t *testing.T) {
	def := toolrunner.Tool{
		Name:    "http-framework-test",
		Command: "python3",
		Args: []string{"-c", `
import json
from typing import Dict

try:
    import httpx
except ImportError:
    raise

try:
    from charset_normalizer import from_bytes
except ImportError:
    charset_from_bytes = None

import chardet
`},
	}
	modules := pythonImports(def)
	joined := strings.Join(modules, ",")
	if !strings.Contains(joined, "httpx") {
		t.Fatalf("应识别必需模块 httpx: %v", modules)
	}
	for _, optional := range []string{"charset_normalizer", "chardet"} {
		if strings.Contains(joined, optional) {
			t.Fatalf("可选模块 %s 不应计入必需依赖: %v", optional, modules)
		}
	}
}

func TestInlinePythonScriptOnlyForPythonCommand(t *testing.T) {
	if got := inlinePythonScript(toolrunner.Tool{
		Command: "bash",
		Args:    []string{"-c", "echo hi"},
	}); got != "" {
		t.Fatalf("非 python 命令不应提取脚本: %q", got)
	}
	if got := inlinePythonScript(toolrunner.Tool{
		Command: "/usr/bin/python3",
		Args:    []string{"-c", "print(1)"},
	}); got != "print(1)" {
		t.Fatalf("应提取 python 内联脚本: %q", got)
	}
}
