package policy

import (
	"os"
	"path/filepath"
	"testing"

	"sophon/internal/database"
)

func TestPythonImportedModuleTargetsFeedPolicyEngine(t *testing.T) {
	workspace := t.TempDir()
	writePolicyPythonFile(t, workspace, "jx.py", `
import urllib.request
TARGET = "https://yxexam.jsmc.edu.cn/webservices/DataSynchronization.asmx"

def raw(value):
    return urllib.request.urlopen(TARGET)
`)
	script := `
import sys
sys.path.insert(0, ".")
import jx
query = "SELECT COUNT(*) FROM msdb.dbo.sysjobs"
jx.raw(query)
`
	targets := targetsForTool("execute-python-script", map[string]interface{}{
		"script":            script,
		"_sophon_workspace": workspace,
	})
	if len(targets) != 1 || targets[0] != "yxexam.jsmc.edu.cn" {
		t.Fatalf("应提取 imported module 中的真实目标: %#v", targets)
	}
	if targets[0] == "msdb.dbo.sysjobs" {
		t.Fatalf("SQL 对象名不应进入目标列表")
	}
	scope := newScope([]database.Asset{{
		Value: "yxexam.jsmc.edu.cn",
	}})
	if !scope.Allows(targets[0]) {
		t.Fatalf("项目授权目标应允许: %s", targets[0])
	}
	outOfScope := newScope([]database.Asset{{
		Value: "other.example.com",
	}})
	if outOfScope.Allows(targets[0]) {
		t.Fatalf("导入模块中的范围外目标不应被放行: %s", targets[0])
	}
}

func TestPythonImportedModulesRecursivelyExtractTargets(t *testing.T) {
	workspace := t.TempDir()
	writePolicyPythonFile(t, workspace, "first.py", "import second\n")
	writePolicyPythonFile(t, workspace, "second.py", `
TARGET = "https://deep.example.com/api"
`)
	analysis := AnalyzePythonScriptInWorkspace(
		"import first\nfirst.run()\n",
		workspace,
	)
	found := false
	for _, target := range analysis.Targets {
		if target == "deep.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("递归 import 目标未提取: %#v", analysis.Targets)
	}
}

func TestPythonImportScannerRejectsSymlinkEscape(t *testing.T) {
	workspace := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.py")
	if err := os.WriteFile(outside, []byte(`TARGET = "https://outside.example.com"`), 0o600); err != nil {
		t.Fatalf("写入范围外模块失败: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(workspace, "evil.py")); err != nil {
		t.Skipf("当前系统不支持符号链接测试: %v", err)
	}
	analysis := AnalyzePythonScriptInWorkspace("import evil\nevil.run()\n", workspace)
	for _, target := range analysis.Targets {
		if target == "outside.example.com" {
			t.Fatalf("不应读取 workspace 外的符号链接模块: %#v", analysis.Targets)
		}
	}
}

func writePolicyPythonFile(t *testing.T, root string, name string, content string) {
	t.Helper()
	target := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatalf("创建模块目录失败: %v", err)
	}
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("写入 Python 模块失败: %v", err)
	}
}
