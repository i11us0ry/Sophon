package skillaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTemplateIsCompliant(t *testing.T) {
	result := AuditContent("demo", Template("demo", "demo methodology"), "skills/demo/SKILL.md")
	if !result.Compliant {
		t.Fatalf("默认模板应通过审计: %+v", result.Issues)
	}
}

func TestAuditDetectsCommandHeavySkill(t *testing.T) {
	content := "---\n" +
		"name: command-only\n" +
		"description: command only\n" +
		"---\n" +
		"# command-only\n\n" +
		"```\n" +
		"curl https://a\n" +
		"curl https://b\n" +
		"nmap target\n" +
		"sqlmap -u target\n" +
		"nuclei -u target\n" +
		"```\n\n" +
		"必须按以下步骤执行。\n"
	result := AuditContent("command-only", content, "skills/command-only/SKILL.md")
	codes := map[string]bool{}
	for _, issue := range result.Issues {
		codes[issue.Code] = true
	}
	for _, want := range []string{
		"missing_applicability",
		"missing_core_judgment",
		"missing_evidence_standard",
		"missing_decision_tree",
		"command_heavy_without_methodology",
		"forced_workflow",
	} {
		if !codes[want] {
			t.Fatalf("缺少审计问题 %s: %+v", want, result.Issues)
		}
	}
	if result.Compliant {
		t.Fatal("缺少方法论章节的 Skill 不应判定为 compliant")
	}
}

func TestAuditDirSkipsFilesAndSortsSkills(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "METHODOLOGY_TEMPLATE.md"), []byte("template"), 0o600); err != nil {
		t.Fatalf("写入模板失败: %v", err)
	}
	for _, name := range []string{"zeta", "alpha"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("创建目录失败: %v", err)
		}
		content := Template(name, name+" methodology")
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(content), 0o600); err != nil {
			t.Fatalf("写入 Skill 失败: %v", err)
		}
	}
	report, err := AuditDir(root)
	if err != nil {
		t.Fatalf("审计目录失败: %v", err)
	}
	if report.Total != 2 || report.Compliant != 2 || report.NonCompliant != 0 {
		t.Fatalf("审计统计错误: %+v", report)
	}
	if report.Results[0].Name != "alpha" || report.Results[1].Name != "zeta" {
		t.Fatalf("审计结果排序错误: %+v", report.Results)
	}
}

func TestTemplateEscapesDescription(t *testing.T) {
	content := Template("demo", "line one: line two")
	if !strings.Contains(content, `description: "line one: line two"`) {
		t.Fatalf("description 未被安全引用: %s", content)
	}
}
