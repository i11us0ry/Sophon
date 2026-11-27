package database

import (
	"strings"
	"testing"
)

func TestParseProjectBriefSeparatesSafetyConstraints(t *testing.T) {
	brief := ParseProjectBrief(`资产扩展：可以扫描端口、可以扫描域名
漏洞目标：优先 SQL 注入和未授权访问
权限目标：shell 和 webshell
安全红线：
- 禁止删除操作
- 禁止修改密码`)
	if len(brief.Goals) != 3 {
		t.Fatalf("应解析三个目标，实际 %+v", brief.Goals)
	}
	if len(brief.Constraints) != 2 {
		t.Fatalf("应解析两个安全约束，实际 %+v", brief.Constraints)
	}
	for _, goal := range brief.Goals {
		if strings.Contains(goal, "禁止") || strings.Contains(goal, "安全红线") {
			t.Fatalf("安全约束被错误建模为目标: %+v", brief.Goals)
		}
	}
	if brief.Constraints[0] != "禁止删除操作" || brief.Constraints[1] != "禁止修改密码" {
		t.Fatalf("安全约束内容错误: %+v", brief.Constraints)
	}
}

func TestProjectConstraintRefIsStable(t *testing.T) {
	first := ProjectConstraintRef("禁止修改密码")
	second := ProjectConstraintRef(" 禁止修改密码 ")
	if first != second || !strings.HasPrefix(first, "project-constraint:") {
		t.Fatalf("约束引用不稳定: %s %s", first, second)
	}
}
