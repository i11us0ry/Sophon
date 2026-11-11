package agent

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestSystemAgentRolesSeedCanonicalIdentityAndPrompt(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "system-agents.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("初始化系统 Agent 失败: %v", err)
	}
	intentRole, err := db.GetAgentRole(ctx, SystemIntentAgentID)
	if err != nil {
		t.Fatalf("读取意图审核失败: %v", err)
	}
	if intentRole.Name != SystemIntentAgentName || !intentRole.Enabled || !intentRole.Builtin ||
		intentRole.Prompt != intentRouterSystemPrompt {
		t.Fatalf("意图审核初始状态错误: %+v", intentRole)
	}
	reportRole, err := db.GetAgentRole(ctx, SystemReportAgentID)
	if err != nil {
		t.Fatalf("读取报告生成 Agent 失败: %v", err)
	}
	if reportRole.Name != SystemReportAgentName || !reportRole.Enabled || !reportRole.Builtin ||
		reportRole.Prompt != reportAgentPrompt || reportRole.Icon != "📄" {
		t.Fatalf("报告生成 Agent 初始状态错误: %+v", reportRole)
	}
	if SystemAgentEditableForRole(*reportRole) {
		t.Fatalf("报告生成 Agent 必须只读")
	}
	reviewerRole, err := db.GetAgentRole(ctx, SystemVulnerabilityReviewerID)
	if err != nil {
		t.Fatalf("读取漏洞审核失败: %v", err)
	}
	if reviewerRole.Name != SystemVulnerabilityReviewerName || !reviewerRole.Enabled || !reviewerRole.Builtin ||
		reviewerRole.Prompt != vulnerabilityReviewerPrompt {
		t.Fatalf("漏洞审核初始状态错误: %+v", reviewerRole)
	}
	policyRole, err := db.GetAgentRole(ctx, SystemMissionPolicyAgentID)
	if err != nil {
		t.Fatalf("读取安全审核失败: %v", err)
	}
	if policyRole.Name != SystemMissionPolicyAgentName || !policyRole.Enabled || !policyRole.Builtin ||
		policyRole.Prompt != missionPolicyAgentPrompt {
		t.Fatalf("安全审核初始状态错误: %+v", policyRole)
	}
	for _, expected := range []struct {
		id     string
		name   string
		prompt string
	}{
		{SystemDeepPathPlannerID, SystemDeepPathPlannerName, deepPathPlannerAgentPrompt},
		{SystemDeepPathWorkerID, SystemDeepPathWorkerName, deepPathWorkerAgentPrompt},
		{SystemDeepPathSubAgentID, SystemDeepPathSubAgentName, pentSubAgentPrompt},
	} {
		role, err := db.GetAgentRole(ctx, expected.id)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", expected.name, err)
		}
		if role.Name != expected.name || !role.Enabled || !role.Builtin || role.Prompt != expected.prompt {
			t.Fatalf("%s 初始状态错误: %+v", expected.name, role)
		}
	}

	editedPrompt := intentRole.Prompt + "\n用户补充规则：优先保持只读。"
	intentRole.Prompt = editedPrompt
	intentRole.Name = "临时意图名称"
	intentRole.Description = "被篡改的描述"
	intentRole.Icon = "x"
	intentRole.Enabled = false
	if err := db.UpdateAgentRole(ctx, *intentRole); err != nil {
		t.Fatalf("更新意图审核失败: %v", err)
	}
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("重复初始化系统 Agent 失败: %v", err)
	}
	stored, err := db.GetAgentRole(ctx, SystemIntentAgentID)
	if err != nil {
		t.Fatalf("读取更新后的意图审核失败: %v", err)
	}
	if stored.Name != SystemIntentAgentName ||
		stored.Description != "平台内置意图审核能力，负责识别任务模式、授权范围、阶段顺序和工具边界，不直接执行漏洞测试。" ||
		stored.Icon != "🧭" || !stored.Enabled || !stored.Builtin || stored.Prompt != intentRouterSystemPrompt {
		t.Fatalf("系统身份属性或 Prompt 基线未恢复: %+v", stored)
	}
	service := &Service{db: db}
	runtimePrompt := service.systemAgentPrompt(
		ctx,
		SystemIntentAgentID,
		SystemIntentAgentName,
		intentRouterSystemPrompt,
	)
	if runtimePrompt != intentRouterSystemPrompt || strings.Contains(runtimePrompt, "优先保持只读") {
		t.Fatalf("运行时应读取系统 Prompt 基线: %q", runtimePrompt)
	}
	for _, expected := range []struct {
		id     string
		name   string
		prompt string
	}{
		{SystemDeepPathPlannerID, SystemDeepPathPlannerName, deepPathPlannerAgentPrompt},
		{SystemDeepPathWorkerID, SystemDeepPathWorkerName, deepPathWorkerAgentPrompt},
		{SystemDeepPathSubAgentID, SystemDeepPathSubAgentName, pentSubAgentPrompt},
	} {
		got := service.systemAgentPrompt(ctx, expected.id, expected.name, "fallback")
		if got != expected.prompt {
			t.Fatalf("%s 运行时 Prompt 不一致: %q", expected.name, got)
		}
	}
}

func TestEditableVulnerabilityReviewerPromptPersists(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "editable-reviewer.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("初始化系统 Agent 失败: %v", err)
	}
	role, err := db.GetAgentRole(ctx, SystemVulnerabilityReviewerID)
	if err != nil {
		t.Fatalf("读取漏洞审核失败: %v", err)
	}
	role.Description = "用户自定义审核描述"
	role.Prompt = "用户自定义审核规则：仅拒绝 self-XSS"
	role.Icon = "x"
	role.Enabled = false
	role.DefaultMode = "deep"
	if err := db.UpdateAgentRole(ctx, *role); err != nil {
		t.Fatalf("更新漏洞审核角色失败: %v", err)
	}
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("重复初始化系统 Agent 失败: %v", err)
	}
	stored, err := db.GetAgentRole(ctx, SystemVulnerabilityReviewerID)
	if err != nil {
		t.Fatalf("读取更新后的漏洞审核失败: %v", err)
	}
	if stored.Description != role.Description ||
		stored.Prompt != role.Prompt ||
		stored.Icon != role.Icon ||
		stored.DefaultMode != "deep" ||
		stored.Enabled ||
		!stored.Builtin {
		t.Fatalf("可编辑、可停用漏洞审核角色未正确持久化: %+v", stored)
	}
	if !SystemAgentEditableForRole(*stored) {
		t.Fatalf("漏洞审核角色应标记为可编辑")
	}
	if !SystemAgentDisableableForRole(*stored) {
		t.Fatalf("漏洞审核角色应允许停用")
	}
}

func TestSystemAgentRolesResolveActiveAndDeletedNameConflicts(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "system-agent-conflict.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateAgentRole(ctx, database.AgentRole{
		ID:          "active-custom-vulnerability-review",
		Name:        SystemVulnerabilityReviewerName,
		Description: "有效自定义漏洞审核角色",
		Prompt:      "有效自定义提示词",
		Icon:        "",
		Skills:      []string{},
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建有效名称冲突角色失败: %v", err)
	}
	if err := db.CreateAgentRole(ctx, database.AgentRole{
		ID:          "deleted-custom-policy",
		Name:        SystemMissionPolicyAgentName,
		Description: "历史自定义安全审核角色",
		Prompt:      "历史自定义提示词",
		Icon:        "",
		Skills:      []string{},
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建历史名称冲突角色失败: %v", err)
	}
	if err := db.DeleteAgentRole(ctx, "deleted-custom-policy"); err != nil {
		t.Fatalf("软删除历史名称冲突角色失败: %v", err)
	}
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("初始化系统 Agent 失败: %v", err)
	}
	reviewer, err := db.GetAgentRole(ctx, SystemVulnerabilityReviewerID)
	if err != nil || reviewer.Name != SystemVulnerabilityReviewerName {
		t.Fatalf("漏洞审核系统 Agent 未使用新名称: %+v err=%v", reviewer, err)
	}
	activeConflict, err := db.GetAgentRole(ctx, "active-custom-vulnerability-review")
	if err != nil || !activeConflict.Enabled ||
		activeConflict.Name != SystemVulnerabilityReviewerName+"（名称冲突-active-custom-vulnerability-review）" {
		t.Fatalf("有效名称冲突角色未安全改名: %+v err=%v", activeConflict, err)
	}
	deletedConflict, err := db.GetAgentRoleByName(
		ctx,
		SystemMissionPolicyAgentName+"（名称冲突-deleted-custom-policy）",
	)
	if err != nil || !deletedConflict.Deleted {
		t.Fatalf("历史名称冲突角色未归档: %+v err=%v", deletedConflict, err)
	}
}

func TestSystemAgentRolesDoNotTreatLegacyNameAsSystem(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "system-agent-legacy-name.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("初始化系统 Agent 失败: %v", err)
	}
	now := time.Now().UTC()
	if err := db.CreateAgentRole(ctx, database.AgentRole{
		ID:          "custom-legacy-intent-name",
		Name:        "意图 Agent",
		Description: "普通自定义角色",
		Prompt:      "普通提示词",
		Icon:        "",
		Skills:      []string{},
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建旧名称普通角色失败: %v", err)
	}
	role, err := db.GetAgentRole(ctx, "custom-legacy-intent-name")
	if err != nil {
		t.Fatalf("读取旧名称普通角色失败: %v", err)
	}
	if _, isSystem := SystemAgentDefinitionForRole(*role); isSystem {
		t.Fatalf("旧系统名称不应把普通角色识别为系统 Agent: %+v", role)
	}
}

func TestSystemAgentRolesPersistBuiltinAndRestoreDeletedRole(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "system-agent-restore.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateAgentRole(ctx, database.AgentRole{
		ID:          SystemMissionPolicyAgentID,
		Name:        SystemMissionPolicyAgentName,
		Description: "旧描述",
		Prompt:      "被修改的旧 Prompt",
		Icon:        "x",
		Skills:      []string{},
		Builtin:     false,
		Enabled:     false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建待恢复系统角色失败: %v", err)
	}
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("修复系统角色失败: %v", err)
	}
	role, err := db.GetAgentRole(ctx, SystemMissionPolicyAgentID)
	if err != nil || !role.Builtin || !role.Enabled || role.Prompt != missionPolicyAgentPrompt {
		t.Fatalf("系统角色 builtin 或 Prompt 基线未持久化: %+v err=%v", role, err)
	}
	role.Prompt = "再次篡改"
	if err := db.UpdateAgentRole(ctx, *role); err != nil {
		t.Fatalf("修改系统角色 Prompt 失败: %v", err)
	}
	if err := db.DeleteAgentRole(ctx, SystemMissionPolicyAgentID); err != nil {
		t.Fatalf("软删除系统角色失败: %v", err)
	}
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("恢复系统角色失败: %v", err)
	}
	restored, err := db.GetAgentRole(ctx, SystemMissionPolicyAgentID)
	if err != nil || !restored.Builtin || !restored.Enabled || restored.Prompt != missionPolicyAgentPrompt {
		t.Fatalf("软删除系统角色未完整恢复: %+v err=%v", restored, err)
	}
}

func TestDeepPathAgentPromptsContainOperationalContracts(t *testing.T) {
	checks := []struct {
		name    string
		prompt  string
		phrases []string
	}{
		{
			name:   "planner",
			prompt: deepPathPlannerAgentPrompt,
			phrases: []string{
				"核心职责",
				"执行流程",
				"规划优先级",
				"假设契约",
				"project_plan_hypotheses",
				"expected_evidence",
				"写回与去重",
				"禁止事项",
				"停止条件",
				"输出格式",
			},
		},
		{
			name:   "worker",
			prompt: deepPathWorkerAgentPrompt,
			phrases: []string{
				"执行前检查",
				"执行流程",
				"证据标准",
				"状态映射",
				"project_start_hypothesis",
				"project_complete_hypothesis",
				"没有成果",
				"没有下一步思路",
				"不是检查项上限",
				"tested_clean",
				"suspicious",
				"confirmed",
				"禁止事项",
				"停止条件",
				"输出格式",
			},
		},
	}
	for _, check := range checks {
		if len([]rune(check.prompt)) < 800 {
			t.Fatalf("%s Prompt 仍然过短: %d", check.name, len([]rune(check.prompt)))
		}
		for _, phrase := range check.phrases {
			if !strings.Contains(check.prompt, phrase) {
				t.Fatalf("%s Prompt 缺少关键契约 %q", check.name, phrase)
			}
		}
	}
}

func TestReportAgentPromptContainsExportContract(t *testing.T) {
	if len([]rune(reportAgentPrompt)) < 3000 {
		t.Fatalf("报告生成 Agent Prompt 过短: %d", len([]rune(reportAgentPrompt)))
	}
	for _, phrase := range []string{
		"基本边界",
		"数据来源",
		"总体信息架构",
		"主报告 + 漏洞卡片 + 证据附录",
		"VUL-YYYY-001",
		"第5章先按严重程度分组",
		"漏洞卡片",
		"证据分层",
		"附录A 证据索引",
		"附录B 复现与IL证据",
		"正文格式",
		"white-space: pre-wrap",
		"实际换行生成独立Word段落",
		"代码围栏",
		"版式规范",
		"导出前质量检查",
		"表格最多六列",
		"上下页边距2.5厘米",
		"证据索引",
		"未经证据支持的安全结论",
	} {
		if !strings.Contains(reportAgentPrompt, phrase) {
			t.Fatalf("报告生成 Agent Prompt 缺少关键契约 %q", phrase)
		}
	}
}
