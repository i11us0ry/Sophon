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
	mainRole, err := db.GetAgentRole(ctx, SystemMainAgentID)
	if err != nil {
		t.Fatalf("读取主 Agent 失败: %v", err)
	}
	if mainRole.Name != SystemMainAgentName || !mainRole.Enabled || !mainRole.Builtin ||
		mainRole.Prompt != mainAgentPrompt || mainRole.Icon != "◈" {
		t.Fatalf("主 Agent 初始状态错误: %+v", mainRole)
	}
	if SystemAgentEditableForRole(*mainRole) || SystemAgentDisableableForRole(*mainRole) {
		t.Fatalf("主 Agent 必须只读且不可停用")
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
	retestRole, err := db.GetAgentRole(ctx, SystemRetestAgentID)
	if err != nil {
		t.Fatalf("读取漏洞复测 Agent 失败: %v", err)
	}
	if retestRole.Name != SystemRetestAgentName || !retestRole.Enabled || !retestRole.Builtin ||
		retestRole.Prompt != retestAgentPrompt || retestRole.Icon != "🔁" {
		t.Fatalf("漏洞复测 Agent 初始状态错误: %+v", retestRole)
	}
	if SystemAgentEditableForRole(*retestRole) || SystemAgentDisableableForRole(*retestRole) {
		t.Fatalf("漏洞复测 Agent 必须只读且不可停用")
	}
	reviewerRole, err := db.GetAgentRole(ctx, SystemVulnerabilityReviewerID)
	if err != nil {
		t.Fatalf("读取漏洞审核失败: %v", err)
	}
	if reviewerRole.Name != SystemVulnerabilityReviewerName || !reviewerRole.Enabled || !reviewerRole.Builtin ||
		reviewerRole.Prompt != vulnerabilityReviewerPrompt {
		t.Fatalf("漏洞审核初始状态错误: %+v", reviewerRole)
	}
	writerRole, err := db.GetAgentRole(ctx, SystemVulnerabilityWriterID)
	if err != nil {
		t.Fatalf("读取漏洞编写失败: %v", err)
	}
	if writerRole.Name != SystemVulnerabilityWriterName || !writerRole.Enabled || !writerRole.Builtin ||
		writerRole.Prompt != vulnerabilityWriterPrompt ||
		!SystemAgentEditableForRole(*writerRole) ||
		SystemAgentDisableableForRole(*writerRole) {
		t.Fatalf("漏洞编写初始状态错误: %+v", writerRole)
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
		{SystemVulnerabilityWriterID, SystemVulnerabilityWriterName, vulnerabilityWriterPrompt},
		{SystemDeepPathPlannerID, SystemDeepPathPlannerName, deepPathPlannerAgentPrompt},
		{SystemDeepPathWorkerID, SystemDeepPathWorkerName, deepPathWorkerAgentPrompt},
	} {
		role, err := db.GetAgentRole(ctx, expected.id)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", expected.name, err)
		}
		if role.Name != expected.name || !role.Enabled || !role.Builtin || role.Prompt != expected.prompt {
			t.Fatalf("%s 初始状态错误: %+v", expected.name, role)
		}
	}

	service := &Service{db: db}
	for _, expected := range []struct {
		id     string
		name   string
		prompt string
	}{
		{SystemDeepPathPlannerID, SystemDeepPathPlannerName, deepPathPlannerAgentPrompt},
		{SystemDeepPathWorkerID, SystemDeepPathWorkerName, deepPathWorkerAgentPrompt},
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

func TestVulnerabilityWriterPromptSeedUpgradePreservesCustomization(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "vulnerability-writer-prompt.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("初始化系统 Agent 失败: %v", err)
	}
	role, err := db.GetAgentRole(ctx, SystemVulnerabilityWriterID)
	if err != nil {
		t.Fatalf("读取漏洞编写 Agent 失败: %v", err)
	}
	oldPrompt := strings.Replace(
		vulnerabilityWriterPrompt,
		"只写实际依赖如需要普通账户、管理员权限、目标开启什么配置等",
		"只写实际依赖",
		1,
	)
	role.Prompt = oldPrompt
	if err := db.UpdateAgentRole(ctx, *role); err != nil {
		t.Fatalf("写入旧版 Prompt 失败: %v", err)
	}
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("升级旧版 Prompt 失败: %v", err)
	}
	upgraded, err := db.GetAgentRole(ctx, SystemVulnerabilityWriterID)
	if err != nil || upgraded.Prompt != vulnerabilityWriterPrompt {
		t.Fatalf("旧版 Prompt 未升级: %+v err=%v", upgraded, err)
	}

	customPrompt := vulnerabilityWriterPrompt + "\n\n自定义补充：仅整理已验证证据。"
	upgraded.Prompt = customPrompt
	if err := db.UpdateAgentRole(ctx, *upgraded); err != nil {
		t.Fatalf("写入自定义 Prompt 失败: %v", err)
	}
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("再次初始化失败: %v", err)
	}
	preserved, err := db.GetAgentRole(ctx, SystemVulnerabilityWriterID)
	if err != nil || preserved.Prompt != customPrompt {
		t.Fatalf("自定义 Prompt 不应被覆盖: %+v err=%v", preserved, err)
	}
}

func TestLegacyDeepPathSubAgentRoleIsRetired(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "legacy-deep-path-subagent.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateAgentRole(ctx, database.AgentRole{
		ID: legacyDeepPathSubAgentID, Name: "Deep Path 子 Agent",
		Prompt: pentSubAgentPrompt, Builtin: true, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建旧角色失败: %v", err)
	}
	if err := EnsureSystemAgentRoles(ctx, db); err != nil {
		t.Fatalf("执行系统角色迁移失败: %v", err)
	}
	legacy, err := db.GetAgentRoleIncludingDeleted(ctx, legacyDeepPathSubAgentID)
	if err != nil || legacy == nil || !legacy.Deleted {
		t.Fatalf("旧 Deep Path 子 Agent 应被删除: %+v err=%v", legacy, err)
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
				"任务图变化时被频繁唤醒",
				"硬底线",
				"允许产出 0 个假设",
				"project_prove_goal",
				"project_plan_hypotheses",
				"asset_id",
				"parent_ids",
				"dimension",
				"technique",
				"rationale",
				"expected_evidence",
				"priority",
				"required",
				"Planner 不做执行",
				"本轮 planning_task 如下",
			},
		},
		{
			name:   "worker",
			prompt: deepPathWorkerAgentPrompt,
			phrases: []string{
				"唯一职责是完成这一条意图",
				"边发现边写回",
				"project_insert_assets",
				"project_record_fact",
				"project_report_finding",
				"vulnerability_type=\"弱口令\"",
				"project_complete_hypothesis",
				"observed",
				"inferred",
				"状态映射",
				"project_start_hypothesis",
				"tested_clean",
				"suspicious",
				"confirmed",
				"install-python-package",
				"停止与返回",
				"不得通过 shell、Python、MCP、子 Agent 或等价工具绕过",
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

func TestMissionPolicyPromptOnlyDescribesEnforcedBoundaries(t *testing.T) {
	if len([]rune(missionPolicyAgentPrompt)) > 1200 {
		t.Fatalf("安全策略 Prompt 仍然过长: %d", len([]rune(missionPolicyAgentPrompt)))
	}
	for _, expected := range []string{
		"当前用户",
		"当前项目授权范围",
		"网络目标",
		"人工审批",
		"敏感凭据",
		"工具被拒绝时应说明具体原因并停止该操作",
		"你不需要额外制定安全流程",
	} {
		if !strings.Contains(missionPolicyAgentPrompt, expected) {
			t.Fatalf("安全策略 Prompt 缺少真实边界 %q", expected)
		}
	}
	for _, forbidden := range []string{
		"strings_out",
		"Planner",
		"Worker",
		"Shell 命令出现语法",
		"完成任务后立即停止",
	} {
		if strings.Contains(missionPolicyAgentPrompt, forbidden) {
			t.Fatalf("安全策略 Prompt 不应包含平台工作流程 %q", forbidden)
		}
	}
}

func TestRetestAgentPromptContainsRequiredOutputContract(t *testing.T) {
	if len([]rune(retestAgentPrompt)) < 2500 {
		t.Fatalf("漏洞复测 Agent Prompt 过短: %d", len([]rune(retestAgentPrompt)))
	}
	for _, phrase := range []string{
		"confirmed",
		"not_reproducible",
		"insufficient_evidence",
		"blocked",
		"project_get(resource=\"finding\")",
		"Python 3",
		"Burp Repeater",
		"敏感值脱敏",
		"不得编造",
		"最终输出格式",
	} {
		if !strings.Contains(retestAgentPrompt, phrase) {
			t.Fatalf("漏洞复测 Agent Prompt 缺少: %s", phrase)
		}
	}
}

func TestPlannerAndWorkerPreferPreloadedContext(t *testing.T) {
	for name, prompt := range map[string]string{
		"planner": deepPathPlannerAgentPrompt,
		"worker":  deepPathWorkerAgentPrompt,
	} {
		if !strings.Contains(prompt, "状态包") {
			t.Fatalf("%s Prompt 未要求优先使用预加载态势: %s", name, prompt)
		}
	}
	if !strings.Contains(deepPathPlannerAgentPrompt, "按需查询") {
		t.Fatalf("Planner Prompt 未要求按需查询缺失信息")
	}
	if !strings.Contains(deepPathPlannerAgentPrompt, "不重复全量查询") {
		t.Fatalf("Planner Prompt 未限制重复全量查询")
	}
	if strings.Contains(deepPathPlannerAgentPrompt, "validation_steps") {
		t.Fatalf("Planner Prompt 不应引用不存在的 validation_steps 字段")
	}
}

func TestPlannerAndWorkerUseDivergentThinkingWithoutFixedWorkflow(t *testing.T) {
	for name, prompt := range map[string]string{
		"planner": deepPathPlannerAgentPrompt,
		"worker":  deepPathWorkerAgentPrompt,
	} {
		for _, phrase := range []string{"扩散与变换思维", "无论当前是否已经取得成果", "本质不同"} {
			if !strings.Contains(prompt, phrase) {
				t.Fatalf("%s Prompt 缺少扩散思维准则 %q", name, phrase)
			}
		}
		if strings.Contains(prompt, "成果自查") || strings.Contains(prompt, "必须回答三个问题") {
			t.Fatalf("%s Prompt 不应把扩散思维写成固定检查流程", name)
		}
	}
	for _, phrase := range []string{"普遍性", "深入性", "扩散之后必须负责收敛"} {
		if !strings.Contains(deepPathPlannerAgentPrompt, phrase) {
			t.Fatalf("Planner Prompt 缺少全局扩散要求 %q", phrase)
		}
	}
	for _, phrase := range []string{"取得成果时", "没有成果或受阻时", "不自行扩大任务范围"} {
		if !strings.Contains(deepPathWorkerAgentPrompt, phrase) {
			t.Fatalf("Worker Prompt 缺少局部扩散边界 %q", phrase)
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
