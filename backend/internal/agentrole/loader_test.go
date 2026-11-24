package agentrole

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestSyncFromDirPreservesActiveOverridesAndRestoresDeletedRole(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rolesDir := t.TempDir()
	yamlContent := []byte(`name: 内置测试角色
description: YAML 描述
user_prompt: YAML 提示词
icon: "1"
default_mode: deep
skills:
  - demo-skill
  - " demo-skill "
  - recon-skill
enabled: false
`)
	if err := os.WriteFile(filepath.Join(rolesDir, "test.yaml"), yamlContent, 0o600); err != nil {
		t.Fatalf("写入角色 YAML 失败: %v", err)
	}
	ctx := context.Background()
	if err := SyncFromDir(ctx, db, rolesDir); err != nil {
		t.Fatalf("首次同步失败: %v", err)
	}
	role, err := db.GetAgentRoleByName(ctx, "内置测试角色")
	if err != nil {
		t.Fatalf("读取内置角色失败: %v", err)
	}
	if !role.Builtin || role.Enabled || role.Prompt != "YAML 提示词" || role.DefaultMode != "deep" {
		t.Fatalf("首次导入状态错误: %+v", role)
	}
	if len(role.Skills) != 2 || role.Skills[0] != "demo-skill" || role.Skills[1] != "recon-skill" {
		t.Fatalf("首次导入技能绑定错误: %+v", role.Skills)
	}

	role.Description = "用户修改描述"
	role.Prompt = "用户修改提示词"
	role.Icon = "2"
	role.DefaultMode = "fast"
	role.Skills = []string{"user-skill"}
	role.Enabled = true
	role.UpdatedAt = time.Now().UTC()
	if err := db.UpdateAgentRole(ctx, *role); err != nil {
		t.Fatalf("修改角色失败: %v", err)
	}
	if err := SyncFromDir(ctx, db, rolesDir); err != nil {
		t.Fatalf("重复同步失败: %v", err)
	}
	stored, err := db.GetAgentRole(ctx, role.ID)
	if err != nil {
		t.Fatalf("读取修改角色失败: %v", err)
	}
	if stored.Description != "用户修改描述" || stored.Prompt != "用户修改提示词" ||
		stored.Icon != "2" || !stored.Enabled ||
		stored.DefaultMode != "fast" ||
		len(stored.Skills) != 1 || stored.Skills[0] != "user-skill" {
		t.Fatalf("同步不应覆盖有效角色的用户修改: %+v", stored)
	}

	if err := db.DeleteAgentRole(ctx, role.ID); err != nil {
		t.Fatalf("软删除角色失败: %v", err)
	}
	if _, err := db.GetAgentRole(ctx, role.ID); !database.NoRows(err) {
		t.Fatalf("软删除角色不应通过有效角色查询，实际 %v", err)
	}
	if err := SyncFromDir(ctx, db, rolesDir); err != nil {
		t.Fatalf("恢复同步失败: %v", err)
	}
	restored, err := db.GetAgentRole(ctx, role.ID)
	if err != nil {
		t.Fatalf("软删除角色应被恢复: %v", err)
	}
	if restored.Prompt != "YAML 提示词" || restored.Enabled || !restored.Builtin ||
		restored.DefaultMode != "deep" ||
		len(restored.Skills) != 1 || restored.Skills[0] != "user-skill" {
		t.Fatalf("恢复后的内置角色状态错误: %+v", restored)
	}
}

func TestSyncFromDirSkipsRoleWithInvalidSkillName(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	rolesDir := t.TempDir()
	yamlContent := []byte("name: 非法技能角色\nuser_prompt: 测试\nskills:\n  - invalid skill\n")
	if err := os.WriteFile(filepath.Join(rolesDir, "test.yaml"), yamlContent, 0o600); err != nil {
		t.Fatalf("写入角色 YAML 失败: %v", err)
	}
	if err := SyncFromDir(context.Background(), db, rolesDir); err != nil {
		t.Fatalf("同步非法技能角色不应中断其他角色: %v", err)
	}
	if _, err := db.GetAgentRoleByName(context.Background(), "非法技能角色"); !database.NoRows(err) {
		t.Fatalf("非法技能角色不应被导入，实际 %v", err)
	}
}

func TestSyncFromDirUpgradesLegacyMandatorySkillGate(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateAgentRole(ctx, database.AgentRole{
		ID:          "legacy-java-role",
		Name:        "Java代码审计",
		Description: "用户保留的描述",
		Prompt:      "自定义前缀\n必须先读取并使用 java-code-audit 总控技能，再按需加载路由、鉴权、调用链和漏洞专项技能。\n自定义后缀",
		Icon:        "1",
		DefaultMode: "auto",
		Builtin:     true,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建旧角色失败: %v", err)
	}
	rolesDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(rolesDir, "java.yaml"),
		[]byte("name: Java代码审计\nuser_prompt: 新 YAML 提示词\nskills: []\n"),
		0o600,
	); err != nil {
		t.Fatalf("写入角色 YAML 失败: %v", err)
	}
	if err := SyncFromDir(ctx, db, rolesDir); err != nil {
		t.Fatalf("同步角色失败: %v", err)
	}
	role, err := db.GetAgentRole(ctx, "legacy-java-role")
	if err != nil {
		t.Fatalf("读取迁移角色失败: %v", err)
	}
	if strings.Contains(role.Prompt, "必须先读取") {
		t.Fatalf("旧强制技能门禁未被清理: %s", role.Prompt)
	}
	if !strings.Contains(role.Prompt, "自定义前缀") ||
		!strings.Contains(role.Prompt, "自定义后缀") ||
		!strings.Contains(role.Prompt, "可选的方法论参考") {
		t.Fatalf("迁移应保留用户自定义内容并替换强制门禁: %s", role.Prompt)
	}
}

func TestSyncFromDirUpgradesLegacyTaskProfileIdentityPrompt(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	legacyPrompt := `你是 Sophon 的 Java 代码审计角色，仅分析用户授权的本地源码、JAR、WAR 或已反编译代码。
默认只做静态审计，不访问目标服务，不发送真实请求，不执行未知代码。
java-code-audit、路由、鉴权、调用链和漏洞专项技能都是可选的方法论参考；可根据证据缺口和审计收益按需读取，不必先读总控技能。
审计流程为：快速匹配、路由提取、鉴权审计、组件漏洞、调用链追踪、专项漏洞检测、利用链分析与报告。
所有结论必须给出文件、类、方法、关键行和参数流向证据，区分已确认、需验证和模式命中。
利用链只是基于静态证据的候选链，未做授权运行时验证时不得标记为已确认利用。
不得默认联网查询 OSV.dev；只有用户明确授权网络访问后才能使用在线查询。
禁止自动安装 Java、Python 包、CFR 或其他依赖，缺少依赖时说明阻塞。
分拆任务时只使用 pent_agent_execute 的只读或可写模式，不启动主动测试。
产物必须写入当前会话工作区内的输出目录，遵守 Mission Policy。`
	if err := db.CreateAgentRole(ctx, database.AgentRole{
		ID:          "legacy-java-profile",
		Name:        "Java代码审计",
		Description: "Java 审计",
		Prompt:      legacyPrompt,
		Icon:        "1",
		Builtin:     true,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建旧 Task Profile 失败: %v", err)
	}
	rolesDir := t.TempDir()
	newPrompt := "适用场景：Java Web 源码审计。该模板只提供审计方法，不改变系统 Agent 身份。"
	if err := os.WriteFile(
		filepath.Join(rolesDir, "java.yaml"),
		[]byte("name: Java代码审计\nuser_prompt: "+newPrompt+"\nskills: []\n"),
		0o600,
	); err != nil {
		t.Fatalf("写入 Task Profile YAML 失败: %v", err)
	}
	if err := SyncFromDir(ctx, db, rolesDir); err != nil {
		t.Fatalf("同步 Task Profile 失败: %v", err)
	}
	role, err := db.GetAgentRole(ctx, "legacy-java-profile")
	if err != nil {
		t.Fatalf("读取迁移后的 Task Profile 失败: %v", err)
	}
	if role.Prompt != newPrompt {
		t.Fatalf("旧身份型 Prompt 未迁移: %q", role.Prompt)
	}
}

func TestSyncFromDirPreservesEditedLegacyTaskProfilePrompt(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	customPrompt := "你是 Sophon 的 Java 代码审计角色。\n用户自定义的唯一审计流程必须保留。"
	if err := db.CreateAgentRole(ctx, database.AgentRole{
		ID:          "edited-java-profile",
		Name:        "Java代码审计",
		Description: "Java 审计",
		Prompt:      customPrompt,
		Icon:        "1",
		Builtin:     true,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建已编辑 Task Profile 失败: %v", err)
	}
	rolesDir := t.TempDir()
	newPrompt := "适用场景：Java Web 源码审计。"
	if err := os.WriteFile(
		filepath.Join(rolesDir, "java.yaml"),
		[]byte("name: Java代码审计\nuser_prompt: "+newPrompt+"\nskills: []\n"),
		0o600,
	); err != nil {
		t.Fatalf("写入 Task Profile YAML 失败: %v", err)
	}
	if err := SyncFromDir(ctx, db, rolesDir); err != nil {
		t.Fatalf("同步 Task Profile 失败: %v", err)
	}
	role, err := db.GetAgentRole(ctx, "edited-java-profile")
	if err != nil {
		t.Fatalf("读取已编辑 Task Profile 失败: %v", err)
	}
	if role.Prompt != customPrompt {
		t.Fatalf("用户编辑过的 Prompt 被覆盖: %q", role.Prompt)
	}
}
