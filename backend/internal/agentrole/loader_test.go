package agentrole

import (
	"context"
	"os"
	"path/filepath"
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
