package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestRoleInstructionIncludesPromptAndSkills(t *testing.T) {
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	skillDir := filepath.Join(dir, "skills", "demo-skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("create skill dir: %v", err)
	}
	skillContent := "---\nname: demo-skill\ndescription: 演示技能说明\n---\n\n## demo-skill\n"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(skillContent), 0o644); err != nil {
		t.Fatalf("write skill: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.UpsertAgentRole(ctx, database.AgentRole{
		ID:          "role-1",
		Name:        "tester",
		Description: "测试角色",
		Prompt:      "你是测试角色。",
		Skills:      []string{"demo-skill"},
		Builtin:     true,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("upsert role: %v", err)
	}

	service := &Service{
		db:  db,
		cfg: config.Config{SkillsDir: filepath.Join(dir, "skills")},
	}
	instruction := service.roleInstruction(ctx, "role-1")
	if !strings.Contains(instruction, "你是测试角色。") {
		t.Fatalf("instruction missing role prompt: %q", instruction)
	}
	if !strings.Contains(instruction, "演示技能说明") {
		t.Fatalf("instruction missing skill summary: %q", instruction)
	}

	if err := db.CreateConversation(ctx, database.Conversation{
		ID:          "conv-role",
		OwnerUserID: "user-1",
		AgentRoleID: "role-1",
		Title:       "role test",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("create conversation: %v", err)
	}
	messages, err := service.buildModelMessages(ctx, "conv-role", "user-1")
	if err != nil {
		t.Fatalf("build model messages: %v", err)
	}
	systemPrompt := messages[0].Content
	if !strings.Contains(systemPrompt, defaultSystemPrompt) {
		t.Fatalf("绑定角色后不应丢失平台默认 Prompt")
	}
	if !strings.Contains(systemPrompt, "你是测试角色。") {
		t.Fatalf("绑定角色后应保留角色 Prompt: %q", systemPrompt)
	}

	if disabled := service.roleInstruction(ctx, "missing-role"); disabled != "" {
		t.Fatalf("unknown role should not change instruction: %q", disabled)
	}
}
