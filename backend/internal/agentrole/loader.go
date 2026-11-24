package agentrole

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/skillname"

	"gopkg.in/yaml.v3"
)

const maxFileRoleSkills = 50

var legacyRoleSkillGateReplacements = []struct {
	old string
	new string
}{
	{
		old: "必须先读取并使用 java-code-audit 总控技能，再按需加载路由、鉴权、调用链和漏洞专项技能。",
		new: "java-code-audit、路由、鉴权、调用链和漏洞专项技能都是可选的方法论参考；可根据证据缺口和审计收益按需读取，不必先读总控技能。",
	},
	{
		old: "必须先读取 php-code-audit 总控技能，再按需加载路由、追踪、鉴权和专项审计技能。",
		new: "php-code-audit、路由、追踪、鉴权和专项审计技能都是可选的方法论参考；可根据证据缺口和审计收益按需读取，不必先读总控技能。",
	},
	{
		old: "必须先读取 dotnet-code-audit 总控技能，再按需加载路由鉴权、数据流、注入、反序列化、文件、Web 输出、配置和依赖技能。",
		new: "dotnet-code-audit、路由鉴权、数据流、注入、反序列化、文件、Web 输出、配置和依赖技能都是可选的方法论参考；可根据证据缺口和审计收益按需读取，不必先读总控技能。",
	},
}

var legacyTaskProfilePromptHashes = map[string]string{
	"Java代码审计": "9be0d4c8dc2ebf034b6b13b8757b2ecabca330d34657c7fe71b2f8f704edf9be",
	"NET代码审计":  "c7f1f761a803e2951ce68b9b4be5e3a8247d8342378dd8e8ebbe229673b5ce63",
	"PHP代码审计":  "f0b2d13848182632128a12ccad3d9ee871fa45dbfd16714edf45051a31f75dc6",
	"App逆向":    "d51dc090dd1e46732f6b86233524a82596dbc1c14d3fc0885eab1c1684c46dfd",
}

type fileRole struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	UserPrompt  string   `yaml:"user_prompt"`
	Icon        string   `yaml:"icon"`
	DefaultMode string   `yaml:"default_mode"`
	Skills      []string `yaml:"skills"`
	Enabled     *bool    `yaml:"enabled"`
}

// SyncFromDir 把角色 YAML 同步进数据库：首次导入创建，软删除角色恢复，
// 已存在的有效角色保留用户在数据库中的编辑。
func SyncFromDir(ctx context.Context, db *database.DB, dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	synced := 0
	for _, entry := range entries {
		if entry.IsDir() || !isYAML(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			log.Printf("agent role: 读取 %s 失败: %v", path, err)
			continue
		}
		var parsed fileRole
		if err := yaml.Unmarshal(raw, &parsed); err != nil {
			log.Printf("agent role: 解析 %s 失败: %v", path, err)
			continue
		}
		skills, err := normalizeFileRoleSkills(parsed.Skills)
		if err != nil {
			log.Printf("agent role: 校验 %s 技能失败: %v", path, err)
			continue
		}
		name := strings.TrimSpace(parsed.Name)
		if name == "" {
			name = strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		}
		enabled := true
		if parsed.Enabled != nil {
			enabled = *parsed.Enabled
		}
		now := time.Now().UTC()
		role := database.AgentRole{
			ID:          newID(),
			Name:        name,
			Description: strings.TrimSpace(parsed.Description),
			Prompt:      strings.TrimSpace(parsed.UserPrompt),
			Icon:        strings.TrimSpace(parsed.Icon),
			DefaultMode: database.NormalizeAgentRoleDefaultMode(parsed.DefaultMode),
			Skills:      skills,
			Builtin:     true,
			Enabled:     enabled,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if existing, err := db.GetAgentRoleByName(ctx, name); err == nil {
			role.ID = existing.ID
			role.Skills = existing.Skills
			role.CreatedAt = existing.CreatedAt
			role.Name = existing.Name
			if existing.Deleted {
				role.Enabled = enabled
				if err := db.RestoreAgentRole(ctx, role); err != nil {
					return fmt.Errorf("恢复角色 %s 失败: %w", name, err)
				}
				synced++
				continue
			}
			role.Description = existing.Description
			role.Prompt = upgradeLegacyTaskProfilePrompt(name, existing.Prompt, role.Prompt)
			role.Icon = existing.Icon
			role.DefaultMode = existing.DefaultMode
			role.Enabled = existing.Enabled
		}
		if err := db.UpsertAgentRole(ctx, role); err != nil {
			return fmt.Errorf("同步角色 %s 失败: %w", name, err)
		}
		synced++
	}
	if synced > 0 {
		log.Printf("agent role: 已同步 %d 个角色（%s）", synced, dir)
	}
	return nil
}

func upgradeLegacyRoleSkillGates(prompt string) string {
	for _, replacement := range legacyRoleSkillGateReplacements {
		prompt = strings.ReplaceAll(prompt, replacement.old, replacement.new)
	}
	return prompt
}

func upgradeLegacyTaskProfilePrompt(name, current, fallback string) string {
	upgraded := upgradeLegacyRoleSkillGates(current)
	expectedHash := legacyTaskProfilePromptHashes[strings.TrimSpace(name)]
	if expectedHash == "" ||
		(taskProfilePromptHash(current) != expectedHash &&
			taskProfilePromptHash(upgraded) != expectedHash) {
		return upgraded
	}
	fallback = strings.TrimSpace(fallback)
	if fallback == "" {
		return upgraded
	}
	return upgradeLegacyRoleSkillGates(fallback)
}

func taskProfilePromptHash(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func normalizeFileRoleSkills(values []string) ([]string, error) {
	seen := make(map[string]bool, len(values))
	skills := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		if !skillname.Valid(value) {
			return nil, fmt.Errorf("技能名称不合法: %s", value)
		}
		seen[value] = true
		skills = append(skills, value)
		if len(skills) > maxFileRoleSkills {
			return nil, fmt.Errorf("单个角色最多绑定 %d 个技能", maxFileRoleSkills)
		}
	}
	return skills, nil
}

func isYAML(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

func newID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("id_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
