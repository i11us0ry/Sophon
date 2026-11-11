package agentrole

import (
	"context"
	"crypto/rand"
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
			role.Prompt = existing.Prompt
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
