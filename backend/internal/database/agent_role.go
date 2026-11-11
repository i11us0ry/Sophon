package database

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

type AgentRole struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Prompt      string    `json:"prompt"`
	Icon        string    `json:"icon"`
	DefaultMode string    `json:"defaultMode"`
	Skills      []string  `json:"skills"`
	Builtin     bool      `json:"builtin"`
	Enabled     bool      `json:"enabled"`
	Deleted     bool      `json:"-"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func NormalizeAgentRoleDefaultMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "fast":
		return "fast"
	case "deep":
		return "deep"
	default:
		return "auto"
	}
}

func (db *DB) UpsertAgentRole(ctx context.Context, role AgentRole) error {
	raw, err := json.Marshal(role.Skills)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO agent_roles (
			id, name, description, prompt, icon, default_mode, skills_json, builtin, enabled,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			description = excluded.description,
			prompt = excluded.prompt,
			icon = excluded.icon,
			default_mode = excluded.default_mode,
			builtin = excluded.builtin,
			updated_at = excluded.updated_at`,
		role.ID,
		role.Name,
		role.Description,
		role.Prompt,
		role.Icon,
		NormalizeAgentRoleDefaultMode(role.DefaultMode),
		string(raw),
		boolToInt(role.Builtin),
		boolToInt(role.Enabled),
		now.Unix(),
		now.Unix(),
	)
	return err
}

func (db *DB) CreateAgentRole(ctx context.Context, role AgentRole) error {
	raw, err := json.Marshal(role.Skills)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO agent_roles (
			id, name, description, prompt, icon, default_mode, skills_json, builtin, enabled,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		role.ID,
		role.Name,
		role.Description,
		role.Prompt,
		role.Icon,
		NormalizeAgentRoleDefaultMode(role.DefaultMode),
		string(raw),
		boolToInt(role.Builtin),
		boolToInt(role.Enabled),
		role.CreatedAt.Unix(),
		role.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) UpdateAgentRole(ctx context.Context, role AgentRole) error {
	raw, err := json.Marshal(role.Skills)
	if err != nil {
		return err
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE agent_roles
		 SET name = ?, description = ?, prompt = ?, icon = ?, default_mode = ?, skills_json = ?,
			builtin = ?, enabled = ?, updated_at = ?
		 WHERE id = ? AND deleted = 0`,
		role.Name,
		role.Description,
		role.Prompt,
		role.Icon,
		NormalizeAgentRoleDefaultMode(role.DefaultMode),
		string(raw),
		boolToInt(role.Builtin),
		boolToInt(role.Enabled),
		role.UpdatedAt.Unix(),
		role.ID,
	)
	return requireAffected(result, err)
}

func (db *DB) ListAgentRoles(ctx context.Context, onlyEnabled bool) ([]AgentRole, error) {
	query := `SELECT id, name, description, prompt, icon, default_mode, skills_json, builtin, enabled, deleted,
		created_at, updated_at FROM agent_roles`
	conditions := make([]string, 0, 2)
	conditions = append(conditions, "deleted = 0")
	if onlyEnabled {
		conditions = append(conditions, "enabled = 1")
	}
	query += " WHERE " + strings.Join(conditions, " AND ")
	query += ` ORDER BY builtin DESC, name ASC`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make([]AgentRole, 0)
	for rows.Next() {
		role, err := scanAgentRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (db *DB) GetAgentRole(ctx context.Context, id string) (*AgentRole, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, name, description, prompt, icon, default_mode, skills_json, builtin, enabled, deleted,
			created_at, updated_at FROM agent_roles WHERE id = ? AND deleted = 0`,
		id,
	)
	role, err := scanAgentRole(row)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (db *DB) GetAgentRoleIncludingDeleted(ctx context.Context, id string) (*AgentRole, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, name, description, prompt, icon, default_mode, skills_json, builtin, enabled, deleted,
			created_at, updated_at FROM agent_roles WHERE id = ?`,
		id,
	)
	role, err := scanAgentRole(row)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (db *DB) GetAgentRoleByName(ctx context.Context, name string) (*AgentRole, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, name, description, prompt, icon, default_mode, skills_json, builtin, enabled, deleted,
			created_at, updated_at FROM agent_roles
		 WHERE LOWER(TRIM(name)) = LOWER(TRIM(?))`,
		name,
	)
	role, err := scanAgentRole(row)
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (db *DB) DeleteAgentRole(ctx context.Context, id string) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE agent_roles SET deleted = 1, enabled = 0, updated_at = ?
		 WHERE id = ? AND deleted = 0`,
		time.Now().UTC().Unix(),
		id,
	)
	return requireAffected(result, err)
}

// RenameAgentRoleForMigration 用于系统迁移时释放被占用的固定名称。
func (db *DB) RenameAgentRoleForMigration(ctx context.Context, id string, name string) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE agent_roles SET name = ?, updated_at = ? WHERE id = ?`,
		strings.TrimSpace(name),
		time.Now().UTC().Unix(),
		id,
	)
	return requireAffected(result, err)
}

// RestoreAgentRole 复用被软删除的同名角色（清空 deleted 并覆盖字段）。
func (db *DB) RestoreAgentRole(ctx context.Context, role AgentRole) error {
	raw, err := json.Marshal(role.Skills)
	if err != nil {
		return err
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE agent_roles
		 SET description = ?, prompt = ?, icon = ?, default_mode = ?, skills_json = ?, enabled = ?,
			deleted = 0, updated_at = ?
		 WHERE id = ?`,
		role.Description,
		role.Prompt,
		role.Icon,
		NormalizeAgentRoleDefaultMode(role.DefaultMode),
		string(raw),
		boolToInt(role.Enabled),
		role.UpdatedAt.Unix(),
		role.ID,
	)
	return requireAffected(result, err)
}

func scanAgentRole(scanner rowScanner) (AgentRole, error) {
	var role AgentRole
	var defaultMode string
	var raw string
	var builtin int
	var enabled int
	var deleted int
	var createdAt int64
	var updatedAt int64
	err := scanner.Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.Prompt,
		&role.Icon,
		&defaultMode,
		&raw,
		&builtin,
		&enabled,
		&deleted,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return role, err
	}
	role.Builtin = builtin != 0
	role.DefaultMode = NormalizeAgentRoleDefaultMode(defaultMode)
	role.Enabled = enabled != 0
	role.Deleted = deleted != 0
	role.CreatedAt = time.Unix(createdAt, 0)
	role.UpdatedAt = time.Unix(updatedAt, 0)
	_ = json.Unmarshal([]byte(raw), &role.Skills)
	if role.Skills == nil {
		role.Skills = []string{}
	}
	return role, nil
}
