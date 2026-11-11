package database

import (
	"context"
	"encoding/json"
	"time"
)

type RBACRole struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Permissions []string  `json:"permissions"`
	Builtin     bool      `json:"builtin"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (db *DB) UpsertRBACRole(ctx context.Context, role RBACRole) error {
	raw, err := json.Marshal(role.Permissions)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO rbac_roles (
			name, description, permissions_json, builtin, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			description = excluded.description,
			permissions_json = excluded.permissions_json,
			updated_at = excluded.updated_at`,
		role.Name,
		role.Description,
		string(raw),
		boolToInt(role.Builtin),
		now.Unix(),
		now.Unix(),
	)
	return err
}

func (db *DB) GetRBACRole(ctx context.Context, name string) (*RBACRole, error) {
	var role RBACRole
	var raw string
	var builtin int
	var createdAt int64
	var updatedAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT name, description, permissions_json, builtin, created_at, updated_at
		 FROM rbac_roles WHERE name = ?`,
		name,
	).Scan(
		&role.Name,
		&role.Description,
		&raw,
		&builtin,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return nil, err
	}
	role.Builtin = builtin != 0
	role.CreatedAt = time.Unix(createdAt, 0)
	role.UpdatedAt = time.Unix(updatedAt, 0)
	_ = json.Unmarshal([]byte(raw), &role.Permissions)
	return &role, nil
}

func (db *DB) ListRBACRoles(ctx context.Context) ([]RBACRole, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT name, description, permissions_json, builtin, created_at, updated_at
		 FROM rbac_roles ORDER BY builtin DESC, name ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roles := make([]RBACRole, 0)
	for rows.Next() {
		var role RBACRole
		var raw string
		var builtin int
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&role.Name,
			&role.Description,
			&raw,
			&builtin,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		role.Builtin = builtin != 0
		role.CreatedAt = time.Unix(createdAt, 0)
		role.UpdatedAt = time.Unix(updatedAt, 0)
		_ = json.Unmarshal([]byte(raw), &role.Permissions)
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (db *DB) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, username, display_name, password_hash, role, enabled, created_at
		 FROM users ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var user User
		var enabled int
		var createdAt int64
		if err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.DisplayName,
			&user.PasswordHash,
			&user.Role,
			&enabled,
			&createdAt,
		); err != nil {
			return nil, err
		}
		user.Enabled = enabled != 0
		user.CreatedAt = time.Unix(createdAt, 0)
		users = append(users, user)
	}
	return users, rows.Err()
}

func (db *DB) UpdateUser(
	ctx context.Context,
	userID string,
	displayName string,
	role string,
	enabled bool,
) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE users
		 SET display_name = ?, role = ?, enabled = ?
		 WHERE id = ?`,
		displayName,
		role,
		boolToInt(enabled),
		userID,
	)
	return err
}

func (db *DB) UpdateUserPassword(ctx context.Context, userID, passwordHash string) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE users SET password_hash = ? WHERE id = ?`,
		passwordHash,
		userID,
	)
	return err
}

func (db *DB) DeleteUser(ctx context.Context, userID string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	return err
}

func (db *DB) DeleteRBACRole(ctx context.Context, name string) error {
	_, err := db.ExecContext(ctx, `DELETE FROM rbac_roles WHERE name = ? AND builtin = 0`, name)
	return err
}

func (db *DB) CountUsersWithRole(ctx context.Context, role string) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM users WHERE role = ?`,
		role,
	).Scan(&count)
	return count, err
}

func (db *DB) CountEnabledAdmins(ctx context.Context) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM users WHERE role = 'admin' AND enabled = 1`,
	).Scan(&count)
	return count, err
}
