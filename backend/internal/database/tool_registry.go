package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	ToolScopeSession = "session"
	ToolScopeProject = "project"
	ToolScopeGlobal  = "global"
)

type RegisteredTool struct {
	ID             string            `json:"id"`
	OwnerUserID    string            `json:"ownerUserId"`
	ProjectID      string            `json:"projectId,omitempty"`
	ConversationID string            `json:"conversationId,omitempty"`
	Scope          string            `json:"scope"`
	Name           string            `json:"name"`
	Command        string            `json:"command"`
	Args           []string          `json:"args"`
	Env            map[string]string `json:"env"`
	Version        string            `json:"version,omitempty"`
	Source         string            `json:"source,omitempty"`
	HealthCheck    []string          `json:"healthCheck"`
	Enabled        bool              `json:"enabled"`
	Status         string            `json:"status"`
	LastError      string            `json:"lastError,omitempty"`
	CreatedAt      time.Time         `json:"createdAt"`
	UpdatedAt      time.Time         `json:"updatedAt"`
}

type ToolRuntimePath struct {
	ID             string    `json:"id"`
	OwnerUserID    string    `json:"ownerUserId"`
	ProjectID      string    `json:"projectId,omitempty"`
	ConversationID string    `json:"conversationId,omitempty"`
	Scope          string    `json:"scope"`
	Path           string    `json:"path"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

const registeredToolColumns = `id, owner_user_id, project_id, conversation_id, scope,
	name, command, args_json, env_json, version, source, health_check_json,
	enabled, status, last_error, created_at, updated_at`

const toolRuntimePathColumns = `id, owner_user_id, project_id, conversation_id, scope,
	path, created_at, updated_at`

func scanRegisteredTool(scanner rowScanner) (RegisteredTool, error) {
	var item RegisteredTool
	var argsJSON string
	var envJSON string
	var healthJSON string
	var enabled int
	var createdAt int64
	var updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.OwnerUserID,
		&item.ProjectID,
		&item.ConversationID,
		&item.Scope,
		&item.Name,
		&item.Command,
		&argsJSON,
		&envJSON,
		&item.Version,
		&item.Source,
		&healthJSON,
		&enabled,
		&item.Status,
		&item.LastError,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	_ = json.Unmarshal([]byte(argsJSON), &item.Args)
	_ = json.Unmarshal([]byte(envJSON), &item.Env)
	_ = json.Unmarshal([]byte(healthJSON), &item.HealthCheck)
	item.Args = normalizeStringList(item.Args)
	item.HealthCheck = normalizeStringList(item.HealthCheck)
	if item.Env == nil {
		item.Env = map[string]string{}
	}
	item.Enabled = enabled != 0
	item.CreatedAt = time.Unix(createdAt, 0).UTC()
	item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return item, nil
}

func scanToolRuntimePath(scanner rowScanner) (ToolRuntimePath, error) {
	var item ToolRuntimePath
	var createdAt int64
	var updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.OwnerUserID,
		&item.ProjectID,
		&item.ConversationID,
		&item.Scope,
		&item.Path,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	item.CreatedAt = time.Unix(createdAt, 0).UTC()
	item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return item, nil
}

func normalizeStringList(values []string) []string {
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func normalizeToolScope(scope string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case ToolScopeSession, "conversation":
		return ToolScopeSession
	case ToolScopeGlobal:
		return ToolScopeGlobal
	default:
		return ToolScopeProject
	}
}

func normalizeRegisteredTool(item RegisteredTool, now time.Time) (RegisteredTool, error) {
	item.ID = strings.TrimSpace(item.ID)
	item.OwnerUserID = strings.TrimSpace(item.OwnerUserID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	item.Scope = normalizeToolScope(item.Scope)
	item.Name = strings.TrimSpace(item.Name)
	item.Command = strings.TrimSpace(item.Command)
	item.Version = strings.TrimSpace(item.Version)
	item.Source = strings.TrimSpace(item.Source)
	item.Status = strings.TrimSpace(item.Status)
	item.LastError = strings.TrimSpace(item.LastError)
	item.Args = normalizeStringList(item.Args)
	item.HealthCheck = normalizeStringList(item.HealthCheck)
	if item.Env == nil {
		item.Env = map[string]string{}
	}
	if item.ID == "" {
		return item, fmt.Errorf("工具注册 id 不能为空")
	}
	if item.OwnerUserID == "" {
		return item, fmt.Errorf("工具注册所属用户不能为空")
	}
	if item.Name == "" {
		return item, fmt.Errorf("工具名称不能为空")
	}
	if item.Command == "" {
		return item, fmt.Errorf("工具命令不能为空")
	}
	switch item.Scope {
	case ToolScopeSession:
		if item.ConversationID == "" {
			return item, fmt.Errorf("会话级工具必须指定 conversation_id")
		}
	case ToolScopeProject:
		if item.ProjectID == "" {
			return item, fmt.Errorf("项目级工具必须指定 project_id")
		}
	case ToolScopeGlobal:
		item.ProjectID = ""
		item.ConversationID = ""
	}
	if item.Status == "" {
		item.Status = "registered"
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	return item, nil
}

func (db *DB) UpsertRegisteredTool(ctx context.Context, item RegisteredTool) (*RegisteredTool, error) {
	now := time.Now().UTC()
	item, err := normalizeRegisteredTool(item, now)
	if err != nil {
		return nil, err
	}
	argsJSON, err := json.Marshal(item.Args)
	if err != nil {
		return nil, err
	}
	envJSON, err := json.Marshal(item.Env)
	if err != nil {
		return nil, err
	}
	healthJSON, err := json.Marshal(item.HealthCheck)
	if err != nil {
		return nil, err
	}
	enabled := 0
	if item.Enabled {
		enabled = 1
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO tool_registry (
			id, owner_user_id, project_id, conversation_id, scope, name, command,
			args_json, env_json, version, source, health_check_json, enabled,
			status, last_error, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(owner_user_id, project_id, conversation_id, name) DO UPDATE SET
			scope = excluded.scope,
			command = excluded.command,
			args_json = excluded.args_json,
			env_json = excluded.env_json,
			version = excluded.version,
			source = excluded.source,
			health_check_json = excluded.health_check_json,
			enabled = excluded.enabled,
			status = excluded.status,
			last_error = excluded.last_error,
			updated_at = excluded.updated_at`,
		item.ID,
		item.OwnerUserID,
		item.ProjectID,
		item.ConversationID,
		item.Scope,
		item.Name,
		item.Command,
		string(argsJSON),
		string(envJSON),
		item.Version,
		item.Source,
		string(healthJSON),
		enabled,
		item.Status,
		item.LastError,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	if err != nil {
		return nil, err
	}
	row := db.QueryRowContext(
		ctx,
		`SELECT `+registeredToolColumns+`
		 FROM tool_registry
		 WHERE owner_user_id = ? AND project_id = ? AND conversation_id = ? AND name = ?`,
		item.OwnerUserID,
		item.ProjectID,
		item.ConversationID,
		item.Name,
	)
	stored, err := scanRegisteredTool(row)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

func (db *DB) ListRegisteredTools(
	ctx context.Context,
	ownerUserID string,
	projectID string,
	conversationID string,
) ([]RegisteredTool, error) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	projectID = strings.TrimSpace(projectID)
	conversationID = strings.TrimSpace(conversationID)
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+registeredToolColumns+`
		 FROM tool_registry
		 WHERE enabled = 1
		   AND (
			     (owner_user_id = ? AND scope = 'global')
		     OR (owner_user_id = ? AND scope = 'project' AND project_id = ?)
		     OR (owner_user_id = ? AND scope = 'session' AND conversation_id = ?)
		   )
		 ORDER BY CASE scope WHEN 'session' THEN 0 WHEN 'project' THEN 1 ELSE 2 END,
		          updated_at DESC, name ASC`,
		ownerUserID,
		ownerUserID,
		projectID,
		ownerUserID,
		conversationID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]RegisteredTool, 0)
	for rows.Next() {
		item, err := scanRegisteredTool(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListAllRegisteredTools(ctx context.Context, ownerUserID string) ([]RegisteredTool, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+registeredToolColumns+`
		 FROM tool_registry
		 WHERE owner_user_id = ?
		 ORDER BY CASE scope WHEN 'session' THEN 0 WHEN 'project' THEN 1 ELSE 2 END,
		          updated_at DESC, name ASC`,
		strings.TrimSpace(ownerUserID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]RegisteredTool, 0)
	for rows.Next() {
		item, err := scanRegisteredTool(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) DeleteRegisteredTool(ctx context.Context, id string, ownerUserID string) (bool, error) {
	result, err := db.ExecContext(
		ctx,
		`DELETE FROM tool_registry
		 WHERE id = ? AND (owner_user_id = ? OR ? = '')`,
		strings.TrimSpace(id),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(ownerUserID),
	)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected > 0, err
}

func (db *DB) UpsertToolRuntimePath(ctx context.Context, item ToolRuntimePath) (*ToolRuntimePath, error) {
	now := time.Now().UTC()
	item.ID = strings.TrimSpace(item.ID)
	item.OwnerUserID = strings.TrimSpace(item.OwnerUserID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	item.Scope = normalizeToolScope(item.Scope)
	item.Path = strings.TrimSpace(item.Path)
	if item.ID == "" || item.OwnerUserID == "" || item.Path == "" {
		return nil, fmt.Errorf("工具路径注册参数不完整")
	}
	switch item.Scope {
	case ToolScopeSession:
		if item.ConversationID == "" {
			return nil, fmt.Errorf("会话级 PATH 必须指定 conversation_id")
		}
	case ToolScopeProject:
		if item.ProjectID == "" {
			return nil, fmt.Errorf("项目级 PATH 必须指定 project_id")
		}
	case ToolScopeGlobal:
		item.ProjectID = ""
		item.ConversationID = ""
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	item.UpdatedAt = now
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO tool_runtime_paths (
			id, owner_user_id, project_id, conversation_id, scope, path, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(owner_user_id, project_id, conversation_id, path) DO UPDATE SET
			scope = excluded.scope, updated_at = excluded.updated_at`,
		item.ID,
		item.OwnerUserID,
		item.ProjectID,
		item.ConversationID,
		item.Scope,
		item.Path,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	if err != nil {
		return nil, err
	}
	row := db.QueryRowContext(
		ctx,
		`SELECT `+toolRuntimePathColumns+`
		 FROM tool_runtime_paths
		 WHERE owner_user_id = ? AND project_id = ? AND conversation_id = ? AND path = ?`,
		item.OwnerUserID,
		item.ProjectID,
		item.ConversationID,
		item.Path,
	)
	stored, err := scanToolRuntimePath(row)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

func (db *DB) ListToolRuntimePaths(
	ctx context.Context,
	ownerUserID string,
	projectID string,
	conversationID string,
) ([]ToolRuntimePath, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+toolRuntimePathColumns+`
		 FROM tool_runtime_paths
		 WHERE (
			     (owner_user_id = ? AND scope = 'global')
		     OR (owner_user_id = ? AND scope = 'project' AND project_id = ?)
		     OR (owner_user_id = ? AND scope = 'session' AND conversation_id = ?)
		   )
		 ORDER BY CASE scope WHEN 'session' THEN 0 WHEN 'project' THEN 1 ELSE 2 END,
		          updated_at DESC, path ASC`,
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(conversationID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ToolRuntimePath, 0)
	for rows.Next() {
		item, err := scanToolRuntimePath(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListAllToolRuntimePaths(ctx context.Context, ownerUserID string) ([]ToolRuntimePath, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+toolRuntimePathColumns+`
		 FROM tool_runtime_paths
		 WHERE owner_user_id = ?
		 ORDER BY CASE scope WHEN 'session' THEN 0 WHEN 'project' THEN 1 ELSE 2 END,
		          updated_at DESC, path ASC`,
		strings.TrimSpace(ownerUserID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ToolRuntimePath, 0)
	for rows.Next() {
		item, err := scanToolRuntimePath(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) DeleteToolRuntimePath(ctx context.Context, id string, ownerUserID string) (bool, error) {
	result, err := db.ExecContext(
		ctx,
		`DELETE FROM tool_runtime_paths
		 WHERE id = ? AND (owner_user_id = ? OR ? = '')`,
		strings.TrimSpace(id),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(ownerUserID),
	)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected > 0, err
}

func (db *DB) CleanupToolRegistryForProject(ctx context.Context, projectID string) error {
	if strings.TrimSpace(projectID) == "" {
		return nil
	}
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM tool_registry WHERE project_id = ?`,
		strings.TrimSpace(projectID),
	); err != nil {
		return err
	}
	_, err := db.ExecContext(
		ctx,
		`DELETE FROM tool_runtime_paths WHERE project_id = ?`,
		strings.TrimSpace(projectID),
	)
	return err
}

func IsNoRowsToolRegistry(err error) bool {
	return err == sql.ErrNoRows
}
