package database

import (
	"context"
	"encoding/json"
	"time"
)

type MCPServer struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Transport   string            `json:"transport"`
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	URL         string            `json:"url"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
	Status      string            `json:"status"`
	LastError   string            `json:"lastError"`
	ToolCount   int               `json:"toolCount"`
	Builtin     bool              `json:"builtin"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
}

func (db *DB) CreateMCPServer(ctx context.Context, item MCPServer) error {
	argsJSON, envJSON, err := encodeMCPServerPayload(item)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO mcp_servers (
			id, name, transport, command, args_json, env_json, url, description,
			enabled, status, last_error, tool_count, builtin, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.Name,
		item.Transport,
		item.Command,
		argsJSON,
		envJSON,
		item.URL,
		item.Description,
		boolToInt(item.Enabled),
		defaultStatus(item.Status),
		item.LastError,
		item.ToolCount,
		boolToInt(item.Builtin),
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) UpsertMCPServer(ctx context.Context, item MCPServer) error {
	argsJSON, envJSON, err := encodeMCPServerPayload(item)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO mcp_servers (
			id, name, transport, command, args_json, env_json, url, description,
			enabled, status, last_error, tool_count, builtin, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', 0, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			description = excluded.description,
			updated_at = excluded.updated_at`,
		item.ID,
		item.Name,
		item.Transport,
		item.Command,
		argsJSON,
		envJSON,
		item.URL,
		item.Description,
		boolToInt(item.Enabled),
		defaultStatus(item.Status),
		boolToInt(item.Builtin),
		now.Unix(),
		now.Unix(),
	)
	return err
}

func (db *DB) UpdateMCPServer(ctx context.Context, item MCPServer) error {
	argsJSON, envJSON, err := encodeMCPServerPayload(item)
	if err != nil {
		return err
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE mcp_servers
		 SET name = ?, transport = ?, command = ?, args_json = ?, env_json = ?,
			url = ?, description = ?, enabled = ?, updated_at = ?
		 WHERE id = ?`,
		item.Name,
		item.Transport,
		item.Command,
		argsJSON,
		envJSON,
		item.URL,
		item.Description,
		boolToInt(item.Enabled),
		item.UpdatedAt.Unix(),
		item.ID,
	)
	return requireAffected(result, err)
}

func (db *DB) UpdateMCPServerStatus(
	ctx context.Context,
	id string,
	status string,
	lastError string,
	toolCount int,
) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE mcp_servers
		 SET status = ?, last_error = ?, tool_count = ?, updated_at = ?
		 WHERE id = ?`,
		status,
		lastError,
		toolCount,
		time.Now().UTC().Unix(),
		id,
	)
	return err
}

func (db *DB) DeleteMCPServer(ctx context.Context, id string) error {
	result, err := db.ExecContext(ctx, `DELETE FROM mcp_servers WHERE id = ?`, id)
	return requireAffected(result, err)
}

func (db *DB) GetMCPServer(ctx context.Context, id string) (*MCPServer, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, name, transport, command, args_json, env_json, url, description,
			enabled, status, last_error, tool_count, builtin, created_at, updated_at
		 FROM mcp_servers WHERE id = ?`,
		id,
	)
	item, err := scanMCPServer(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) GetMCPServerByName(ctx context.Context, name string) (*MCPServer, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, name, transport, command, args_json, env_json, url, description,
			enabled, status, last_error, tool_count, builtin, created_at, updated_at
		 FROM mcp_servers WHERE name = ?`,
		name,
	)
	item, err := scanMCPServer(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) ListMCPServers(ctx context.Context) ([]MCPServer, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, name, transport, command, args_json, env_json, url, description,
			enabled, status, last_error, tool_count, builtin, created_at, updated_at
		 FROM mcp_servers ORDER BY enabled DESC, name ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]MCPServer, 0)
	for rows.Next() {
		item, err := scanMCPServer(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanMCPServer(scanner rowScanner) (MCPServer, error) {
	var item MCPServer
	var argsJSON string
	var envJSON string
	var enabled int
	var builtin int
	var createdAt int64
	var updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.Name,
		&item.Transport,
		&item.Command,
		&argsJSON,
		&envJSON,
		&item.URL,
		&item.Description,
		&enabled,
		&item.Status,
		&item.LastError,
		&item.ToolCount,
		&builtin,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	item.Enabled = enabled != 0
	item.Builtin = builtin != 0
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	_ = json.Unmarshal([]byte(argsJSON), &item.Args)
	_ = json.Unmarshal([]byte(envJSON), &item.Env)
	if item.Args == nil {
		item.Args = []string{}
	}
	if item.Env == nil {
		item.Env = map[string]string{}
	}
	return item, nil
}

func encodeMCPServerPayload(item MCPServer) (string, string, error) {
	args := item.Args
	if args == nil {
		args = []string{}
	}
	env := item.Env
	if env == nil {
		env = map[string]string{}
	}
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return "", "", err
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return "", "", err
	}
	return string(argsJSON), string(envJSON), nil
}

func defaultStatus(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
