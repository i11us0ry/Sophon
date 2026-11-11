package database

import (
	"context"
	"time"
)

type MCPToolSetting struct {
	ServerName string    `json:"serverName"`
	ToolName   string    `json:"toolName"`
	Enabled    bool      `json:"enabled"`
	Capability string    `json:"capability"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

func (db *DB) ListMCPToolSettings(ctx context.Context) ([]MCPToolSetting, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT server_name, tool_name, enabled, capability, updated_at
		 FROM mcp_tool_settings`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]MCPToolSetting, 0)
	for rows.Next() {
		var item MCPToolSetting
		var enabled int
		var updatedAt int64
		if err := rows.Scan(
			&item.ServerName,
			&item.ToolName,
			&enabled,
			&item.Capability,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.Enabled = enabled != 0
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) UpsertMCPToolSettings(ctx context.Context, items []MCPToolSetting) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, item := range items {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO mcp_tool_settings (
				server_name, tool_name, enabled, capability, updated_at
			) VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(server_name, tool_name) DO UPDATE SET
				enabled = excluded.enabled,
				capability = excluded.capability,
				updated_at = excluded.updated_at`,
			item.ServerName,
			item.ToolName,
			boolToInt(item.Enabled),
			item.Capability,
			item.UpdatedAt.Unix(),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) GetMCPToolSetting(
	ctx context.Context,
	serverName string,
	toolName string,
) (*MCPToolSetting, error) {
	var item MCPToolSetting
	var enabled int
	var updatedAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT server_name, tool_name, enabled, capability, updated_at
		 FROM mcp_tool_settings
		 WHERE server_name = ? AND tool_name = ?`,
		serverName,
		toolName,
	).Scan(
		&item.ServerName,
		&item.ToolName,
		&enabled,
		&item.Capability,
		&updatedAt,
	)
	if err != nil {
		if NoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	item.Enabled = enabled != 0
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return &item, nil
}

// DisabledMCPToolNames 返回被停用的工具名集合，用于 Agent 运行时的工具过滤。
func (db *DB) DisabledMCPToolNames(ctx context.Context) (map[string]bool, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT DISTINCT tool_name FROM mcp_tool_settings WHERE enabled = 0`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	names := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names[name] = true
	}
	return names, rows.Err()
}
