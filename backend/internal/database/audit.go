package database

import (
	"context"
	"strings"
	"time"
)

type AuditLog struct {
	ID           string    `json:"id"`
	UserID       string    `json:"userId"`
	Username     string    `json:"username"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resourceType"`
	ResourceID   string    `json:"resourceId"`
	Result       string    `json:"result"`
	Detail       string    `json:"detail"`
	CreatedAt    time.Time `json:"createdAt"`
}

func (db *DB) AddAuditLog(ctx context.Context, entry AuditLog) error {
	if entry.ID == "" {
		entry.ID = newID()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO audit_logs (
			id, user_id, username, action, resource_type,
			resource_id, result, detail, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID,
		entry.UserID,
		entry.Username,
		entry.Action,
		entry.ResourceType,
		entry.ResourceID,
		entry.Result,
		entry.Detail,
		entry.CreatedAt.Unix(),
	)
	return err
}

type AuditLogFilter struct {
	UserID   string
	AllUsers bool
	Result   string
	Search   string
	Limit    int
	Offset   int
}

func (db *DB) ListAuditLogs(ctx context.Context, userID string, limit int) ([]AuditLog, error) {
	items, _, err := db.ListAuditLogsFiltered(ctx, AuditLogFilter{
		UserID: userID,
		Limit:  limit,
	})
	return items, err
}

func (db *DB) ListAuditLogsFiltered(
	ctx context.Context,
	filter AuditLogFilter,
) ([]AuditLog, int, error) {
	where, args := buildAuditLogWhere(filter)

	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM audit_logs`+where,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, user_id, username, action, resource_type,
			resource_id, result, detail, created_at
		 FROM audit_logs`+where+`
		 ORDER BY created_at DESC
		 LIMIT ? OFFSET ?`,
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]AuditLog, 0)
	for rows.Next() {
		var item AuditLog
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.UserID,
			&item.Username,
			&item.Action,
			&item.ResourceType,
			&item.ResourceID,
			&item.Result,
			&item.Detail,
			&createdAt,
		); err != nil {
			return nil, 0, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func buildAuditLogWhere(filter AuditLogFilter) (string, []interface{}) {
	clauses := make([]string, 0, 2)
	args := make([]interface{}, 0, 6)
	if !filter.AllUsers {
		clauses = append(clauses, "(user_id = ? OR user_id = '')")
		args = append(args, filter.UserID)
	}
	if result := strings.TrimSpace(filter.Result); result != "" {
		clauses = append(clauses, "result = ?")
		args = append(args, result)
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		pattern := "%" + escapeLikePattern(search) + "%"
		clauses = append(
			clauses,
			`(username LIKE ? ESCAPE '\' OR action LIKE ? ESCAPE '\'
			 OR resource_type LIKE ? ESCAPE '\' OR resource_id LIKE ? ESCAPE '\'
			 OR detail LIKE ? ESCAPE '\')`,
		)
		args = append(args, pattern, pattern, pattern, pattern, pattern)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}
