package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

const maxHITLArgumentsBytes = 64 << 10

type HITLRequest struct {
	ID             string                 `json:"id"`
	ConversationID string                 `json:"conversationId"`
	UserID         string                 `json:"userId"`
	ToolName       string                 `json:"toolName"`
	Arguments      map[string]interface{} `json:"arguments"`
	Status         string                 `json:"status"`
	Comment        string                 `json:"comment"`
	CreatedAt      time.Time              `json:"createdAt"`
	DecidedAt      *time.Time             `json:"decidedAt"`
	DecidedBy      string                 `json:"decidedBy"`
}

func (db *DB) CreateHITLRequest(ctx context.Context, request HITLRequest) error {
	raw, err := json.Marshal(request.Arguments)
	if err != nil {
		return fmt.Errorf("marshal HITL arguments: %w", err)
	}
	if len(raw) > maxHITLArgumentsBytes {
		return fmt.Errorf("HITL 工具参数超过 %dKB 上限", maxHITLArgumentsBytes/1024)
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO hitl_requests (
			id, conversation_id, user_id, tool_name, arguments,
			status, comment, created_at
		) VALUES (?, ?, ?, ?, ?, 'pending', '', ?)`,
		request.ID,
		request.ConversationID,
		request.UserID,
		request.ToolName,
		string(raw),
		request.CreatedAt.Unix(),
	)
	return err
}

func (db *DB) GetHITLRequest(ctx context.Context, id string) (*HITLRequest, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, conversation_id, user_id, tool_name, arguments,
			status, comment, created_at, decided_at, decided_by
		 FROM hitl_requests
		 WHERE id = ?`,
		id,
	)
	return scanHITLRequest(row)
}

func (db *DB) ListPendingHITLRequests(
	ctx context.Context,
	userID string,
) ([]HITLRequest, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, user_id, tool_name, arguments,
			status, comment, created_at, decided_at, decided_by
		 FROM hitl_requests
		 WHERE status = 'pending' AND user_id = ?
		 ORDER BY created_at ASC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]HITLRequest, 0)
	for rows.Next() {
		item, err := scanHITLRequestRows(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}

// PendingHITLConversationIDs 返回当前用户存在待审批请求的会话集合。
func (db *DB) PendingHITLConversationIDs(
	ctx context.Context,
	userID string,
) (map[string]bool, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT DISTINCT conversation_id
		 FROM hitl_requests
		 WHERE status = 'pending' AND user_id = ?`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]bool)
	for rows.Next() {
		var conversationID string
		if err := rows.Scan(&conversationID); err != nil {
			return nil, err
		}
		result[conversationID] = true
	}
	return result, rows.Err()
}

func (db *DB) DecideHITLRequest(
	ctx context.Context,
	id string,
	ownerUserID string,
	approved bool,
	comment string,
	decidedBy string,
) error {
	status := "rejected"
	if approved {
		status = "approved"
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE hitl_requests
		 SET status = ?, comment = ?, decided_at = ?, decided_by = ?
		 WHERE id = ? AND user_id = ? AND status = 'pending'`,
		status,
		comment,
		time.Now().UTC().Unix(),
		decidedBy,
		id,
		ownerUserID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func scanHITLRequest(row *sql.Row) (*HITLRequest, error) {
	return scanHITLRequestScanner(row)
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanHITLRequestRows(rows *sql.Rows) (*HITLRequest, error) {
	return scanHITLRequestScanner(rows)
}

func scanHITLRequestScanner(scanner rowScanner) (*HITLRequest, error) {
	var item HITLRequest
	var raw string
	var createdAt int64
	var decidedAt sql.NullInt64
	if err := scanner.Scan(
		&item.ID,
		&item.ConversationID,
		&item.UserID,
		&item.ToolName,
		&raw,
		&item.Status,
		&item.Comment,
		&createdAt,
		&decidedAt,
		&item.DecidedBy,
	); err != nil {
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	if decidedAt.Valid {
		value := time.Unix(decidedAt.Int64, 0)
		item.DecidedAt = &value
	}
	_ = json.Unmarshal([]byte(raw), &item.Arguments)
	return &item, nil
}
