package database

import (
	"context"
	"strings"
	"time"
)

type ProjectHistoryHit struct {
	MessageID      string
	ConversationID string
	Title          string
	Role           string
	Content        string
	CreatedAt      time.Time
}

func (db *DB) SearchProjectHistory(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	query string,
	limit int,
	offset int,
) ([]ProjectHistoryHit, int, error) {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	query = strings.TrimSpace(query)
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	where := `c.project_id = ? AND c.owner_user_id = ?
		AND m.role IN ('user', 'assistant')`
	args := []interface{}{projectID, ownerUserID}
	if query != "" {
		where += ` AND m.content LIKE ? ESCAPE '\'`
		args = append(args, "%"+escapeLike(query)+"%")
	}
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM messages m
		 JOIN conversations c ON c.id = m.conversation_id
		 WHERE `+where,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT m.id, m.conversation_id, c.title, m.role, m.content, m.created_at
		 FROM messages m
		 JOIN conversations c ON c.id = m.conversation_id
		 WHERE `+where+`
		 ORDER BY m.created_at DESC, m.rowid DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]ProjectHistoryHit, 0, limit)
	for rows.Next() {
		var item ProjectHistoryHit
		var createdAt int64
		if err := rows.Scan(
			&item.MessageID,
			&item.ConversationID,
			&item.Title,
			&item.Role,
			&item.Content,
			&createdAt,
		); err != nil {
			return nil, 0, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func escapeLike(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	return strings.ReplaceAll(value, `_`, `\_`)
}
