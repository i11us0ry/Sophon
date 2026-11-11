package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type Attachment struct {
	ID             string
	ConversationID string
	MessageID      string
	FileName       string
	MimeType       string
	SizeBytes      int64
	StoragePath    string
	TextContent    string
	CreatedAt      time.Time
}

func (db *DB) AddAttachment(ctx context.Context, item Attachment) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO attachments (
			id, conversation_id, message_id, file_name, mime_type,
			size_bytes, storage_path, text_content, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.ConversationID,
		nullableString(item.MessageID),
		item.FileName,
		item.MimeType,
		item.SizeBytes,
		item.StoragePath,
		item.TextContent,
		item.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("add attachment: %w", err)
	}
	return nil
}

// ListAttachments 按上传时间正序返回会话附件。
func (db *DB) ListAttachments(ctx context.Context, conversationID string) ([]Attachment, error) {
	return db.queryAttachments(ctx, conversationID, "ASC", 0)
}

// ListRecentAttachments 返回最近上传的附件（按时间正序），供上下文摘要使用。
func (db *DB) ListRecentAttachments(
	ctx context.Context,
	conversationID string,
	limit int,
) ([]Attachment, error) {
	if limit <= 0 || limit > 50 {
		limit = 5
	}
	items, err := db.queryAttachments(ctx, conversationID, "DESC", limit)
	if err != nil {
		return nil, err
	}
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
	return items, nil
}

func (db *DB) queryAttachments(
	ctx context.Context,
	conversationID string,
	order string,
	limit int,
) ([]Attachment, error) {
	query := `SELECT id, conversation_id, COALESCE(message_id, ''), file_name, mime_type,
			size_bytes, storage_path, text_content, created_at
		 FROM attachments WHERE conversation_id = ?
		 ORDER BY created_at ` + order + `, rowid ` + order
	args := []interface{}{conversationID}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]Attachment, 0)
	for rows.Next() {
		var item Attachment
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.MessageID,
			&item.FileName,
			&item.MimeType,
			&item.SizeBytes,
			&item.StoragePath,
			&item.TextContent,
			&createdAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetAttachment(ctx context.Context, id string) (*Attachment, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, conversation_id, COALESCE(message_id, ''), file_name, mime_type,
			size_bytes, storage_path, text_content, created_at
		 FROM attachments WHERE id = ?`,
		id,
	)
	var item Attachment
	var createdAt int64
	if err := row.Scan(
		&item.ID,
		&item.ConversationID,
		&item.MessageID,
		&item.FileName,
		&item.MimeType,
		&item.SizeBytes,
		&item.StoragePath,
		&item.TextContent,
		&createdAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("attachment not found")
		}
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	return &item, nil
}

func (db *DB) CountPendingAttachments(ctx context.Context, conversationID string) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM attachments
		 WHERE conversation_id = ? AND message_id IS NULL`,
		conversationID,
	).Scan(&count)
	return count, err
}

// LinkAttachments 把未发送的附件关联到消息，返回关联数量。
func (db *DB) LinkAttachments(
	ctx context.Context,
	conversationID string,
	messageID string,
	ids []string,
) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, 0, len(ids)+2)
	args = append(args, messageID, conversationID)
	for _, id := range ids {
		args = append(args, id)
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE attachments SET message_id = ?
		 WHERE conversation_id = ? AND message_id IS NULL AND id IN (`+placeholders+`)`,
		args...,
	)
	if err != nil {
		return 0, fmt.Errorf("link attachments: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(affected), nil
}

func (db *DB) DeleteAttachment(ctx context.Context, id string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM attachments WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete attachment: %w", err)
	}
	return nil
}

func (db *DB) ListAttachmentStoragePathsAfterMessage(
	ctx context.Context,
	conversationID string,
	messageID string,
) ([]string, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT a.storage_path
		 FROM attachments a
		 JOIN messages m ON m.id = a.message_id
		 WHERE a.conversation_id = ?
		 AND m.rowid > (
			SELECT rowid FROM messages WHERE id = ? AND conversation_id = ?
		 )`,
		conversationID,
		messageID,
		conversationID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	paths := make([]string, 0)
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			return nil, err
		}
		if strings.TrimSpace(path) != "" {
			paths = append(paths, path)
		}
	}
	return paths, rows.Err()
}
