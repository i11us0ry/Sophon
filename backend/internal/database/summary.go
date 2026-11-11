package database

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type ConversationSummary struct {
	ConversationID   string
	Summary          string
	ThroughMessageID string
	Version          int
	TokenBefore      int
	TokenAfter       int
	TranscriptPath   string
	UpdatedAt        time.Time
}

func (db *DB) SaveConversationSummary(
	ctx context.Context,
	summary ConversationSummary,
) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO conversation_summaries (
			conversation_id, summary, through_message_id,
			version, token_before, token_after, transcript_path, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(conversation_id) DO UPDATE SET
			summary = excluded.summary,
			through_message_id = excluded.through_message_id,
			version = excluded.version,
			token_before = excluded.token_before,
			token_after = excluded.token_after,
			transcript_path = excluded.transcript_path,
			updated_at = excluded.updated_at`,
		summary.ConversationID,
		summary.Summary,
		summary.ThroughMessageID,
		summary.Version,
		summary.TokenBefore,
		summary.TokenAfter,
		summary.TranscriptPath,
		summary.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) GetConversationSummary(
	ctx context.Context,
	conversationID string,
) (*ConversationSummary, error) {
	var summary ConversationSummary
	var updatedAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT conversation_id, summary, through_message_id,
		        version, token_before, token_after, transcript_path, updated_at
		 FROM conversation_summaries
		 WHERE conversation_id = ?`,
		conversationID,
	).Scan(
		&summary.ConversationID,
		&summary.Summary,
		&summary.ThroughMessageID,
		&summary.Version,
		&summary.TokenBefore,
		&summary.TokenAfter,
		&summary.TranscriptPath,
		&updatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	summary.UpdatedAt = time.Unix(updatedAt, 0)
	return &summary, nil
}

// ContextCompaction 记录一次上下文压缩的前后 token、耗时与原文路径，用于审计与看板。
type ContextCompaction struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversationId"`
	TokensBefore   int       `json:"tokensBefore"`
	TokensAfter    int       `json:"tokensAfter"`
	SummaryTokens  int       `json:"summaryTokens"`
	Kind           string    `json:"kind"`
	Model          string    `json:"model"`
	LatencyMs      int64     `json:"latencyMs"`
	TriggerRatio   float64   `json:"triggerRatio"`
	TranscriptPath string    `json:"transcriptPath"`
	CreatedAt      time.Time `json:"createdAt"`
}

func (db *DB) AddContextCompaction(ctx context.Context, item ContextCompaction) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO context_compactions (
			id, conversation_id, tokens_before, tokens_after, summary_tokens,
			kind, model, latency_ms, trigger_ratio, transcript_path, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.ConversationID,
		item.TokensBefore,
		item.TokensAfter,
		item.SummaryTokens,
		normalizeCompactionKind(item.Kind),
		item.Model,
		item.LatencyMs,
		item.TriggerRatio,
		item.TranscriptPath,
		item.CreatedAt.Unix(),
	)
	return err
}

func (db *DB) ListContextCompactions(
	ctx context.Context,
	conversationID string,
	limit int,
) ([]ContextCompaction, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, tokens_before, tokens_after, summary_tokens,
		        kind, model, latency_ms, trigger_ratio, transcript_path, created_at
		 FROM context_compactions
		 WHERE conversation_id = ?
		 ORDER BY created_at DESC
		 LIMIT ?`,
		conversationID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]ContextCompaction, 0)
	for rows.Next() {
		var item ContextCompaction
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.TokensBefore,
			&item.TokensAfter,
			&item.SummaryTokens,
			&item.Kind,
			&item.Model,
			&item.LatencyMs,
			&item.TriggerRatio,
			&item.TranscriptPath,
			&createdAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func normalizeCompactionKind(kind string) string {
	kind = strings.TrimSpace(kind)
	if kind == "" {
		return "major"
	}
	return kind
}

// ListContextCompactionsForUser 按会话所有者过滤压缩记录；conversationID 为空时返回该用户全部会话记录。
func (db *DB) ListContextCompactionsForUser(
	ctx context.Context,
	userID string,
	conversationID string,
	limit int,
	all bool,
) ([]ContextCompaction, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `SELECT c.id, c.conversation_id, c.tokens_before, c.tokens_after, c.summary_tokens,
	                 c.kind, c.model, c.latency_ms, c.trigger_ratio, c.transcript_path, c.created_at
	          FROM context_compactions c`
	args := []interface{}{}
	if all {
		query += " WHERE 1 = 1"
	} else {
		query += ` JOIN conversations conv ON conv.id = c.conversation_id
		          WHERE conv.owner_user_id = ?`
		args = append(args, userID)
	}
	if conversationID = strings.TrimSpace(conversationID); conversationID != "" {
		query += " AND c.conversation_id = ?"
		args = append(args, conversationID)
	}
	query += " ORDER BY c.created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ContextCompaction, 0)
	for rows.Next() {
		var item ContextCompaction
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.TokensBefore,
			&item.TokensAfter,
			&item.SummaryTokens,
			&item.Kind,
			&item.Model,
			&item.LatencyMs,
			&item.TriggerRatio,
			&item.TranscriptPath,
			&createdAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}
