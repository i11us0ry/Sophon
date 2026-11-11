package database

import (
	"context"
	"encoding/json"
	"time"
)

type KnowledgeChunk struct {
	ID         string
	ItemID     string
	ChunkIndex int
	Content    string
	Embedding  []float64
	UpdatedAt  time.Time
}

type KnowledgeChunkResult struct {
	KnowledgeChunk
	ItemTitle string
	Category  string
}

func (db *DB) ReplaceKnowledgeChunks(
	ctx context.Context,
	itemID string,
	chunks []KnowledgeChunk,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM knowledge_chunks WHERE item_id = ?`, itemID); err != nil {
		return err
	}
	for _, chunk := range chunks {
		embeddingJSON, err := json.Marshal(chunk.Embedding)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO knowledge_chunks (
				id, item_id, chunk_index, content, embedding, updated_at
			) VALUES (?, ?, ?, ?, ?, ?)`,
			chunk.ID,
			itemID,
			chunk.ChunkIndex,
			chunk.Content,
			string(embeddingJSON),
			time.Now().UTC().Unix(),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) ListKnowledgeChunks(
	ctx context.Context,
	ownerUserID string,
) ([]KnowledgeChunkResult, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT
			c.id, c.item_id, c.chunk_index, c.content, c.embedding, c.updated_at,
			i.title, i.category
		 FROM knowledge_chunks c
		 JOIN knowledge_items i ON i.id = c.item_id
		 WHERE i.owner_user_id = ?`,
		ownerUserID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]KnowledgeChunkResult, 0)
	for rows.Next() {
		var item KnowledgeChunkResult
		var embeddingJSON string
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ItemID,
			&item.ChunkIndex,
			&item.Content,
			&embeddingJSON,
			&updatedAt,
			&item.ItemTitle,
			&item.Category,
		); err != nil {
			return nil, err
		}
		item.UpdatedAt = time.Unix(updatedAt, 0)
		_ = json.Unmarshal([]byte(embeddingJSON), &item.Embedding)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) DeleteKnowledgeItem(ctx context.Context, id, ownerUserID string) error {
	_, err := db.ExecContext(
		ctx,
		`DELETE FROM knowledge_items WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	)
	return err
}
