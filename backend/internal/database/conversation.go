package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotLastUserMessage 表示待编辑的消息不是会话最后一条用户消息。
var ErrNotLastUserMessage = errors.New("不是最后一条用户消息")

type Conversation struct {
	ID                   string
	OwnerUserID          string
	ProjectID            string    `json:"projectId"`
	AssetID              string    `json:"assetId"`
	Kind                 string    `json:"kind"`
	ParentConversationID string    `json:"parentConversationId"`
	BatchID              string    `json:"batchId"`
	ChildCount           int       `json:"childCount"`
	AgentRoleID          string    `json:"agentRoleId"`
	Title                string    `json:"title"`
	LastUserMessage      string    `json:"lastUserMessage,omitempty"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

type Message struct {
	ID               string
	ConversationID   string
	Role             string
	Content          string
	ReasoningContent string
	CreatedAt        time.Time
}

type ProcessDetail struct {
	ID             string
	ConversationID string
	MessageID      string
	EventType      string
	Message        string
	Data           map[string]interface{}
	CreatedAt      time.Time
}

func (db *DB) CreateConversation(ctx context.Context, conversation Conversation) error {
	conversation.Kind = strings.TrimSpace(conversation.Kind)
	if conversation.Kind == "" {
		conversation.Kind = "normal"
	}
	conversation.ParentConversationID = strings.TrimSpace(conversation.ParentConversationID)
	conversation.BatchID = strings.TrimSpace(conversation.BatchID)
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO conversations (
			id, owner_user_id, project_id, asset_id, kind, parent_conversation_id,
			batch_id, agent_role_id, title, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		conversation.ID,
		conversation.OwnerUserID,
		conversation.ProjectID,
		conversation.AssetID,
		conversation.Kind,
		conversation.ParentConversationID,
		conversation.BatchID,
		conversation.AgentRoleID,
		conversation.Title,
		conversation.CreatedAt.Unix(),
		conversation.UpdatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("create conversation: %w", err)
	}
	return nil
}

func (db *DB) ListConversations(ctx context.Context, ownerUserID string, limit int) ([]Conversation, error) {
	items, _, err := db.ListConversationsPage(ctx, ownerUserID, limit, "")
	return items, err
}

// ListConversationsPage 返回 beforeConversationID 之前的对话，按更新时间倒序排列。
func (db *DB) ListConversationsPage(
	ctx context.Context,
	ownerUserID string,
	limit int,
	beforeConversationID string,
) ([]Conversation, bool, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	query := `SELECT id, owner_user_id, project_id, asset_id, kind, parent_conversation_id,
			batch_id, agent_role_id, title, created_at, updated_at,
			(SELECT COUNT(*) FROM conversations child
			 WHERE child.owner_user_id = conversations.owner_user_id
			   AND child.parent_conversation_id = conversations.id) AS child_count,
			COALESCE((SELECT SUBSTR(message.content, 1, 300)
			 FROM messages message
			 WHERE message.conversation_id = conversations.id
			   AND message.role = 'user'
			 ORDER BY message.created_at DESC, message.rowid DESC
			 LIMIT 1), '') AS last_user_message
		FROM conversations
		WHERE owner_user_id = ? AND parent_conversation_id = ''`
	args := []interface{}{ownerUserID}
	if beforeConversationID = strings.TrimSpace(beforeConversationID); beforeConversationID != "" {
		var updatedAt int64
		var ordering int64
		err := db.QueryRowContext(
			ctx,
			`SELECT updated_at, rowid FROM conversations WHERE id = ? AND owner_user_id = ?`,
			beforeConversationID,
			ownerUserID,
		).Scan(&updatedAt, &ordering)
		if errors.Is(err, sql.ErrNoRows) {
			return []Conversation{}, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		query += ` AND (updated_at < ? OR (updated_at = ? AND rowid < ?))`
		args = append(args, updatedAt, updatedAt, ordering)
	}
	query += ` ORDER BY updated_at DESC, rowid DESC LIMIT ?`
	args = append(args, limit+1)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	conversations := make([]Conversation, 0)
	for rows.Next() {
		var item Conversation
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.OwnerUserID,
			&item.ProjectID,
			&item.AssetID,
			&item.Kind,
			&item.ParentConversationID,
			&item.BatchID,
			&item.AgentRoleID,
			&item.Title,
			&createdAt,
			&updatedAt,
			&item.ChildCount,
			&item.LastUserMessage,
		); err != nil {
			return nil, false, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		conversations = append(conversations, item)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(conversations) > limit
	if hasMore {
		conversations = conversations[:limit]
	}
	return conversations, hasMore, nil
}

func (db *DB) GetConversation(ctx context.Context, id, ownerUserID string) (*Conversation, error) {
	var item Conversation
	var createdAt int64
	var updatedAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT id, owner_user_id, project_id, asset_id, kind, parent_conversation_id,
			batch_id, agent_role_id, title, created_at, updated_at,
			(SELECT COUNT(*) FROM conversations child
			 WHERE child.owner_user_id = conversations.owner_user_id
			   AND child.parent_conversation_id = conversations.id) AS child_count
		 FROM conversations
		 WHERE id = ? AND owner_user_id = ?`,
		id,
		ownerUserID,
	).Scan(
		&item.ID,
		&item.OwnerUserID,
		&item.ProjectID,
		&item.AssetID,
		&item.Kind,
		&item.ParentConversationID,
		&item.BatchID,
		&item.AgentRoleID,
		&item.Title,
		&createdAt,
		&updatedAt,
		&item.ChildCount,
	)
	if err != nil {
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return &item, nil
}

// ListConversationChildren 返回批量父对话下的资产子对话。
func (db *DB) ListConversationChildren(
	ctx context.Context,
	parentConversationID string,
	ownerUserID string,
	limit int,
	offset int,
) ([]Conversation, int, error) {
	parentConversationID = strings.TrimSpace(parentConversationID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if parentConversationID == "" || ownerUserID == "" {
		return []Conversation{}, 0, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM conversations
		 WHERE owner_user_id = ? AND parent_conversation_id = ?`,
		ownerUserID,
		parentConversationID,
	).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, owner_user_id, project_id, asset_id, kind, parent_conversation_id,
			batch_id, agent_role_id, title, created_at, updated_at
		 FROM conversations
		 WHERE owner_user_id = ? AND parent_conversation_id = ?
		 ORDER BY created_at ASC, rowid ASC
		 LIMIT ? OFFSET ?`,
		ownerUserID,
		parentConversationID,
		limit,
		offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]Conversation, 0)
	for rows.Next() {
		var item Conversation
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.OwnerUserID,
			&item.ProjectID,
			&item.AssetID,
			&item.Kind,
			&item.ParentConversationID,
			&item.BatchID,
			&item.AgentRoleID,
			&item.Title,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, 0, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (db *DB) SetConversationAgentRole(
	ctx context.Context,
	id string,
	ownerUserID string,
	agentRoleID string,
) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE conversations SET agent_role_id = ?, updated_at = ? WHERE id = ? AND owner_user_id = ?`,
		agentRoleID,
		time.Now().UTC().Unix(),
		id,
		ownerUserID,
	)
	return requireAffected(result, err)
}

// DeleteConversations 删除会话并清理关联的流水数据（消息等由外键级联删除）。
func (db *DB) DeleteConversations(
	ctx context.Context,
	ids []string,
	ownerUserID string,
) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	deleteIDs := make([]string, 0, len(ids))
	seenIDs := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seenIDs[id] {
			continue
		}
		seenIDs[id] = true
		deleteIDs = append(deleteIDs, id)
		rows, err := db.QueryContext(
			ctx,
			`SELECT id FROM conversations
			 WHERE owner_user_id = ? AND parent_conversation_id = ?`,
			ownerUserID,
			id,
		)
		if err != nil {
			return 0, err
		}
		for rows.Next() {
			var childID string
			if err := rows.Scan(&childID); err != nil {
				_ = rows.Close()
				return 0, err
			}
			if !seenIDs[childID] {
				seenIDs[childID] = true
				deleteIDs = append(deleteIDs, childID)
			}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return 0, err
		}
		_ = rows.Close()
	}
	ids = deleteIDs

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_chain_steps WHERE chain_id IN (
			SELECT id FROM campaign_chains WHERE campaign_id IN (
				SELECT id FROM conversation_batches
				WHERE parent_conversation_id IN (`+placeholders(len(ids))+`)
			)
		 )`,
		buildIDArgs(nil, ids)...,
	); err != nil {
		return 0, err
	}
	for _, statement := range []string{
		`DELETE FROM campaign_chains WHERE campaign_id IN (
			SELECT id FROM conversation_batches
			WHERE parent_conversation_id IN (` + placeholders(len(ids)) + `)
		 )`,
		`DELETE FROM campaign_memory_digests WHERE campaign_id IN (
			SELECT id FROM conversation_batches
			WHERE parent_conversation_id IN (` + placeholders(len(ids)) + `)
		 )`,
		`DELETE FROM campaign_verifications WHERE campaign_id IN (
			SELECT id FROM conversation_batches
			WHERE parent_conversation_id IN (` + placeholders(len(ids)) + `)
		 )`,
		`DELETE FROM campaign_links WHERE campaign_id IN (
			SELECT id FROM conversation_batches
			WHERE parent_conversation_id IN (` + placeholders(len(ids)) + `)
		 )`,
		`DELETE FROM campaign_frontier WHERE campaign_id IN (
			SELECT id FROM conversation_batches
			WHERE parent_conversation_id IN (` + placeholders(len(ids)) + `)
		 )`,
	} {
		if _, err := tx.ExecContext(ctx, statement, buildIDArgs(nil, ids)...); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_coverage WHERE campaign_id IN (
			SELECT id FROM conversation_batches
			WHERE parent_conversation_id IN (`+placeholders(len(ids))+`)
		 )`,
		buildIDArgs(nil, ids)...,
	); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_tasks WHERE conversation_id IN (`+placeholders(len(ids))+`)`,
		buildIDArgs(nil, ids)...,
	); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_groups WHERE campaign_id IN (
			SELECT id FROM conversation_batches
			WHERE parent_conversation_id IN (`+placeholders(len(ids))+`)
		 )`,
		buildIDArgs(nil, ids)...,
	); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM campaign_endpoints WHERE campaign_id IN (
			SELECT id FROM conversation_batches
			WHERE parent_conversation_id IN (`+placeholders(len(ids))+`)
		 )`,
		buildIDArgs(nil, ids)...,
	); err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM conversation_batches
		 WHERE owner_user_id = ? AND parent_conversation_id IN (`+placeholders(len(ids))+`)`,
		buildIDArgs([]interface{}{ownerUserID}, ids)...,
	); err != nil {
		return 0, err
	}

	deleted := 0
	for _, id := range ids {
		result, err := tx.ExecContext(
			ctx,
			`DELETE FROM conversations WHERE id = ? AND owner_user_id = ?`,
			id,
			ownerUserID,
		)
		if err != nil {
			return 0, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if affected == 0 {
			continue
		}
		deleted++
		for _, statement := range []string{
			`DELETE FROM token_usage WHERE conversation_id = ?`,
			`DELETE FROM hitl_requests WHERE conversation_id = ?`,
			`DELETE FROM tool_executions WHERE conversation_id = ?`,
			`DELETE FROM tool_jobs WHERE conversation_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, statement, id); err != nil {
				return 0, err
			}
		}
	}
	if deleted == 0 {
		return 0, nil
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return deleted, nil
}

func (db *DB) AddMessage(ctx context.Context, message Message) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO messages (
			id, conversation_id, role, content, reasoning_content, created_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		message.ID,
		message.ConversationID,
		message.Role,
		message.Content,
		message.ReasoningContent,
		message.CreatedAt.Unix(),
	); err != nil {
		return fmt.Errorf("add message: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE conversations SET updated_at = ? WHERE id = ?`,
		message.CreatedAt.Unix(),
		message.ConversationID,
	); err != nil {
		return fmt.Errorf("touch conversation: %w", err)
	}
	return tx.Commit()
}

func (db *DB) UpdateMessageContent(
	ctx context.Context,
	messageID string,
	content string,
	reasoningContent string,
) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE messages
		 SET content = ?, reasoning_content = ?
		 WHERE id = ?`,
		content,
		reasoningContent,
		messageID,
	)
	if err != nil {
		return fmt.Errorf("update message: %w", err)
	}
	return nil
}

// SetConversationTitleIfDefault 仅在会话仍是默认标题时改写标题。
func (db *DB) SetConversationTitleIfDefault(
	ctx context.Context,
	conversationID string,
	title string,
) error {
	title = strings.TrimSpace(title)
	if title == "" {
		return nil
	}
	_, err := db.ExecContext(
		ctx,
		`UPDATE conversations SET title = ?
		 WHERE id = ? AND title IN ('', '新对话', 'New Chat')`,
		title,
		conversationID,
	)
	if err != nil {
		return fmt.Errorf("update conversation title: %w", err)
	}
	return nil
}

// ResetAssistantMessage 清空助手消息内容并删除其过程明细，供重新生成使用。
func (db *DB) ResetAssistantMessage(ctx context.Context, messageID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM process_details WHERE message_id = ?`,
		messageID,
	); err != nil {
		return fmt.Errorf("clear process details: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE messages SET content = '', reasoning_content = '' WHERE id = ?`,
		messageID,
	); err != nil {
		return fmt.Errorf("reset assistant message: %w", err)
	}
	return tx.Commit()
}

// EditLastUserMessage 用新内容替换最后一条用户消息，并删除其后产生的回复与流水。
func (db *DB) EditLastUserMessage(
	ctx context.Context,
	conversationID string,
	messageID string,
	content string,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var lastUserID string
	err = tx.QueryRowContext(
		ctx,
		`SELECT id FROM messages
		 WHERE conversation_id = ? AND role = 'user'
		 ORDER BY created_at DESC, rowid DESC
		 LIMIT 1`,
		conversationID,
	).Scan(&lastUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotLastUserMessage
	}
	if err != nil {
		return err
	}
	if lastUserID != messageID {
		return ErrNotLastUserMessage
	}

	subsequent := `SELECT id FROM messages WHERE conversation_id = ? AND rowid > (SELECT rowid FROM messages WHERE id = ?)`
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM process_details WHERE conversation_id = ? AND message_id IN (`+subsequent+`)`,
		conversationID,
		conversationID,
		messageID,
	); err != nil {
		return fmt.Errorf("clear process details: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM token_usage WHERE conversation_id = ? AND message_id IN (`+subsequent+`)`,
		conversationID,
		conversationID,
		messageID,
	); err != nil {
		return fmt.Errorf("clear token usage: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM messages WHERE conversation_id = ? AND rowid > (SELECT rowid FROM messages WHERE id = ?)`,
		conversationID,
		messageID,
	); err != nil {
		return fmt.Errorf("truncate messages: %w", err)
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE messages SET content = ? WHERE id = ?`,
		strings.TrimSpace(content),
		messageID,
	); err != nil {
		return fmt.Errorf("update message: %w", err)
	}
	return tx.Commit()
}

func (db *DB) GetMessages(ctx context.Context, conversationID string, limit int) ([]Message, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, role, content, reasoning_content, created_at
		 FROM (
			SELECT id, conversation_id, role, content, reasoning_content, created_at, rowid AS ordering
			FROM messages
			WHERE conversation_id = ?
			ORDER BY created_at DESC, rowid DESC
			LIMIT ?
		 )
		 ORDER BY created_at ASC, ordering ASC`,
		conversationID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := make([]Message, 0)
	for rows.Next() {
		var message Message
		var createdAt int64
		if err := rows.Scan(
			&message.ID,
			&message.ConversationID,
			&message.Role,
			&message.Content,
			&message.ReasoningContent,
			&createdAt,
		); err != nil {
			return nil, err
		}
		message.CreatedAt = time.Unix(createdAt, 0)
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

// GetMessagePage 返回 beforeMessageID 之前的一页消息，结果按时间正序排列。
// beforeMessageID 为空时返回最新一页；hasMore 表示是否存在更早的消息。
func (db *DB) GetMessagePage(
	ctx context.Context,
	conversationID string,
	beforeMessageID string,
	limit int,
) ([]Message, bool, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	var query strings.Builder
	query.WriteString(`SELECT id, conversation_id, role, content, reasoning_content, created_at
		FROM (
			SELECT id, conversation_id, role, content, reasoning_content, created_at, rowid AS ordering
			FROM messages
			WHERE conversation_id = ?`)
	args := []interface{}{conversationID}

	if strings.TrimSpace(beforeMessageID) != "" {
		var createdAt int64
		var ordering int64
		err := db.QueryRowContext(
			ctx,
			`SELECT created_at, rowid FROM messages WHERE id = ? AND conversation_id = ?`,
			beforeMessageID,
			conversationID,
		).Scan(&createdAt, &ordering)
		if errors.Is(err, sql.ErrNoRows) {
			return []Message{}, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("resolve message cursor: %w", err)
		}
		query.WriteString(` AND (created_at < ? OR (created_at = ? AND rowid < ?))`)
		args = append(args, createdAt, createdAt, ordering)
	}

	query.WriteString(` ORDER BY created_at DESC, ordering DESC LIMIT ?
		)
		ORDER BY created_at ASC, ordering ASC`)
	args = append(args, limit+1)

	rows, err := db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	messages := make([]Message, 0, limit+1)
	for rows.Next() {
		var message Message
		var createdAt int64
		if err := rows.Scan(
			&message.ID,
			&message.ConversationID,
			&message.Role,
			&message.Content,
			&message.ReasoningContent,
			&createdAt,
		); err != nil {
			return nil, false, err
		}
		message.CreatedAt = time.Unix(createdAt, 0)
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	hasMore := len(messages) > limit
	if hasMore {
		messages = messages[len(messages)-limit:]
	}
	return messages, hasMore, nil
}

// GetMessagePageAfter 返回 afterMessageID 之后的一页消息，结果按时间正序排列。
// hasMore 表示还存在更新的消息，供前端向下恢复滑动窗口。
func (db *DB) GetMessagePageAfter(
	ctx context.Context,
	conversationID string,
	afterMessageID string,
	limit int,
) ([]Message, bool, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	afterMessageID = strings.TrimSpace(afterMessageID)
	if afterMessageID == "" {
		return []Message{}, false, nil
	}

	var createdAt int64
	var ordering int64
	err := db.QueryRowContext(
		ctx,
		`SELECT created_at, rowid FROM messages WHERE id = ? AND conversation_id = ?`,
		afterMessageID,
		conversationID,
	).Scan(&createdAt, &ordering)
	if errors.Is(err, sql.ErrNoRows) {
		return []Message{}, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("resolve message cursor: %w", err)
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, role, content, reasoning_content, created_at
		 FROM messages
		 WHERE conversation_id = ?
		   AND (created_at > ? OR (created_at = ? AND rowid > ?))
		 ORDER BY created_at ASC, rowid ASC
		 LIMIT ?`,
		conversationID,
		createdAt,
		createdAt,
		ordering,
		limit+1,
	)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	messages := make([]Message, 0, limit+1)
	for rows.Next() {
		var message Message
		var messageCreatedAt int64
		if err := rows.Scan(
			&message.ID,
			&message.ConversationID,
			&message.Role,
			&message.Content,
			&message.ReasoningContent,
			&messageCreatedAt,
		); err != nil {
			return nil, false, err
		}
		message.CreatedAt = time.Unix(messageCreatedAt, 0)
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	hasMore := len(messages) > limit
	if hasMore {
		messages = messages[:limit]
	}
	return messages, hasMore, nil
}

const (
	maxProcessDetailMessageRunes = 2000
	maxProcessDetailDataBytes    = 128 << 10
)

func (db *DB) AddProcessDetail(ctx context.Context, detail ProcessDetail) error {
	dataJSON := "{}"
	if detail.Data != nil {
		raw, err := json.Marshal(detail.Data)
		if err != nil {
			return fmt.Errorf("marshal process detail: %w", err)
		}
		dataJSON = string(raw)
	}
	if len(dataJSON) > maxProcessDetailDataBytes {
		dataJSON = fmt.Sprintf(
			`{"truncated":true,"originalBytes":%d}`,
			len(dataJSON),
		)
	}
	message := detail.Message
	if runes := []rune(message); len(runes) > maxProcessDetailMessageRunes {
		message = string(runes[:maxProcessDetailMessageRunes]) + "…"
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO process_details (
			id, conversation_id, message_id, event_type, message, data, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		detail.ID,
		detail.ConversationID,
		nullableString(detail.MessageID),
		detail.EventType,
		message,
		dataJSON,
		detail.CreatedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("add process detail: %w", err)
	}
	return nil
}

func (db *DB) ListProcessDetails(ctx context.Context, conversationID string, limit int) ([]ProcessDetail, error) {
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, COALESCE(message_id, ''), event_type, message, data, created_at
		 FROM (
			SELECT id, conversation_id, COALESCE(message_id, '') AS message_id,
				event_type, message, data, created_at, rowid AS ordering
			FROM process_details
			WHERE conversation_id = ?
			ORDER BY created_at DESC, rowid DESC
			LIMIT ?
		 )
		 ORDER BY created_at ASC, ordering ASC`,
		conversationID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	details := make([]ProcessDetail, 0)
	for rows.Next() {
		var detail ProcessDetail
		var dataJSON string
		var createdAt int64
		if err := rows.Scan(
			&detail.ID,
			&detail.ConversationID,
			&detail.MessageID,
			&detail.EventType,
			&detail.Message,
			&dataJSON,
			&createdAt,
		); err != nil {
			return nil, err
		}
		detail.CreatedAt = time.Unix(createdAt, 0)
		_ = json.Unmarshal([]byte(dataJSON), &detail.Data)
		details = append(details, detail)
	}
	return details, rows.Err()
}

// ListProcessDetailsByMessageIDs 返回指定消息的过程明细，最多 1000 条，按时间正序排列。
func (db *DB) ListProcessDetailsByMessageIDs(
	ctx context.Context,
	conversationID string,
	messageIDs []string,
) ([]ProcessDetail, error) {
	ids := normalizeProcessDetailMessageIDs(messageIDs)
	items, _, _, err := db.ListProcessDetailsByMessageIDsPage(
		ctx,
		conversationID,
		ids,
		1000,
		0,
	)
	return items, err
}

func (db *DB) CountProcessDetailsByMessageIDs(
	ctx context.Context,
	conversationID string,
	messageIDs []string,
) (map[string]int, error) {
	ids := normalizeProcessDetailMessageIDs(messageIDs)
	result := make(map[string]int, len(ids))
	if len(ids) == 0 {
		return result, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, conversationID)
	for _, id := range ids {
		args = append(args, id)
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT message_id, COUNT(*) FROM process_details
		 WHERE conversation_id = ? AND message_id IN (`+placeholders+`)
		 GROUP BY message_id`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var messageID string
		var count int
		if err := rows.Scan(&messageID, &count); err != nil {
			return nil, err
		}
		result[messageID] = count
	}
	return result, rows.Err()
}

// ListAgentLifecycleDetails 返回用于 Agent 统计的生命周期事件，不受过程详情分页窗口限制。
func (db *DB) ListAgentLifecycleDetails(
	ctx context.Context,
	conversationID string,
	messageIDs []string,
) ([]ProcessDetail, error) {
	ids := normalizeProcessDetailMessageIDs(messageIDs)
	query := `SELECT id, conversation_id, COALESCE(message_id, ''), event_type, message, data, created_at
		FROM process_details
		WHERE conversation_id = ?
		  AND event_type IN ('subagent.started', 'subagent.completed', 'subagent.failed')`
	args := []interface{}{conversationID}
	if len(ids) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		query += ` AND message_id IN (` + placeholders + `)`
		for _, id := range ids {
			args = append(args, id)
		}
	}
	query += ` ORDER BY created_at ASC, rowid ASC LIMIT 5000`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	details := make([]ProcessDetail, 0)
	for rows.Next() {
		var detail ProcessDetail
		var dataJSON string
		var createdAt int64
		if err := rows.Scan(
			&detail.ID,
			&detail.ConversationID,
			&detail.MessageID,
			&detail.EventType,
			&detail.Message,
			&dataJSON,
			&createdAt,
		); err != nil {
			return nil, err
		}
		detail.CreatedAt = time.Unix(createdAt, 0)
		_ = json.Unmarshal([]byte(dataJSON), &detail.Data)
		details = append(details, detail)
	}
	return details, rows.Err()
}

func (db *DB) ListProcessDetailsByMessageIDsPage(
	ctx context.Context,
	conversationID string,
	messageIDs []string,
	limit int,
	offset int,
) ([]ProcessDetail, int, bool, error) {
	ids := normalizeProcessDetailMessageIDs(messageIDs)
	if len(ids) == 0 {
		return []ProcessDetail{}, 0, false, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]interface{}, 0, len(ids)+1)
	args = append(args, conversationID)
	for _, id := range ids {
		args = append(args, id)
	}
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM process_details
		 WHERE conversation_id = ? AND message_id IN (`+placeholders+`)`,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, false, err
	}
	queryArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, COALESCE(message_id, ''), event_type, message, data, created_at
		 FROM process_details
		 WHERE conversation_id = ? AND message_id IN (`+placeholders+`)
		 ORDER BY created_at ASC, rowid ASC
		 LIMIT ? OFFSET ?`,
		queryArgs...,
	)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()

	details := make([]ProcessDetail, 0)
	for rows.Next() {
		var detail ProcessDetail
		var dataJSON string
		var createdAt int64
		if err := rows.Scan(
			&detail.ID,
			&detail.ConversationID,
			&detail.MessageID,
			&detail.EventType,
			&detail.Message,
			&dataJSON,
			&createdAt,
		); err != nil {
			return nil, 0, false, err
		}
		detail.CreatedAt = time.Unix(createdAt, 0)
		_ = json.Unmarshal([]byte(dataJSON), &detail.Data)
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := offset+len(details) < total
	return details, total, hasMore, nil
}

func normalizeProcessDetailMessageIDs(messageIDs []string) []string {
	ids := make([]string, 0, len(messageIDs))
	seen := make(map[string]struct{}, len(messageIDs))
	for _, raw := range messageIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
		if len(ids) >= 50 {
			break
		}
	}
	return ids
}

// ListRecentProcessDetails 返回最近的过程明细（按时间正序），供上下文压缩使用。
func (db *DB) ListRecentProcessDetails(
	ctx context.Context,
	conversationID string,
	limit int,
) ([]ProcessDetail, error) {
	if limit <= 0 || limit > 200 {
		limit = 80
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, COALESCE(message_id, ''), event_type, message, data, created_at
		 FROM process_details
		 WHERE conversation_id = ?
		 ORDER BY created_at DESC, rowid DESC
		 LIMIT ?`,
		conversationID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	details := make([]ProcessDetail, 0, limit)
	for rows.Next() {
		var detail ProcessDetail
		var dataJSON string
		var createdAt int64
		if err := rows.Scan(
			&detail.ID,
			&detail.ConversationID,
			&detail.MessageID,
			&detail.EventType,
			&detail.Message,
			&dataJSON,
			&createdAt,
		); err != nil {
			return nil, err
		}
		detail.CreatedAt = time.Unix(createdAt, 0)
		_ = json.Unmarshal([]byte(dataJSON), &detail.Data)
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 查询按时间倒序取最近记录，这里翻回正序供调用方按发生顺序处理。
	for left, right := 0, len(details)-1; left < right; left, right = left+1, right-1 {
		details[left], details[right] = details[right], details[left]
	}
	return details, nil
}

func nullableString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}
