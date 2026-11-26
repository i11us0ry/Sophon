package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	ConversationLaneCoordinated = "coordinated"
	ConversationLaneFast        = "fast"
)

type AgentLaneConversations struct {
	Coordinated *Conversation
	Fast        *Conversation
	Changes     []string
}

// EnsureAgentLaneConversations 返回项目固定的协调/Fast 主 Agent 会话。
//
// 迁移时优先复用项目最近一条协调模式会话作为协调通道，Fast 通道只复用
// 已明确为 Fast 的会话；缺少的通道会创建，不会复制消息或项目数据。
func (db *DB) EnsureAgentLaneConversations(
	ctx context.Context,
	ownerUserID string,
	projectID string,
) (AgentLaneConversations, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		result, err := db.ensureAgentLaneConversationsOnce(ctx, ownerUserID, projectID)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !isAgentLaneRetryableError(err) || attempt == 2 {
			return AgentLaneConversations{}, err
		}
		time.Sleep(time.Duration(attempt+1) * 25 * time.Millisecond)
	}
	return AgentLaneConversations{}, lastErr
}

func (db *DB) ensureAgentLaneConversationsOnce(
	ctx context.Context,
	ownerUserID string,
	projectID string,
) (AgentLaneConversations, error) {
	ownerUserID = strings.TrimSpace(ownerUserID)
	projectID = strings.TrimSpace(projectID)
	if ownerUserID == "" || projectID == "" {
		return AgentLaneConversations{}, fmt.Errorf("主 Agent 会话缺少用户或项目")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return AgentLaneConversations{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var projectName string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT name FROM projects WHERE id = ? AND owner_user_id = ?`,
		projectID,
		ownerUserID,
	).Scan(&projectName); err != nil {
		return AgentLaneConversations{}, err
	}
	projectName = strings.TrimSpace(projectName)
	if projectName == "" {
		projectName = "项目"
	}

	coordinatedID, coordinatedChange, err := findOrMigrateAgentLaneConversation(
		ctx,
		tx,
		ownerUserID,
		projectID,
		ConversationLaneCoordinated,
		"deep",
		projectName+" · 主 Agent - 协调",
	)
	if err != nil {
		return AgentLaneConversations{}, err
	}
	fastID, fastChange, err := findOrMigrateAgentLaneConversation(
		ctx,
		tx,
		ownerUserID,
		projectID,
		ConversationLaneFast,
		"fast",
		projectName+" · 主 Agent - 不协调",
	)
	if err != nil {
		return AgentLaneConversations{}, err
	}
	if err := tx.Commit(); err != nil {
		return AgentLaneConversations{}, err
	}
	coordinated, err := db.GetConversation(ctx, coordinatedID, ownerUserID)
	if err != nil {
		return AgentLaneConversations{}, err
	}
	fast, err := db.GetConversation(ctx, fastID, ownerUserID)
	if err != nil {
		return AgentLaneConversations{}, err
	}
	return AgentLaneConversations{
		Coordinated: coordinated,
		Fast:        fast,
		Changes:     []string{coordinatedChange, fastChange},
	}, nil
}

func findOrMigrateAgentLaneConversation(
	ctx context.Context,
	tx *sql.Tx,
	ownerUserID string,
	projectID string,
	lane string,
	mode string,
	title string,
) (string, string, error) {
	var conversationID string
	err := tx.QueryRowContext(
		ctx,
		`SELECT id FROM conversations
		 WHERE owner_user_id = ? AND project_id = ? AND execution_lane = ?
		   AND parent_conversation_id = ''
		 LIMIT 1`,
		ownerUserID,
		projectID,
		lane,
	).Scan(&conversationID)
	if err == nil {
		if err := ensureAgentLaneSettings(ctx, tx, conversationID, mode); err != nil {
			return "", "", err
		}
		return conversationID, lane + "=reused:" + conversationID, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", "", err
	}

	var previousTitle string
	var previousMode string
	if lane == ConversationLaneCoordinated {
		err = tx.QueryRowContext(
			ctx,
			`SELECT c.id, c.title, COALESCE(s.agent_mode, '')
			 FROM conversations c
			 LEFT JOIN conversation_agent_settings s ON s.conversation_id = c.id
			 WHERE c.owner_user_id = ? AND c.project_id = ?
			   AND c.parent_conversation_id = '' AND c.execution_lane = ''
			   AND c.kind = 'normal'
			   AND (
			     s.agent_mode IS NULL OR s.agent_mode IN ('', 'auto', 'deep') OR
			     EXISTS (
			       SELECT 1 FROM agent_orchestrations o
			       WHERE o.conversation_id = c.id AND o.status IN ('running', 'paused')
			     )
			   )
			 ORDER BY CASE
			            WHEN EXISTS (
			              SELECT 1 FROM agent_orchestrations o
			              WHERE o.conversation_id = c.id AND o.status IN ('running', 'paused')
			            ) THEN 0
			            WHEN s.agent_mode = 'deep' THEN 1
			            ELSE 2
			          END,
			          c.updated_at DESC, c.rowid DESC
			 LIMIT 1`,
			ownerUserID,
			projectID,
		).Scan(&conversationID, &previousTitle, &previousMode)
	} else {
		err = tx.QueryRowContext(
			ctx,
			`SELECT c.id, c.title, COALESCE(s.agent_mode, '')
			 FROM conversations c
			 JOIN conversation_agent_settings s ON s.conversation_id = c.id
			 WHERE c.owner_user_id = ? AND c.project_id = ?
			   AND c.parent_conversation_id = '' AND c.execution_lane = ''
			   AND c.kind = 'normal' AND s.agent_mode = ?
			   AND NOT EXISTS (
			     SELECT 1 FROM agent_orchestrations o
			     WHERE o.conversation_id = c.id AND o.status IN ('running', 'paused')
			   )
			 ORDER BY c.updated_at DESC, c.rowid DESC
			 LIMIT 1`,
			ownerUserID,
			projectID,
			mode,
		).Scan(&conversationID, &previousTitle, &previousMode)
	}
	if err == nil {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE conversations
			 SET execution_lane = ?, updated_at = ?
			 WHERE id = ? AND owner_user_id = ?`,
			lane,
			time.Now().UTC().Unix(),
			conversationID,
			ownerUserID,
		); err != nil {
			return "", "", err
		}
		if err := ensureAgentLaneSettings(ctx, tx, conversationID, mode); err != nil {
			return "", "", err
		}
		return conversationID, fmt.Sprintf(
			"%s=migrated:%s:title=%q:mode=%q",
			lane,
			conversationID,
			previousTitle,
			previousMode,
		), nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", "", err
	}

	now := time.Now().UTC()
	conversationID = newID()
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO conversations (
			id, owner_user_id, project_id, asset_id, execution_lane, kind,
			parent_conversation_id, batch_id, agent_role_id, title, created_at, updated_at
		) VALUES (?, ?, ?, '', ?, 'normal', '', '', '', ?, ?, ?)`,
		conversationID,
		ownerUserID,
		projectID,
		lane,
		title,
		now.Unix(),
		now.Unix(),
	); err != nil {
		return "", "", err
	}
	if err := ensureAgentLaneSettings(ctx, tx, conversationID, mode); err != nil {
		return "", "", err
	}
	return conversationID, lane + "=created:" + conversationID, nil
}

func ensureAgentLaneSettings(
	ctx context.Context,
	tx *sql.Tx,
	conversationID string,
	mode string,
) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO conversation_agent_settings (
			conversation_id, auto_continue, agent_mode, updated_at
		) VALUES (?, 1, ?, ?)
		ON CONFLICT(conversation_id) DO UPDATE SET
			agent_mode = excluded.agent_mode,
			updated_at = excluded.updated_at`,
		conversationID,
		mode,
		time.Now().UTC().Unix(),
	)
	return err
}

func isAgentLaneRetryableError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint failed") ||
		strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database table is locked")
}
