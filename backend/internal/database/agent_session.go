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

const (
	AgentRoleMain     = "mainagent"
	AgentRolePlanner  = "planner"
	AgentRoleWorker   = "worker"
	AgentRoleSystem   = "system"
	agentSessionIDMax = 240
)

type AgentSession struct {
	ID              string                 `json:"id"`
	ConversationID  string                 `json:"conversationId"`
	Role            string                 `json:"role"`
	Title           string                 `json:"title"`
	Status          string                 `json:"status"`
	AgentID         string                 `json:"agentId"`
	AgentName       string                 `json:"agentName"`
	HypothesisID    string                 `json:"hypothesisId"`
	ParentSessionID string                 `json:"parentSessionId"`
	ActivityCount   int                    `json:"activityCount"`
	Metadata        map[string]interface{} `json:"metadata"`
	CreatedAt       time.Time              `json:"createdAt"`
	UpdatedAt       time.Time              `json:"updatedAt"`
	LastActivityAt  time.Time              `json:"lastActivityAt"`
}

func AgentSessionID(conversationID, role, agentID, hypothesisID string) string {
	conversationID = sessionIDPart(conversationID)
	role = normalizeAgentSessionRole(role)
	switch role {
	case AgentRoleWorker:
		item := strings.TrimSpace(hypothesisID)
		if item == "" {
			item = strings.TrimSpace(agentID)
		}
		if item == "" {
			item = "unknown"
		}
		return truncateSessionID("worker:" + conversationID + ":" + sessionIDPart(item))
	case AgentRolePlanner:
		return truncateSessionID("planner:" + conversationID)
	case AgentRoleSystem:
		agentID = strings.TrimSpace(agentID)
		if agentID != "" {
			return truncateSessionID("system:" + conversationID + ":" + sessionIDPart(agentID))
		}
		return truncateSessionID("system:" + conversationID)
	default:
		return truncateSessionID("main:" + conversationID)
	}
}

func EnsureCoreAgentSessions(ctx context.Context, db *DB, conversationID string) error {
	if db == nil || strings.TrimSpace(conversationID) == "" {
		return nil
	}
	now := time.Now().UTC()
	for _, item := range []struct {
		role  string
		title string
	}{
		{AgentRoleMain, "主 Agent"},
		{AgentRolePlanner, "规划 Planner"},
		{AgentRoleSystem, "系统事件"},
	} {
		session := AgentSession{
			ID:             AgentSessionID(conversationID, item.role, "", ""),
			ConversationID: conversationID,
			Role:           item.role,
			Title:          item.title,
			Status:         "idle",
			Metadata:       map[string]interface{}{},
			CreatedAt:      now,
			UpdatedAt:      now,
			LastActivityAt: now,
		}
		if err := db.insertAgentSessionIfMissing(ctx, session); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) insertAgentSessionIfMissing(ctx context.Context, session AgentSession) error {
	metadataJSON := "{}"
	if session.Metadata != nil {
		if encoded, err := json.Marshal(session.Metadata); err == nil {
			metadataJSON = string(encoded)
		}
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO agent_sessions (
			id, conversation_id, role, title, status, agent_id, agent_name,
			hypothesis_id, parent_session_id, activity_count, metadata,
			created_at, updated_at, last_activity_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID,
		session.ConversationID,
		session.Role,
		session.Title,
		session.Status,
		session.AgentID,
		session.AgentName,
		session.HypothesisID,
		session.ParentSessionID,
		session.ActivityCount,
		metadataJSON,
		session.CreatedAt.Unix(),
		session.UpdatedAt.Unix(),
		session.LastActivityAt.Unix(),
	)
	return err
}

func (db *DB) ListAgentSessions(ctx context.Context, conversationID string) ([]AgentSession, error) {
	if db == nil {
		return nil, fmt.Errorf("数据库不可用")
	}
	if err := EnsureCoreAgentSessions(ctx, db, conversationID); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, role, title, status, agent_id, agent_name,
			hypothesis_id, parent_session_id, activity_count, metadata, created_at,
			updated_at, last_activity_at
		 FROM agent_sessions
		 WHERE conversation_id = ?
		 ORDER BY CASE role
			WHEN 'mainagent' THEN 0
			WHEN 'planner' THEN 1
			WHEN 'system' THEN 2
			ELSE 3 END,
			last_activity_at DESC, id ASC`,
		conversationID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AgentSession, 0)
	for rows.Next() {
		var item AgentSession
		var metadataJSON string
		var createdAt, updatedAt, lastActivityAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.Role,
			&item.Title,
			&item.Status,
			&item.AgentID,
			&item.AgentName,
			&item.HypothesisID,
			&item.ParentSessionID,
			&item.ActivityCount,
			&metadataJSON,
			&createdAt,
			&updatedAt,
			&lastActivityAt,
		); err != nil {
			return nil, err
		}
		item.Metadata = map[string]interface{}{}
		_ = json.Unmarshal([]byte(metadataJSON), &item.Metadata)
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		item.LastActivityAt = time.Unix(lastActivityAt, 0).UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

// PauseProjectAgentSessions settles all active session projections for a
// project. The orchestrator context cancel stops execution; this update keeps
// the session list from showing stale running/waiting entries.
func (db *DB) PauseProjectAgentSessions(
	ctx context.Context,
	projectID string,
	userID string,
	reason string,
) (int64, error) {
	projectID = strings.TrimSpace(projectID)
	userID = strings.TrimSpace(userID)
	reason = strings.TrimSpace(reason)
	if projectID == "" || userID == "" {
		return 0, fmt.Errorf("项目或用户为空")
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE agent_sessions
		 SET status = 'paused',
		     metadata = json_set(
		         CASE WHEN json_valid(metadata) THEN metadata ELSE '{}' END,
		         '$.statusReason',
		         ?
		     ),
		     updated_at = ?
		 WHERE conversation_id IN (
		     SELECT id FROM conversations WHERE project_id = ? AND owner_user_id = ?
		 )
		   AND role IN ('mainagent', 'planner', 'worker')
		   AND status IN ('running', 'waiting')`,
		reason,
		now.Unix(),
		projectID,
		userID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// PauseRunningAgentSessionsOnStartup settles session rows left over from a
// previous backend process. In-memory Agent goroutines cannot survive a restart.
func (db *DB) PauseRunningAgentSessionsOnStartup(
	ctx context.Context,
	reason string,
) (int64, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "服务重启导致 Agent 会话中断"
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE agent_sessions
		 SET status = 'paused',
		     metadata = json_set(
		         CASE WHEN json_valid(metadata) THEN metadata ELSE '{}' END,
		         '$.statusReason',
		         ?
		     ),
		     updated_at = ?
		 WHERE status IN ('running', 'waiting')`,
		reason,
		now.Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) ListAgentSessionDetailsPage(
	ctx context.Context,
	conversationID string,
	sessionID string,
	limit int,
	before int64,
) ([]ProcessDetail, int, bool, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM process_details
		 WHERE conversation_id = ? AND session_id = ?`,
		conversationID,
		sessionID,
	).Scan(&total); err != nil {
		return nil, 0, false, err
	}
	query := `SELECT rowid, id, conversation_id, COALESCE(message_id, ''), session_id,
		event_type, message, data, created_at
		FROM process_details
		WHERE conversation_id = ? AND session_id = ?`
	args := []interface{}{conversationID, sessionID}
	if before > 0 {
		query += ` AND rowid < ?`
		args = append(args, before)
	}
	query += ` ORDER BY rowid DESC LIMIT ?`
	args = append(args, limit+1)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()
	items := make([]ProcessDetail, 0, limit+1)
	for rows.Next() {
		var item ProcessDetail
		var dataJSON string
		var createdAt int64
		if err := rows.Scan(
			&item.Sequence,
			&item.ID,
			&item.ConversationID,
			&item.MessageID,
			&item.SessionID,
			&item.EventType,
			&item.Message,
			&dataJSON,
			&createdAt,
		); err != nil {
			return nil, 0, false, err
		}
		item.Data = map[string]interface{}{}
		_ = json.Unmarshal([]byte(dataJSON), &item.Data)
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
	return items, total, hasMore, nil
}

func (db *DB) ListAgentSessionDetailsAfter(
	ctx context.Context,
	conversationID string,
	after int64,
	limit int,
) ([]ProcessDetail, int64, error) {
	if after < 0 {
		after = 0
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT rowid, id, conversation_id, COALESCE(message_id, ''), session_id,
			event_type, message, data, created_at
		 FROM process_details
		 WHERE conversation_id = ? AND rowid > ?
		 ORDER BY rowid ASC
		 LIMIT ?`,
		strings.TrimSpace(conversationID),
		after,
		limit,
	)
	if err != nil {
		return nil, after, err
	}
	defer rows.Close()
	items := make([]ProcessDetail, 0, limit)
	cursor := after
	for rows.Next() {
		var item ProcessDetail
		var dataJSON string
		var createdAt int64
		if err := rows.Scan(
			&item.Sequence,
			&item.ID,
			&item.ConversationID,
			&item.MessageID,
			&item.SessionID,
			&item.EventType,
			&item.Message,
			&dataJSON,
			&createdAt,
		); err != nil {
			return nil, after, err
		}
		item.Data = map[string]interface{}{}
		_ = json.Unmarshal([]byte(dataJSON), &item.Data)
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		cursor = item.Sequence
		items = append(items, item)
	}
	return items, cursor, rows.Err()
}

func (db *DB) ensureAgentSessionSchema(ctx context.Context) error {
	if _, err := db.ExecContext(
		ctx,
		`CREATE INDEX IF NOT EXISTS idx_process_details_session
		 ON process_details(conversation_id, session_id, created_at)`,
	); err != nil {
		return err
	}
	var legacyCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM process_details WHERE session_id = ''`,
	).Scan(&legacyCount); err != nil {
		return err
	}
	if legacyCount == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE process_details
		 SET session_id = CASE
			WHEN json_valid(data) AND json_extract(data, '$.agentKind') = 'planner' THEN 'planner:' || conversation_id
			WHEN json_valid(data) AND json_extract(data, '$.agentKind') = 'worker' THEN
				'worker:' || conversation_id || ':' ||
				COALESCE(NULLIF(json_extract(data, '$.hypothesisId'), ''),
					NULLIF(json_extract(data, '$.agentId'), ''), 'unknown')
			WHEN json_valid(data) AND json_extract(data, '$.agentKind') = 'system' THEN 'system:' || conversation_id
			ELSE 'main:' || conversation_id END
		 WHERE session_id = ''`,
	); err != nil {
		return err
	}
	for _, role := range []string{AgentRoleMain, AgentRolePlanner, AgentRoleWorker, AgentRoleSystem} {
		titleExpr := `'Worker'`
		switch role {
		case AgentRoleMain:
			titleExpr = `'主 Agent'`
		case AgentRolePlanner:
			titleExpr = `'规划 Planner'`
		case AgentRoleSystem:
			titleExpr = `'系统事件'`
		case AgentRoleWorker:
			titleExpr = `COALESCE(NULLIF(json_extract(data, '$.workerFocus'), ''),
				NULLIF(json_extract(data, '$.agentName'), ''), 'Worker')`
		}
		query := fmt.Sprintf(
			`INSERT OR IGNORE INTO agent_sessions (
				id, conversation_id, role, title, status, agent_id, agent_name,
				hypothesis_id, parent_session_id, activity_count, metadata,
				created_at, updated_at, last_activity_at
			)
			SELECT session_id, conversation_id, ?, %s, 'idle',
				COALESCE(json_extract(data, '$.agentId'), ''),
				COALESCE(json_extract(data, '$.agentName'), ''),
				COALESCE(json_extract(data, '$.hypothesisId'), ''),
				CASE WHEN ? = 'worker' THEN 'main:' || conversation_id ELSE '' END,
				COUNT(*), '{}', MIN(created_at), MAX(created_at), MAX(created_at)
			FROM process_details
			WHERE json_valid(data) AND CASE
				WHEN json_extract(data, '$.agentKind') = 'planner' THEN 'planner'
				WHEN json_extract(data, '$.agentKind') = 'worker' THEN 'worker'
				WHEN json_extract(data, '$.agentKind') = 'system' THEN 'system'
				ELSE 'mainagent' END = ?
			GROUP BY session_id, conversation_id`,
			titleExpr,
		)
		if _, err := tx.ExecContext(ctx, query, role, role, role); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) upsertAgentSession(ctx context.Context, session AgentSession, increment bool) error {
	return upsertAgentSessionExec(ctx, db, session, increment)
}

type agentSessionExecer interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
}

type agentSessionQueryRower interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func projectActiveForConversation(
	ctx context.Context,
	queryer agentSessionQueryRower,
	conversationID string,
) (bool, error) {
	var active int
	err := queryer.QueryRowContext(
		ctx,
		`SELECT CASE WHEN p.status = 'active' THEN 1 ELSE 0 END
		 FROM conversations c
		 JOIN projects p ON p.id = c.project_id
		 WHERE c.id = ?`,
		strings.TrimSpace(conversationID),
	).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return active != 0, err
}

func upsertAgentSessionExec(
	ctx context.Context,
	execer agentSessionExecer,
	session AgentSession,
	increment bool,
) error {
	metadataJSON := "{}"
	if session.Metadata != nil {
		encoded, err := json.Marshal(session.Metadata)
		if err == nil {
			metadataJSON = string(encoded)
		}
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now().UTC()
	}
	if session.UpdatedAt.IsZero() {
		session.UpdatedAt = session.CreatedAt
	}
	if session.LastActivityAt.IsZero() {
		session.LastActivityAt = session.UpdatedAt
	}
	_, err := execer.ExecContext(
		ctx,
		`INSERT INTO agent_sessions (
			id, conversation_id, role, title, status, agent_id, agent_name,
			hypothesis_id, parent_session_id, activity_count, metadata,
			created_at, updated_at, last_activity_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			title = CASE WHEN excluded.updated_at >= agent_sessions.updated_at
				THEN excluded.title ELSE agent_sessions.title END,
			status = CASE WHEN excluded.updated_at >= agent_sessions.updated_at
				THEN excluded.status ELSE agent_sessions.status END,
			agent_id = CASE WHEN excluded.agent_id != '' THEN excluded.agent_id ELSE agent_sessions.agent_id END,
			agent_name = CASE WHEN excluded.agent_name != '' THEN excluded.agent_name ELSE agent_sessions.agent_name END,
			hypothesis_id = CASE WHEN excluded.hypothesis_id != '' THEN excluded.hypothesis_id ELSE agent_sessions.hypothesis_id END,
			parent_session_id = CASE WHEN excluded.parent_session_id != '' THEN excluded.parent_session_id ELSE agent_sessions.parent_session_id END,
			activity_count = agent_sessions.activity_count + ?,
			metadata = CASE WHEN excluded.updated_at >= agent_sessions.updated_at
				THEN excluded.metadata ELSE agent_sessions.metadata END,
			updated_at = MAX(agent_sessions.updated_at, excluded.updated_at),
			last_activity_at = MAX(agent_sessions.last_activity_at, excluded.last_activity_at)`,
		session.ID,
		session.ConversationID,
		session.Role,
		session.Title,
		session.Status,
		session.AgentID,
		session.AgentName,
		session.HypothesisID,
		session.ParentSessionID,
		session.ActivityCount,
		metadataJSON,
		session.CreatedAt.Unix(),
		session.UpdatedAt.Unix(),
		session.LastActivityAt.Unix(),
		boolInt(increment),
	)
	return err
}

func agentSessionFromDetail(detail ProcessDetail) AgentSession {
	data := detail.Data
	role := normalizeAgentSessionRole(stringData(data, "agentKind"))
	agentID := strings.TrimSpace(stringData(data, "agentId"))
	hypothesisID := strings.TrimSpace(stringData(data, "hypothesisId"))
	agentName := strings.TrimSpace(stringData(data, "agentName"))
	workerFocus := strings.TrimSpace(stringData(data, "workerFocus"))
	title := "主 Agent"
	switch role {
	case AgentRolePlanner:
		title = "规划 Planner"
	case AgentRoleSystem:
		title = firstNonEmpty(agentName, "系统事件")
	case AgentRoleWorker:
		title = firstNonEmpty(workerFocus, agentName, "Worker")
	}
	status := normalizeAgentSessionStatus(stringData(data, "status"))
	switch detail.EventType {
	case "subagent.started":
		status = "running"
	case "subagent.completed":
		status = "completed"
	case "subagent.failed":
		status = "failed"
	case "tool_call", "tool_result", "reasoning", "thinking":
		if status == "" {
			status = "running"
		}
	case "finalization", "response":
		if status == "" {
			status = "completed"
		}
	}
	if status == "" {
		status = "idle"
	}
	parent := ""
	if role != AgentRoleMain {
		parent = AgentSessionID(detail.ConversationID, AgentRoleMain, "", "")
	}
	return AgentSession{
		ID:              AgentSessionID(detail.ConversationID, role, agentID, hypothesisID),
		ConversationID:  detail.ConversationID,
		Role:            role,
		Title:           title,
		Status:          status,
		AgentID:         agentID,
		AgentName:       agentName,
		HypothesisID:    hypothesisID,
		ParentSessionID: parent,
		ActivityCount:   1,
		Metadata:        map[string]interface{}{},
		CreatedAt:       detail.CreatedAt,
		UpdatedAt:       detail.CreatedAt,
		LastActivityAt:  detail.CreatedAt,
	}
}

func normalizeAgentSessionRole(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case AgentRolePlanner:
		return AgentRolePlanner
	case AgentRoleWorker, "subagent":
		return AgentRoleWorker
	case AgentRoleSystem:
		return AgentRoleSystem
	default:
		return AgentRoleMain
	}
}

func normalizeAgentSessionStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "idle", "running", "waiting", "completed", "failed", "paused", "stopped", "blocked":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func stringData(data map[string]interface{}, key string) string {
	if data == nil {
		return ""
	}
	value, _ := data[key].(string)
	return value
}

func sessionIDPart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var builder strings.Builder
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z',
			char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9',
			char == '-', char == '_', char == '.':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
	}
	return builder.String()
}

func truncateSessionID(value string) string {
	if len(value) <= agentSessionIDMax {
		return value
	}
	return value[:agentSessionIDMax]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
