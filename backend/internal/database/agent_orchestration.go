package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	AgentOrchestrationRunning   = "running"
	AgentOrchestrationPaused    = "paused"
	AgentOrchestrationCompleted = "completed"
	AgentOrchestrationFailed    = "failed"
	AgentOrchestrationStopped   = "stopped"
)

type AgentOrchestration struct {
	ConversationID string    `json:"conversationId"`
	ProjectID      string    `json:"projectId"`
	OwnerUserID    string    `json:"ownerUserId"`
	Status         string    `json:"status"`
	PlanJSON       string    `json:"planJson"`
	Phase          string    `json:"phase"`
	AgentMode      string    `json:"agentMode"`
	RunID          string    `json:"runId"`
	MessageID      string    `json:"messageId"`
	CampaignID     string    `json:"campaignId"`
	CampaignTaskID string    `json:"campaignTaskId"`
	Feedback       []string  `json:"feedback"`
	LastError      string    `json:"lastError"`
	StartedAt      time.Time `json:"startedAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func NormalizeAgentOrchestrationStatus(value string) (string, bool) {
	switch status := strings.ToLower(strings.TrimSpace(value)); status {
	case AgentOrchestrationRunning,
		AgentOrchestrationPaused,
		AgentOrchestrationCompleted,
		AgentOrchestrationFailed,
		AgentOrchestrationStopped:
		return status, true
	default:
		return "", false
	}
}

func (db *DB) UpsertAgentOrchestration(
	ctx context.Context,
	item AgentOrchestration,
) error {
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.OwnerUserID = strings.TrimSpace(item.OwnerUserID)
	if item.ConversationID == "" || item.ProjectID == "" || item.OwnerUserID == "" {
		return fmt.Errorf("编排会话、项目和用户不能为空")
	}
	status, ok := NormalizeAgentOrchestrationStatus(item.Status)
	if !ok {
		return fmt.Errorf("编排状态不合法")
	}
	if strings.TrimSpace(item.PlanJSON) == "" {
		item.PlanJSON = "{}"
	}
	if item.StartedAt.IsZero() {
		item.StartedAt = time.Now().UTC()
	}
	if item.UpdatedAt.IsZero() {
		item.UpdatedAt = item.StartedAt
	}
	feedbackJSON, err := json.Marshal(nonEmptyStrings(item.Feedback))
	if err != nil {
		return fmt.Errorf("编码编排纠偏失败: %w", err)
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO agent_orchestrations (
			conversation_id, project_id, owner_user_id, status, plan_json,
			phase, agent_mode, run_id, message_id, campaign_id, campaign_task_id, feedback_json,
			last_error, started_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(conversation_id) DO UPDATE SET
			project_id = excluded.project_id,
			owner_user_id = excluded.owner_user_id,
			status = excluded.status,
			plan_json = excluded.plan_json,
			phase = excluded.phase,
			agent_mode = excluded.agent_mode,
			run_id = excluded.run_id,
			message_id = excluded.message_id,
			campaign_id = excluded.campaign_id,
			campaign_task_id = excluded.campaign_task_id,
			feedback_json = excluded.feedback_json,
			last_error = excluded.last_error,
			started_at = excluded.started_at,
			updated_at = excluded.updated_at`,
		item.ConversationID,
		item.ProjectID,
		item.OwnerUserID,
		status,
		item.PlanJSON,
		strings.TrimSpace(item.Phase),
		strings.TrimSpace(item.AgentMode),
		strings.TrimSpace(item.RunID),
		strings.TrimSpace(item.MessageID),
		strings.TrimSpace(item.CampaignID),
		strings.TrimSpace(item.CampaignTaskID),
		string(feedbackJSON),
		strings.TrimSpace(item.LastError),
		item.StartedAt.Unix(),
		item.UpdatedAt.Unix(),
	)
	return err
}

func (db *DB) UpdateAgentOrchestrationState(
	ctx context.Context,
	conversationID string,
	status string,
	lastError string,
	feedback []string,
) error {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return fmt.Errorf("编排会话不能为空")
	}
	normalized, ok := NormalizeAgentOrchestrationStatus(status)
	if !ok {
		return fmt.Errorf("编排状态不合法")
	}
	feedbackJSON, err := json.Marshal(nonEmptyStrings(feedback))
	if err != nil {
		return fmt.Errorf("编码编排纠偏失败: %w", err)
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE agent_orchestrations
		 SET status = ?, last_error = ?, feedback_json = ?, updated_at = ?
		 WHERE conversation_id = ?`,
		normalized,
		strings.TrimSpace(lastError),
		string(feedbackJSON),
		time.Now().UTC().Unix(),
		conversationID,
	)
	if err != nil {
		return err
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr == nil && affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) ListRecoverableAgentOrchestrations(
	ctx context.Context,
) ([]AgentOrchestration, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT conversation_id, project_id, owner_user_id, status, plan_json,
			phase, agent_mode, run_id, message_id, campaign_id, campaign_task_id, feedback_json,
			last_error, started_at, updated_at
		 FROM agent_orchestrations
		 WHERE status IN (?, ?)
		 ORDER BY updated_at DESC`,
		AgentOrchestrationRunning,
		AgentOrchestrationPaused,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AgentOrchestration, 0)
	for rows.Next() {
		var item AgentOrchestration
		var feedbackJSON string
		var startedAt, updatedAt int64
		if err := rows.Scan(
			&item.ConversationID,
			&item.ProjectID,
			&item.OwnerUserID,
			&item.Status,
			&item.PlanJSON,
			&item.Phase,
			&item.AgentMode,
			&item.RunID,
			&item.MessageID,
			&item.CampaignID,
			&item.CampaignTaskID,
			&feedbackJSON,
			&item.LastError,
			&startedAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(feedbackJSON), &item.Feedback)
		item.Feedback = nonEmptyStrings(item.Feedback)
		item.StartedAt = time.Unix(startedAt, 0).UTC()
		item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

func nonEmptyStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}
