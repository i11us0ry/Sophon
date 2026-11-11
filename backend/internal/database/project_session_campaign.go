package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrProjectCampaignActive = errors.New("项目已有未结束的后台会话")
	ErrNoActiveProjectAssets = errors.New("项目没有启用的授权资产")
)

// CreateProjectSessionCampaign creates one visible conversation and one
// internal single-task campaign that uses the project's complete asset scope.
func (db *DB) CreateProjectSessionCampaign(
	ctx context.Context,
	batch ConversationBatch,
	conversation Conversation,
	instruction string,
) error {
	batch.OwnerUserID = strings.TrimSpace(batch.OwnerUserID)
	batch.ProjectID = strings.TrimSpace(batch.ProjectID)
	batch.ID = strings.TrimSpace(batch.ID)
	conversation.ID = strings.TrimSpace(conversation.ID)
	conversation.OwnerUserID = strings.TrimSpace(conversation.OwnerUserID)
	conversation.ProjectID = strings.TrimSpace(conversation.ProjectID)
	instruction = strings.TrimSpace(instruction)
	if batch.ID == "" || batch.ProjectID == "" || batch.OwnerUserID == "" ||
		conversation.ID == "" || conversation.OwnerUserID != batch.OwnerUserID ||
		conversation.ProjectID != batch.ProjectID || instruction == "" {
		return fmt.Errorf("项目会话战役参数不完整")
	}

	now := batch.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	batch.ParentConversationID = conversation.ID
	batch.Instruction = instruction
	batch.Total = 1
	batch.Status = CampaignStatusDraft
	batch.MaxConcurrency = 1
	batch.MaxAttemptsPerTask = 2
	batch.MaxSegmentsPerTask = 0
	batch.MaxToolCallsPerTask = 0
	batch.CampaignMode = CampaignModeSingle
	batch.ResumeOnStart = false
	batch.CampaignRound = 0
	batch.MaxRounds = 1
	batch.CampaignToolCallBudget = 0
	batch.CampaignToolCalls = 0
	batch.StoppedAt = time.Time{}
	batch.CreatedAt = now
	batch.UpdatedAt = now
	batch.StartedAt = time.Time{}
	batch.FinishedAt = time.Time{}

	conversation.Kind = "batch_child"
	conversation.ParentConversationID = ""
	conversation.BatchID = batch.ID
	if conversation.CreatedAt.IsZero() {
		conversation.CreatedAt = now
	}
	conversation.UpdatedAt = now

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	hasUnfinished, err := projectHasUnfinishedCampaignTx(
		ctx,
		tx,
		batch.ProjectID,
		batch.OwnerUserID,
	)
	if err != nil {
		return err
	}
	if hasUnfinished {
		return ErrProjectCampaignActive
	}

	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO conversation_batches (
			id, owner_user_id, project_id, parent_conversation_id, title,
			instruction, source_text, total, status, max_concurrency,
			max_attempts_per_task, max_segments_per_task, max_tool_calls_per_task,
			campaign_mode, resume_on_start, campaign_round, max_rounds,
			campaign_tool_call_budget, campaign_tool_calls, stopped_at,
			created_at, updated_at, started_at, finished_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		batch.ID,
		batch.OwnerUserID,
		batch.ProjectID,
		batch.ParentConversationID,
		batch.Title,
		batch.Instruction,
		"",
		batch.Total,
		batch.Status,
		batch.MaxConcurrency,
		batch.MaxAttemptsPerTask,
		batch.MaxSegmentsPerTask,
		batch.MaxToolCallsPerTask,
		batch.CampaignMode,
		batch.ResumeOnStart,
		batch.CampaignRound,
		batch.MaxRounds,
		batch.CampaignToolCallBudget,
		batch.CampaignToolCalls,
		0,
		batch.CreatedAt.Unix(),
		batch.UpdatedAt.Unix(),
		0,
		0,
	); err != nil {
		return err
	}
	if err := insertConversationTx(ctx, tx, conversation); err != nil {
		return err
	}
	insertedEndpoints, err := insertProjectSessionCampaignEndpointsTx(ctx, tx, batch)
	if err != nil {
		return err
	}
	if insertedEndpoints == 0 {
		return ErrNoActiveProjectAssets
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO messages (id, conversation_id, role, content, reasoning_content, created_at)
		 VALUES (?, ?, 'user', ?, '', ?)`,
		newID(),
		conversation.ID,
		instruction,
		now.Unix(),
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO campaign_tasks (
			id, campaign_id, group_id, asset_id, conversation_id,
			project_id, owner_user_id, kind, parent_task_id, source_type,
			source_ref, intent_json, status, priority, attempts, max_attempts,
			max_segments, max_tool_calls, tool_calls, result, error,
			next_attempt_at, failure_kind, started_at, finished_at, created_at, updated_at
		) VALUES (?, ?, '', '', ?, ?, ?, 'project_scan', '', 'project_session', ?, '{}',
			'queued', 100, 0, 2, 0, 0, 0, '', '', 0, '', 0, 0, ?, ?)`,
		newID(),
		batch.ID,
		conversation.ID,
		batch.ProjectID,
		batch.OwnerUserID,
		batch.ProjectID,
		now.Unix(),
		now.Unix(),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func insertProjectSessionCampaignEndpointsTx(
	ctx context.Context,
	tx *sql.Tx,
	batch ConversationBatch,
) (int, error) {
	rows, err := tx.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, name, kind, value, status,
			criticality, risk_score
		 FROM assets
		 WHERE project_id = ? AND owner_user_id = ?
		   AND LOWER(TRIM(status)) = 'active'
		 ORDER BY created_at ASC, id ASC`,
		batch.ProjectID,
		batch.OwnerUserID,
	)
	if err != nil {
		return 0, err
	}
	assets := make([]Asset, 0)
	for rows.Next() {
		var asset Asset
		if err := rows.Scan(
			&asset.ID,
			&asset.ProjectID,
			&asset.OwnerUserID,
			&asset.Name,
			&asset.Kind,
			&asset.Value,
			&asset.Status,
			&asset.Criticality,
			&asset.RiskScore,
		); err != nil {
			_ = rows.Close()
			return 0, err
		}
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	inserted := 0
	for _, asset := range assets {
		endpoint := campaignEndpointForAsset(batch.ID, "", asset)
		result, err := tx.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO campaign_endpoints (
				id, campaign_id, group_id, asset_id, project_id, owner_user_id,
				method, url, host, path, fingerprint, status, risk_score,
				created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			endpoint.ID,
			endpoint.CampaignID,
			endpoint.GroupID,
			endpoint.AssetID,
			endpoint.ProjectID,
			endpoint.OwnerUserID,
			endpoint.Method,
			endpoint.URL,
			endpoint.Host,
			endpoint.Path,
			endpoint.Fingerprint,
			endpoint.Status,
			endpoint.RiskScore,
			endpoint.CreatedAt.Unix(),
			endpoint.UpdatedAt.Unix(),
		)
		if err != nil {
			return 0, err
		}
		if affected, err := result.RowsAffected(); err == nil {
			inserted += int(affected)
		}
	}
	return inserted, nil
}

// backfillProjectSessionCampaignEndpoints repairs project-wide campaigns that
// were created before campaign authorization assets were persisted.
func (db *DB) backfillProjectSessionCampaignEndpoints(ctx context.Context) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(
		ctx,
		`SELECT DISTINCT b.id, b.project_id, b.owner_user_id
		 FROM conversation_batches b
		 JOIN campaign_tasks t ON t.campaign_id = b.id
		 WHERE t.source_type = 'project_session'
		   AND b.status IN (?, ?, ?)
		   AND b.stopped_at = 0
		   AND NOT EXISTS (
		     SELECT 1 FROM campaign_endpoints e WHERE e.campaign_id = b.id
		   )
		 ORDER BY b.id ASC`,
		CampaignStatusDraft,
		CampaignStatusRunning,
		CampaignStatusPaused,
	)
	if err != nil {
		return err
	}
	batches := make([]ConversationBatch, 0)
	for rows.Next() {
		var batch ConversationBatch
		if err := rows.Scan(&batch.ID, &batch.ProjectID, &batch.OwnerUserID); err != nil {
			_ = rows.Close()
			return err
		}
		batches = append(batches, batch)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, batch := range batches {
		if _, err := insertProjectSessionCampaignEndpointsTx(ctx, tx, batch); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) recoverDraftProjectSessionCampaigns(ctx context.Context) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET status = ?, resume_on_start = 1, updated_at = ?
		 WHERE status = ? AND stopped_at = 0
		   AND EXISTS (
		     SELECT 1 FROM campaign_tasks t
		     WHERE t.campaign_id = conversation_batches.id
		       AND t.source_type = 'project_session'
		   )`,
		CampaignStatusPaused,
		time.Now().UTC().Unix(),
		CampaignStatusDraft,
	)
	return err
}

func projectHasUnfinishedCampaignTx(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	ownerUserID string,
) (bool, error) {
	var exists bool
	err := tx.QueryRowContext(
		ctx,
		`SELECT EXISTS(
			SELECT 1 FROM conversation_batches
			WHERE project_id = ? AND owner_user_id = ?
			  AND status IN (?, ?, ?) AND stopped_at = 0
		)`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		CampaignStatusDraft,
		CampaignStatusRunning,
		CampaignStatusPaused,
	).Scan(&exists)
	return exists, err
}

func (db *DB) ProjectHasUnfinishedCampaign(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) (bool, error) {
	var exists bool
	err := db.QueryRowContext(
		ctx,
		`SELECT EXISTS(
			SELECT 1 FROM conversation_batches
			WHERE project_id = ? AND owner_user_id = ?
			  AND status IN (?, ?, ?) AND stopped_at = 0
		)`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		CampaignStatusDraft,
		CampaignStatusRunning,
		CampaignStatusPaused,
	).Scan(&exists)
	return exists, err
}

func (db *DB) FailProjectSessionCampaign(
	ctx context.Context,
	campaignID string,
	ownerUserID string,
	errorText string,
) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Unix()
	result, err := tx.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET status = ?, finished_at = ?, updated_at = ?
		 WHERE id = ? AND owner_user_id = ?`,
		CampaignStatusFailed,
		now,
		now,
		strings.TrimSpace(campaignID),
		strings.TrimSpace(ownerUserID),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("项目会话战役不存在")
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE campaign_tasks
		 SET status = ?, error = ?, finished_at = ?, updated_at = ?
		 WHERE campaign_id = ? AND owner_user_id = ? AND status = ?`,
		CampaignTaskStatusFailed,
		strings.TrimSpace(errorText),
		now,
		now,
		strings.TrimSpace(campaignID),
		strings.TrimSpace(ownerUserID),
		CampaignTaskStatusQueued,
	); err != nil {
		return err
	}
	return tx.Commit()
}
