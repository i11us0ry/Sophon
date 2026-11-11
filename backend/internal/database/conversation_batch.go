package database

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type ConversationBatch struct {
	ID                     string    `json:"id"`
	OwnerUserID            string    `json:"ownerUserId"`
	ProjectID              string    `json:"projectId"`
	ParentConversationID   string    `json:"parentConversationId"`
	Title                  string    `json:"title"`
	Instruction            string    `json:"instruction"`
	SourceText             string    `json:"-"`
	Total                  int       `json:"total"`
	Status                 string    `json:"status"`
	MaxConcurrency         int       `json:"maxConcurrency"`
	MaxAttemptsPerTask     int       `json:"maxAttemptsPerTask"`
	MaxSegmentsPerTask     int       `json:"maxSegmentsPerTask"`
	MaxToolCallsPerTask    int       `json:"maxToolCallsPerTask"`
	CampaignMode           string    `json:"campaignMode"`
	ResumeOnStart          bool      `json:"resumeOnStart"`
	CampaignRound          int       `json:"campaignRound"`
	MaxRounds              int       `json:"maxRounds"`
	CampaignToolCallBudget int       `json:"campaignToolCallBudget"`
	CampaignToolCalls      int       `json:"campaignToolCalls"`
	StoppedAt              time.Time `json:"stoppedAt,omitempty"`
	CreatedAt              time.Time `json:"createdAt"`
	UpdatedAt              time.Time `json:"updatedAt"`
	StartedAt              time.Time `json:"startedAt,omitempty"`
	FinishedAt             time.Time `json:"finishedAt,omitempty"`
}

type ConversationBatchItem struct {
	Asset        Asset
	Conversation Conversation
}

type CampaignResumeItem struct {
	ID          string
	OwnerUserID string
}

// CreateConversationBatch 在一个事务中创建批次、资产、父对话和子对话。
func (db *DB) CreateConversationBatch(
	ctx context.Context,
	batch ConversationBatch,
	parent Conversation,
	items []ConversationBatchItem,
	parentMessage string,
) (int, int, error) {
	if len(items) == 0 {
		return 0, 0, sql.ErrNoRows
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()

	now := batch.CreatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	batch.CreatedAt = now
	batch.UpdatedAt = now
	batch.Status = strings.TrimSpace(batch.Status)
	if batch.Status == "" {
		batch.Status = "draft"
	}
	if batch.MaxConcurrency <= 0 {
		batch.MaxConcurrency = 3
	}
	if batch.MaxConcurrency > 20 {
		batch.MaxConcurrency = 20
	}
	if batch.MaxAttemptsPerTask <= 0 {
		batch.MaxAttemptsPerTask = 2
	}
	if batch.MaxSegmentsPerTask <= 0 {
		batch.MaxSegmentsPerTask = 6
	}
	if batch.MaxToolCallsPerTask <= 0 {
		batch.MaxToolCallsPerTask = 60
	}
	batch.CampaignMode = strings.ToLower(strings.TrimSpace(batch.CampaignMode))
	if batch.CampaignMode != "continuous" {
		batch.CampaignMode = "single"
	}
	batch.ResumeOnStart = batch.CampaignMode == CampaignModeContinuous
	if batch.MaxRounds <= 0 {
		batch.MaxRounds = 3
	}
	if batch.MaxRounds > 20 {
		batch.MaxRounds = 20
	}
	if batch.CampaignToolCallBudget <= 0 {
		batch.CampaignToolCallBudget = 600
	}
	if batch.CampaignToolCallBudget > 100000 {
		batch.CampaignToolCallBudget = 100000
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO conversation_batches (
			id, owner_user_id, project_id, parent_conversation_id, title,
			instruction, source_text, total, status, max_concurrency,
			max_attempts_per_task, max_segments_per_task, max_tool_calls_per_task,
			campaign_mode, resume_on_start, campaign_round, max_rounds, campaign_tool_call_budget,
			campaign_tool_calls, stopped_at, created_at, updated_at, started_at, finished_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 0, 0, ?, ?, 0, 0)`,
		batch.ID,
		batch.OwnerUserID,
		batch.ProjectID,
		batch.ParentConversationID,
		batch.Title,
		batch.Instruction,
		batch.SourceText,
		batch.Total,
		batch.Status,
		batch.MaxConcurrency,
		batch.MaxAttemptsPerTask,
		batch.MaxSegmentsPerTask,
		batch.MaxToolCallsPerTask,
		batch.CampaignMode,
		batch.ResumeOnStart,
		batch.MaxRounds,
		batch.CampaignToolCallBudget,
		batch.CreatedAt.Unix(),
		batch.UpdatedAt.Unix(),
	); err != nil {
		return 0, 0, err
	}

	parent.Kind = "batch_parent"
	parent.BatchID = batch.ID
	parent.ParentConversationID = ""
	if err := insertConversationTx(ctx, tx, parent); err != nil {
		return 0, 0, err
	}

	groups := make(map[string]campaignGroupRecord)
	for _, item := range items {
		group := campaignGroupForAsset(item.Asset)
		existing := groups[group.Key]
		if existing.ID == "" {
			existing = campaignGroupRecord{
				ID:        newID(),
				Key:       group.Key,
				Label:     group.Label,
				CreatedAt: now,
			}
		}
		existing.TotalAssets++
		groups[group.Key] = existing
	}
	for _, group := range groups {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO campaign_groups (
				id, campaign_id, project_id, owner_user_id, group_key, label,
				status, total_assets, completed_assets, failed_assets, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, 0, 0, ?, ?)`,
			group.ID,
			batch.ID,
			batch.ProjectID,
			batch.OwnerUserID,
			group.Key,
			group.Label,
			group.TotalAssets,
			now.Unix(),
			now.Unix(),
		); err != nil {
			return 0, 0, err
		}
	}

	createdAssets := 0
	reusedAssets := 0
	for index := range items {
		item := &items[index]
		asset := item.Asset
		var existingID string
		err := tx.QueryRowContext(
			ctx,
			`SELECT id FROM assets
			 WHERE project_id = ? AND owner_user_id = ?
			   AND kind = ? AND LOWER(TRIM(value)) = LOWER(TRIM(?))
			 ORDER BY created_at ASC, id ASC
			 LIMIT 1`,
			asset.ProjectID,
			asset.OwnerUserID,
			asset.Kind,
			asset.Value,
		).Scan(&existingID)
		switch {
		case err == nil:
			item.Conversation.AssetID = existingID
			reusedAssets++
		case err == sql.ErrNoRows:
			if strings.TrimSpace(asset.ID) == "" {
				asset.ID = newID()
			}
			if err := insertAssetTx(ctx, tx, asset); err != nil {
				return 0, 0, err
			}
			item.Conversation.AssetID = asset.ID
			createdAssets++
		default:
			return 0, 0, err
		}
		item.Conversation.Kind = "batch_child"
		item.Conversation.ParentConversationID = parent.ID
		item.Conversation.BatchID = batch.ID
		if err := insertConversationTx(ctx, tx, item.Conversation); err != nil {
			return 0, 0, err
		}
		group := campaignGroupForAsset(asset)
		groupRecord := groups[group.Key]
		endpoint := campaignEndpointForAsset(batch.ID, groupRecord.ID, asset)
		if _, err := tx.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO campaign_endpoints (
				id, campaign_id, group_id, asset_id, project_id, owner_user_id,
				method, url, host, path, fingerprint, status, risk_score,
				created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)`,
			endpoint.ID,
			endpoint.CampaignID,
			endpoint.GroupID,
			item.Conversation.AssetID,
			endpoint.ProjectID,
			endpoint.OwnerUserID,
			endpoint.Method,
			endpoint.URL,
			endpoint.Host,
			endpoint.Path,
			endpoint.Fingerprint,
			asset.RiskScore,
			now.Unix(),
			now.Unix(),
		); err != nil {
			return 0, 0, err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO campaign_tasks (
				id, campaign_id, group_id, asset_id, conversation_id,
				project_id, owner_user_id, kind, parent_task_id, source_type,
				source_ref, intent_json, status, priority,
				attempts, max_attempts, max_segments, max_tool_calls,
				tool_calls, result, error, next_attempt_at, failure_kind,
				started_at, finished_at, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, 'asset_scan', '', '', '', '{}', 'queued', ?, 0, ?, ?, ?, 0, '', '', 0, '', 0, 0, ?, ?)`,
			newID(),
			batch.ID,
			groupRecord.ID,
			item.Conversation.AssetID,
			item.Conversation.ID,
			batch.ProjectID,
			batch.OwnerUserID,
			100-asset.RiskScore,
			batch.MaxAttemptsPerTask,
			batch.MaxSegmentsPerTask,
			batch.MaxToolCallsPerTask,
			now.Unix(),
			now.Unix(),
		); err != nil {
			return 0, 0, err
		}
	}

	if strings.TrimSpace(parentMessage) != "" {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO messages (id, conversation_id, role, content, reasoning_content, created_at)
			 VALUES (?, ?, 'assistant', ?, '', ?)`,
			newID(),
			parent.ID,
			parentMessage,
			now.Unix(),
		); err != nil {
			return 0, 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return createdAssets, reusedAssets, nil
}

func (db *DB) GetConversationBatchByChildConversation(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
) (*ConversationBatch, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT b.id, b.owner_user_id, b.project_id, b.parent_conversation_id,
			b.title, b.instruction, b.source_text, b.total,
			b.campaign_mode, b.campaign_round, b.max_rounds,
			b.campaign_tool_call_budget, b.campaign_tool_calls, b.stopped_at,
			b.created_at, b.updated_at
		 FROM conversation_batches b
		 JOIN conversations c ON c.batch_id = b.id
		 WHERE c.id = ? AND c.owner_user_id = ?`,
		conversationID,
		ownerUserID,
	)
	var item ConversationBatch
	var createdAt, updatedAt, stoppedAt int64
	if err := row.Scan(
		&item.ID,
		&item.OwnerUserID,
		&item.ProjectID,
		&item.ParentConversationID,
		&item.Title,
		&item.Instruction,
		&item.SourceText,
		&item.Total,
		&item.CampaignMode,
		&item.CampaignRound,
		&item.MaxRounds,
		&item.CampaignToolCallBudget,
		&item.CampaignToolCalls,
		&stoppedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	item.StoppedAt = unixTimeOrZero(stoppedAt)
	return &item, nil
}

func (db *DB) SetCampaignResumeOnStart(
	ctx context.Context,
	campaignID string,
	ownerUserID string,
	enabled bool,
) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET resume_on_start = ?, updated_at = ?
		 WHERE id = ? AND owner_user_id = ?`,
		enabled,
		time.Now().UTC().Unix(),
		strings.TrimSpace(campaignID),
		strings.TrimSpace(ownerUserID),
	)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) ListCampaignsForAutoResume(ctx context.Context) ([]CampaignResumeItem, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, owner_user_id
		 FROM conversation_batches
		 WHERE status = ? AND resume_on_start = 1 AND stopped_at = 0
		 ORDER BY updated_at ASC`,
		CampaignStatusPaused,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CampaignResumeItem, 0)
	for rows.Next() {
		var item CampaignResumeItem
		if err := rows.Scan(&item.ID, &item.OwnerUserID); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func insertConversationTx(ctx context.Context, tx *sql.Tx, conversation Conversation) error {
	conversation.Kind = strings.TrimSpace(conversation.Kind)
	if conversation.Kind == "" {
		conversation.Kind = "normal"
	}
	_, err := tx.ExecContext(
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
	return err
}

func insertAssetTx(ctx context.Context, tx *sql.Tx, asset Asset) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO assets (
			id, project_id, owner_user_id, name, kind, value, status,
			criticality, risk_score, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		asset.ID,
		asset.ProjectID,
		asset.OwnerUserID,
		asset.Name,
		asset.Kind,
		asset.Value,
		asset.Status,
		asset.Criticality,
		asset.RiskScore,
		asset.CreatedAt.Unix(),
		asset.UpdatedAt.Unix(),
	)
	return err
}
