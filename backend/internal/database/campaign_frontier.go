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
	CampaignFrontierStatusPending   = "pending"
	CampaignFrontierStatusRunning   = "running"
	CampaignFrontierStatusCompleted = "completed"
	CampaignFrontierStatusFailed    = "failed"

	CampaignVerificationStatusPending   = "pending"
	CampaignVerificationStatusRunning   = "running"
	CampaignVerificationStatusCompleted = "completed"
	CampaignVerificationStatusFailed    = "failed"
)

type CampaignFrontierItem struct {
	ID            string    `json:"id"`
	CampaignID    string    `json:"campaignId"`
	GroupID       string    `json:"groupId"`
	AssetID       string    `json:"assetId"`
	TaskID        string    `json:"taskId"`
	Kind          string    `json:"kind"`
	Priority      int       `json:"priority"`
	ExpectedValue int       `json:"expectedValue"`
	EstimatedCost int       `json:"estimatedCost"`
	ROI           int       `json:"roi"`
	Reason        string    `json:"reason"`
	Status        string    `json:"status"`
	DedupeKey     string    `json:"dedupeKey"`
	SourceType    string    `json:"sourceType"`
	SourceRef     string    `json:"sourceRef"`
	IntentJSON    string    `json:"intentJson"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

type CampaignLink struct {
	ID           string    `json:"id"`
	CampaignID   string    `json:"campaignId"`
	ProjectID    string    `json:"projectId"`
	SrcAssetID   string    `json:"srcAssetId"`
	DstAssetID   string    `json:"dstAssetId"`
	Kind         string    `json:"kind"`
	Summary      string    `json:"summary"`
	Confidence   int       `json:"confidence"`
	SrcFactID    string    `json:"srcFactId"`
	SrcFindingID string    `json:"srcFindingId"`
	EvidenceRefs []string  `json:"evidenceRefs"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type CampaignVerification struct {
	ID           string    `json:"id"`
	CampaignID   string    `json:"campaignId"`
	FindingID    string    `json:"findingId"`
	TaskID       string    `json:"taskId"`
	Status       string    `json:"status"`
	Attempts     int       `json:"attempts"`
	MaxAttempts  int       `json:"maxAttempts"`
	Result       string    `json:"result"`
	EvidenceRefs []string  `json:"evidenceRefs"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type CampaignTaskLimits struct {
	MaxAttempts  int
	MaxSegments  int
	MaxToolCalls int
}

func (db *DB) EnqueueCampaignFrontier(
	ctx context.Context,
	item CampaignFrontierItem,
	limits CampaignTaskLimits,
) (*CampaignFrontierItem, error) {
	item.CampaignID = strings.TrimSpace(item.CampaignID)
	item.AssetID = strings.TrimSpace(item.AssetID)
	item.Kind = strings.TrimSpace(item.Kind)
	item.DedupeKey = strings.TrimSpace(item.DedupeKey)
	if item.CampaignID == "" || item.AssetID == "" || item.Kind == "" {
		return nil, fmt.Errorf("campaign、asset 和 kind 不能为空")
	}
	if item.DedupeKey == "" {
		item.DedupeKey = item.Kind + ":" + item.AssetID + ":" + item.SourceRef
	}
	if item.Priority <= 0 {
		item.Priority = 50
	}
	if item.Priority > 100 {
		item.Priority = 100
	}
	if item.IntentJSON == "" {
		item.IntentJSON = "{}"
	}
	now := time.Now().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var campaignProject, ownerUserID, conversationID, groupID string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT b.project_id, b.owner_user_id,
			COALESCE((
			 SELECT c.id FROM conversations c
			 WHERE c.batch_id = b.id AND c.asset_id = ?
			 ORDER BY c.created_at ASC LIMIT 1
			), ''),
			COALESCE((
			 SELECT g.id FROM campaign_groups g
			 WHERE g.campaign_id = b.id
			   AND EXISTS (
			   	SELECT 1 FROM campaign_endpoints e
			   	WHERE e.campaign_id = b.id AND e.group_id = g.id AND e.asset_id = ?
			   )
			 LIMIT 1
			), '')
		 FROM conversation_batches b WHERE b.id = ?`,
		item.AssetID,
		item.AssetID,
		item.CampaignID,
	).Scan(&campaignProject, &ownerUserID, &conversationID, &groupID); err != nil {
		return nil, err
	}
	if conversationID == "" {
		return nil, fmt.Errorf("资产没有关联的 Campaign 对话")
	}
	if item.GroupID == "" {
		item.GroupID = groupID
	}
	if limits.MaxAttempts <= 0 {
		limits.MaxAttempts = 2
	}
	if limits.MaxSegments <= 0 {
		limits.MaxSegments = 6
	}
	if limits.MaxToolCalls <= 0 {
		limits.MaxToolCalls = 60
	}
	taskID := newID()
	if _, err := tx.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO campaign_tasks (
			id, campaign_id, group_id, asset_id, conversation_id,
				project_id, owner_user_id, kind, parent_task_id, source_type,
				source_ref, intent_json, status, priority, attempts,
				max_attempts, max_segments, max_tool_calls, tool_calls,
				result, error, next_attempt_at, failure_kind,
				started_at, finished_at, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, 'queued', ?, 0, ?, ?, ?, 0, '', '', 0, '', 0, 0, ?, ?)`,
		taskID,
		item.CampaignID,
		item.GroupID,
		item.AssetID,
		conversationID,
		campaignProject,
		ownerUserID,
		item.Kind,
		item.SourceType,
		item.SourceRef,
		item.IntentJSON,
		item.Priority,
		limits.MaxAttempts,
		limits.MaxSegments,
		limits.MaxToolCalls,
		now.Unix(),
		now.Unix(),
	); err != nil {
		return nil, err
	}
	if err := tx.QueryRowContext(
		ctx,
		`SELECT id FROM campaign_tasks
		 WHERE campaign_id = ? AND asset_id = ? AND kind = ?
		 LIMIT 1`,
		item.CampaignID,
		item.AssetID,
		item.Kind,
	).Scan(&taskID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO campaign_frontier (
			id, campaign_id, group_id, asset_id, task_id, kind, priority,
			reason, status, dedupe_key, source_type, source_ref, intent_json,
			expected_value, estimated_cost, roi, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(campaign_id, dedupe_key) DO UPDATE SET
			task_id = excluded.task_id,
			priority = excluded.priority,
			expected_value = excluded.expected_value,
			estimated_cost = excluded.estimated_cost,
			roi = excluded.roi,
			reason = excluded.reason,
			status = CASE
				WHEN campaign_frontier.status = 'completed' THEN campaign_frontier.status
				ELSE 'pending'
			END,
			source_type = excluded.source_type,
			source_ref = excluded.source_ref,
			intent_json = excluded.intent_json,
			updated_at = excluded.updated_at`,
		newID(),
		item.CampaignID,
		item.GroupID,
		item.AssetID,
		taskID,
		item.Kind,
		item.Priority,
		item.Reason,
		item.DedupeKey,
		item.SourceType,
		item.SourceRef,
		item.IntentJSON,
		frontierExpectedValue(item.Kind, item.Priority),
		frontierEstimatedCost(limits),
		frontierROI(
			frontierExpectedValue(item.Kind, item.Priority),
			frontierEstimatedCost(limits),
		),
		now.Unix(),
		now.Unix(),
	); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.GetCampaignFrontierByDedupe(ctx, item.CampaignID, item.DedupeKey)
}

func (db *DB) GetCampaignFrontierByDedupe(
	ctx context.Context,
	campaignID string,
	dedupeKey string,
) (*CampaignFrontierItem, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, campaign_id, group_id, asset_id, task_id, kind, priority,
			reason, status, dedupe_key, source_type, source_ref, intent_json,
			expected_value, estimated_cost, roi, created_at, updated_at
		 FROM campaign_frontier
		 WHERE campaign_id = ? AND dedupe_key = ?`,
		campaignID,
		dedupeKey,
	)
	var item CampaignFrontierItem
	var createdAt, updatedAt int64
	if err := row.Scan(
		&item.ID,
		&item.CampaignID,
		&item.GroupID,
		&item.AssetID,
		&item.TaskID,
		&item.Kind,
		&item.Priority,
		&item.Reason,
		&item.Status,
		&item.DedupeKey,
		&item.SourceType,
		&item.SourceRef,
		&item.IntentJSON,
		&item.ExpectedValue,
		&item.EstimatedCost,
		&item.ROI,
		&createdAt,
		&updatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return &item, nil
}

func (db *DB) ListCampaignFrontier(
	ctx context.Context,
	campaignID string,
	limit int,
) ([]CampaignFrontierItem, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, group_id, asset_id, task_id, kind, priority,
			reason, status, dedupe_key, source_type, source_ref, intent_json,
			expected_value, estimated_cost, roi, created_at, updated_at
		 FROM campaign_frontier
		 WHERE campaign_id = ?
			ORDER BY
			CASE status WHEN 'running' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END,
			roi DESC, priority DESC, updated_at DESC
		 LIMIT ?`,
		campaignID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CampaignFrontierItem, 0)
	for rows.Next() {
		var item CampaignFrontierItem
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.CampaignID,
			&item.GroupID,
			&item.AssetID,
			&item.TaskID,
			&item.Kind,
			&item.Priority,
			&item.Reason,
			&item.Status,
			&item.DedupeKey,
			&item.SourceType,
			&item.SourceRef,
			&item.IntentJSON,
			&item.ExpectedValue,
			&item.EstimatedCost,
			&item.ROI,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) RecomputeCampaignPriorities(
	ctx context.Context,
	campaignID string,
) error {
	_, err := db.ExecContext(
		ctx,
		`UPDATE campaign_tasks
		 SET priority = MAX(
		 	0,
		 	COALESCE((
		 		SELECT f.priority FROM campaign_frontier f
		 		WHERE f.task_id = campaign_tasks.id
		 		  AND f.status IN ('pending','running')
		 	), campaign_tasks.priority) - campaign_tasks.attempts * 3
		 ),
		 updated_at = ?
		 WHERE campaign_id = ?`,
		time.Now().UTC().Unix(),
		campaignID,
	)
	return err
}

func (db *DB) UpsertCampaignVerification(
	ctx context.Context,
	item CampaignVerification,
) (*CampaignVerification, error) {
	item.CampaignID = strings.TrimSpace(item.CampaignID)
	item.FindingID = strings.TrimSpace(item.FindingID)
	if item.CampaignID == "" || item.FindingID == "" {
		return nil, fmt.Errorf("campaign 和 finding 不能为空")
	}
	if item.Status == "" {
		item.Status = CampaignVerificationStatusPending
	}
	if item.MaxAttempts <= 0 {
		item.MaxAttempts = 2
	}
	refs, err := encodeEvidenceRefs(item.EvidenceRefs)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if item.ID == "" {
		item.ID = newID()
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO campaign_verifications (
			id, campaign_id, finding_id, task_id, status, attempts,
			max_attempts, result, evidence_refs, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(campaign_id, finding_id) DO UPDATE SET
			task_id = CASE WHEN excluded.task_id = '' THEN campaign_verifications.task_id ELSE excluded.task_id END,
			status = excluded.status,
			attempts = campaign_verifications.attempts + CASE WHEN excluded.status = 'running' THEN 1 ELSE 0 END,
			result = CASE WHEN excluded.result = '' THEN campaign_verifications.result ELSE excluded.result END,
			evidence_refs = CASE WHEN excluded.evidence_refs = '[]' THEN campaign_verifications.evidence_refs ELSE excluded.evidence_refs END,
			updated_at = excluded.updated_at`,
		item.ID,
		item.CampaignID,
		item.FindingID,
		item.TaskID,
		item.Status,
		item.Attempts,
		item.MaxAttempts,
		item.Result,
		refs,
		now.Unix(),
		now.Unix(),
	)
	if err != nil {
		return nil, err
	}
	return db.GetCampaignVerification(ctx, item.CampaignID, item.FindingID)
}

func (db *DB) GetCampaignVerification(
	ctx context.Context,
	campaignID string,
	findingID string,
) (*CampaignVerification, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, campaign_id, finding_id, task_id, status, attempts,
			max_attempts, result, evidence_refs, created_at, updated_at
		 FROM campaign_verifications
		 WHERE campaign_id = ? AND finding_id = ?`,
		campaignID,
		findingID,
	)
	var item CampaignVerification
	var refs string
	var createdAt, updatedAt int64
	if err := row.Scan(
		&item.ID,
		&item.CampaignID,
		&item.FindingID,
		&item.TaskID,
		&item.Status,
		&item.Attempts,
		&item.MaxAttempts,
		&item.Result,
		&refs,
		&createdAt,
		&updatedAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	item.EvidenceRefs = decodeEvidenceRefs(refs)
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return &item, nil
}

func (db *DB) ListCampaignVerifications(
	ctx context.Context,
	campaignID string,
	status string,
	limit int,
) ([]CampaignVerification, error) {
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	where := `campaign_id = ?`
	args := []interface{}{campaignID}
	if value := strings.TrimSpace(status); value != "" {
		where += ` AND status = ?`
		args = append(args, value)
	}
	args = append(args, limit)
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, finding_id, task_id, status, attempts,
			max_attempts, result, evidence_refs, created_at, updated_at
		 FROM campaign_verifications
		 WHERE `+where+`
		 ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'running' THEN 1 ELSE 2 END,
			updated_at DESC
		 LIMIT ?`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CampaignVerification, 0)
	for rows.Next() {
		var item CampaignVerification
		var refs string
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.CampaignID,
			&item.FindingID,
			&item.TaskID,
			&item.Status,
			&item.Attempts,
			&item.MaxAttempts,
			&item.Result,
			&refs,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.EvidenceRefs = decodeEvidenceRefs(refs)
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) CreateCampaignLink(
	ctx context.Context,
	item CampaignLink,
) (*CampaignLink, error) {
	item.CampaignID = strings.TrimSpace(item.CampaignID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.SrcAssetID = strings.TrimSpace(item.SrcAssetID)
	item.DstAssetID = strings.TrimSpace(item.DstAssetID)
	item.Kind = strings.TrimSpace(item.Kind)
	if item.CampaignID == "" || item.SrcAssetID == "" || item.DstAssetID == "" || item.Kind == "" {
		return nil, fmt.Errorf("campaign、源资产、目标资产和关系类型不能为空")
	}
	if item.Confidence < 0 {
		item.Confidence = 0
	}
	if item.Confidence > 100 {
		item.Confidence = 100
	}
	refs, err := encodeEvidenceRefs(item.EvidenceRefs)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if item.ID == "" {
		item.ID = newID()
	}
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO campaign_links (
			id, campaign_id, project_id, src_asset_id, dst_asset_id, kind,
			summary, confidence, src_fact_id, src_finding_id, evidence_refs,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(campaign_id, src_asset_id, dst_asset_id, kind, src_fact_id, src_finding_id)
		DO UPDATE SET
			summary = excluded.summary,
			confidence = excluded.confidence,
			evidence_refs = excluded.evidence_refs,
			updated_at = excluded.updated_at`,
		item.ID,
		item.CampaignID,
		item.ProjectID,
		item.SrcAssetID,
		item.DstAssetID,
		item.Kind,
		item.Summary,
		item.Confidence,
		item.SrcFactID,
		item.SrcFindingID,
		refs,
		now.Unix(),
		now.Unix(),
	)
	if err != nil {
		return nil, err
	}
	var stored CampaignLink
	var storedRefs string
	var createdAt, updatedAt int64
	if err := db.QueryRowContext(
		ctx,
		`SELECT id, campaign_id, project_id, src_asset_id, dst_asset_id, kind,
			summary, confidence, src_fact_id, src_finding_id, evidence_refs,
			created_at, updated_at
		 FROM campaign_links
		 WHERE campaign_id = ? AND src_asset_id = ? AND dst_asset_id = ?
		   AND kind = ? AND src_fact_id = ? AND src_finding_id = ?`,
		item.CampaignID,
		item.SrcAssetID,
		item.DstAssetID,
		item.Kind,
		item.SrcFactID,
		item.SrcFindingID,
	).Scan(
		&stored.ID,
		&stored.CampaignID,
		&stored.ProjectID,
		&stored.SrcAssetID,
		&stored.DstAssetID,
		&stored.Kind,
		&stored.Summary,
		&stored.Confidence,
		&stored.SrcFactID,
		&stored.SrcFindingID,
		&storedRefs,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	stored.EvidenceRefs = decodeEvidenceRefs(storedRefs)
	stored.CreatedAt = time.Unix(createdAt, 0)
	stored.UpdatedAt = time.Unix(updatedAt, 0)
	return &stored, nil
}

func (db *DB) ListCampaignLinks(
	ctx context.Context,
	campaignID string,
	limit int,
) ([]CampaignLink, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, project_id, src_asset_id, dst_asset_id, kind,
			summary, confidence, src_fact_id, src_finding_id, evidence_refs,
			created_at, updated_at
		 FROM campaign_links
		 WHERE campaign_id = ?
		 ORDER BY confidence DESC, updated_at DESC
		 LIMIT ?`,
		campaignID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CampaignLink, 0)
	for rows.Next() {
		var item CampaignLink
		var refs string
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.CampaignID,
			&item.ProjectID,
			&item.SrcAssetID,
			&item.DstAssetID,
			&item.Kind,
			&item.Summary,
			&item.Confidence,
			&item.SrcFactID,
			&item.SrcFindingID,
			&refs,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.EvidenceRefs = decodeEvidenceRefs(refs)
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) EnqueueCredentialReuseTasks(
	ctx context.Context,
	campaignID string,
	srcAssetID string,
	factID string,
	summary string,
) (int, error) {
	if strings.TrimSpace(campaignID) == "" || strings.TrimSpace(srcAssetID) == "" {
		return 0, nil
	}
	var groupID string
	if err := db.QueryRowContext(
		ctx,
		`SELECT group_id FROM campaign_endpoints
		 WHERE campaign_id = ? AND asset_id = ?
		 ORDER BY created_at ASC LIMIT 1`,
		campaignID,
		srcAssetID,
	).Scan(&groupID); err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		}
		return 0, err
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT DISTINCT asset_id FROM campaign_endpoints
		 WHERE campaign_id = ? AND group_id = ? AND asset_id <> ?
		 ORDER BY asset_id
		 LIMIT 20`,
		campaignID,
		groupID,
		srcAssetID,
	)
	if err != nil {
		return 0, err
	}
	assetIDs := make([]string, 0)
	for rows.Next() {
		var assetID string
		if err := rows.Scan(&assetID); err != nil {
			_ = rows.Close()
			return 0, err
		}
		assetIDs = append(assetIDs, assetID)
	}
	_ = rows.Close()
	count := 0
	for _, dstAssetID := range assetIDs {
		intent, _ := json.Marshal(map[string]interface{}{
			"kind":         "credential_reuse",
			"src_asset_id": srcAssetID,
			"dst_asset_id": dstAssetID,
			"summary":      summary,
		})
		if _, err := db.EnqueueCampaignFrontier(ctx, CampaignFrontierItem{
			CampaignID: campaignID,
			GroupID:    groupID,
			AssetID:    dstAssetID,
			Kind:       "credential_reuse",
			Priority:   85,
			Reason:     "发现凭据，验证同组授权资产复用",
			DedupeKey:  "credential_reuse:" + factID + ":" + dstAssetID,
			SourceType: "fact",
			SourceRef:  factID,
			IntentJSON: string(intent),
		}, CampaignTaskLimits{
			MaxAttempts:  1,
			MaxSegments:  4,
			MaxToolCalls: 30,
		}); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (db *DB) EnqueueFindingVerification(
	ctx context.Context,
	campaignID string,
	findingID string,
	assetID string,
	severity string,
	title string,
) (*CampaignVerification, error) {
	if strings.TrimSpace(campaignID) == "" || strings.TrimSpace(findingID) == "" {
		return nil, nil
	}
	priority := 70
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		priority = 100
	case "high":
		priority = 95
	case "medium":
		priority = 80
	}
	intent, _ := json.Marshal(map[string]interface{}{
		"kind":       "verify_finding",
		"finding_id": findingID,
		"asset_id":   assetID,
		"title":      title,
	})
	frontierItem, err := db.EnqueueCampaignFrontier(ctx, CampaignFrontierItem{
		CampaignID: campaignID,
		AssetID:    assetID,
		Kind:       "verify_finding",
		Priority:   priority,
		Reason:     "验证漏洞证据和可复现性",
		DedupeKey:  "verify_finding:" + findingID,
		SourceType: "finding",
		SourceRef:  findingID,
		IntentJSON: string(intent),
	}, CampaignTaskLimits{
		MaxAttempts:  2,
		MaxSegments:  6,
		MaxToolCalls: 40,
	})
	if err != nil {
		return nil, err
	}
	taskID := ""
	if frontierItem != nil {
		taskID = frontierItem.TaskID
	}
	return db.UpsertCampaignVerification(ctx, CampaignVerification{
		CampaignID:  campaignID,
		FindingID:   findingID,
		TaskID:      taskID,
		Status:      CampaignVerificationStatusPending,
		MaxAttempts: 2,
	})
}

func (db *DB) CampaignP1Counts(
	ctx context.Context,
	campaignID string,
) (pendingFrontier int, pendingVerification int, linkCount int, err error) {
	if err = db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_frontier
		 WHERE campaign_id = ? AND status IN ('pending','running')`,
		campaignID,
	).Scan(&pendingFrontier); err != nil {
		return
	}
	if err = db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_verifications
		 WHERE campaign_id = ? AND status IN ('pending','running')`,
		campaignID,
	).Scan(&pendingVerification); err != nil {
		return
	}
	err = db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_links WHERE campaign_id = ?`,
		campaignID,
	).Scan(&linkCount)
	return
}
