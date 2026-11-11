package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

const (
	CampaignStatusDraft     = "draft"
	CampaignStatusRunning   = "running"
	CampaignStatusPaused    = "paused"
	CampaignStatusCompleted = "completed"
	CampaignStatusFailed    = "failed"

	CampaignTaskStatusQueued    = "queued"
	CampaignTaskStatusRunning   = "running"
	CampaignTaskStatusCompleted = "completed"
	CampaignTaskStatusFailed    = "failed"
	CampaignTaskStatusPaused    = "paused"
)

type CampaignGroup struct {
	ID                string    `json:"id"`
	CampaignID        string    `json:"campaignId"`
	ProjectID         string    `json:"projectId"`
	OwnerUserID       string    `json:"ownerUserId"`
	GroupKey          string    `json:"groupKey"`
	Label             string    `json:"label"`
	Status            string    `json:"status"`
	TotalAssets       int       `json:"totalAssets"`
	CompletedAssets   int       `json:"completedAssets"`
	FailedAssets      int       `json:"failedAssets"`
	BusinessSystem    string    `json:"businessSystem"`
	BusinessPriority  int       `json:"businessPriority"`
	PriorityScore     int       `json:"priorityScore"`
	PriorityReason    string    `json:"priorityReason"`
	PriorityUpdatedAt time.Time `json:"priorityUpdatedAt,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

type CampaignEndpoint struct {
	ID          string    `json:"id"`
	CampaignID  string    `json:"campaignId"`
	GroupID     string    `json:"groupId"`
	AssetID     string    `json:"assetId"`
	ProjectID   string    `json:"projectId"`
	OwnerUserID string    `json:"ownerUserId"`
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	Host        string    `json:"host"`
	Path        string    `json:"path"`
	Fingerprint string    `json:"fingerprint"`
	Status      string    `json:"status"`
	RiskScore   int       `json:"riskScore"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type CampaignTask struct {
	ID             string    `json:"id"`
	CampaignID     string    `json:"campaignId"`
	GroupID        string    `json:"groupId"`
	AssetID        string    `json:"assetId"`
	ConversationID string    `json:"conversationId"`
	ProjectID      string    `json:"projectId"`
	OwnerUserID    string    `json:"ownerUserId"`
	Kind           string    `json:"kind"`
	ParentTaskID   string    `json:"parentTaskId"`
	SourceType     string    `json:"sourceType"`
	SourceRef      string    `json:"sourceRef"`
	IntentJSON     string    `json:"intentJson"`
	Status         string    `json:"status"`
	Priority       int       `json:"priority"`
	Attempts       int       `json:"attempts"`
	MaxAttempts    int       `json:"maxAttempts"`
	MaxSegments    int       `json:"maxSegments"`
	MaxToolCalls   int       `json:"maxToolCalls"`
	ToolCalls      int       `json:"toolCalls"`
	Result         string    `json:"result"`
	Error          string    `json:"error"`
	NextAttemptAt  time.Time `json:"nextAttemptAt,omitempty"`
	FailureKind    string    `json:"failureKind"`
	StartedAt      time.Time `json:"startedAt,omitempty"`
	FinishedAt     time.Time `json:"finishedAt,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type CampaignStatus struct {
	ID                     string `json:"id"`
	Status                 string `json:"status"`
	TotalGroups            int    `json:"totalGroups"`
	TotalAssets            int    `json:"totalAssets"`
	TotalEndpoints         int    `json:"totalEndpoints"`
	QueuedTasks            int    `json:"queuedTasks"`
	RunningTasks           int    `json:"runningTasks"`
	CompletedTasks         int    `json:"completedTasks"`
	FailedTasks            int    `json:"failedTasks"`
	PausedTasks            int    `json:"pausedTasks"`
	CoverageTotal          int    `json:"coverageTotal"`
	CoverageCompleted      int    `json:"coverageCompleted"`
	PendingFrontier        int    `json:"pendingFrontier"`
	PendingVerification    int    `json:"pendingVerification"`
	LinkCount              int    `json:"linkCount"`
	ChainCount             int    `json:"chainCount"`
	HotMemoryCount         int    `json:"hotMemoryCount"`
	ColdMemoryCount        int    `json:"coldMemoryCount"`
	CampaignMode           string `json:"campaignMode"`
	CampaignRound          int    `json:"campaignRound"`
	MaxRounds              int    `json:"maxRounds"`
	CampaignToolCallBudget int    `json:"campaignToolCallBudget"`
	CampaignToolCalls      int    `json:"campaignToolCalls"`
}

type campaignGroupRecord struct {
	ID          string
	Key         string
	Label       string
	TotalAssets int
	CreatedAt   time.Time
}

type campaignGroupDescriptor struct {
	Key   string
	Label string
}

func campaignGroupForAsset(asset Asset) campaignGroupDescriptor {
	kind := strings.ToLower(strings.TrimSpace(asset.Kind))
	value := strings.TrimSpace(asset.Value)
	switch kind {
	case "url":
		if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
			host := strings.ToLower(parsed.Hostname())
			return campaignGroupDescriptor{Key: "host:" + host, Label: host}
		}
	case "domain":
		host := strings.ToLower(strings.TrimSuffix(value, "."))
		return campaignGroupDescriptor{Key: "domain:" + host, Label: host}
	case "ip":
		if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
			if ipv4 := ip.To4(); ipv4 != nil {
				key := fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
				return campaignGroupDescriptor{Key: "ipv4:" + key, Label: key}
			}
			if ipv6 := ip.To16(); ipv6 != nil {
				key := fmt.Sprintf("%x:%x:%x:%x::/64", ipv6[0:2], ipv6[2:4], ipv6[4:6], ipv6[6:8])
				return campaignGroupDescriptor{Key: "ipv6:" + key, Label: key}
			}
		}
	}
	if value == "" {
		value = strings.TrimSpace(asset.Name)
	}
	return campaignGroupDescriptor{Key: "other:" + strings.ToLower(value), Label: value}
}

func campaignEndpointForAsset(campaignID, groupID string, asset Asset) CampaignEndpoint {
	method := "GET"
	endpointURL := strings.TrimSpace(asset.Value)
	host := ""
	path := "/"
	if parsed, err := url.Parse(endpointURL); err == nil && parsed.Hostname() != "" {
		host = strings.ToLower(parsed.Hostname())
		path = parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
	}
	sum := sha256.Sum256([]byte(method + "\x00" + strings.ToLower(endpointURL)))
	now := time.Now().UTC()
	return CampaignEndpoint{
		ID:          newID(),
		CampaignID:  campaignID,
		GroupID:     groupID,
		AssetID:     asset.ID,
		ProjectID:   asset.ProjectID,
		OwnerUserID: asset.OwnerUserID,
		Method:      method,
		URL:         endpointURL,
		Host:        host,
		Path:        path,
		Fingerprint: hex.EncodeToString(sum[:]),
		Status:      CampaignTaskStatusQueued,
		RiskScore:   asset.RiskScore,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func (db *DB) GetCampaign(
	ctx context.Context,
	campaignID string,
	ownerUserID string,
) (*ConversationBatch, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, owner_user_id, project_id, parent_conversation_id, title,
				instruction, source_text, total, status, max_concurrency,
				max_attempts_per_task, max_segments_per_task, max_tool_calls_per_task,
				campaign_mode, resume_on_start, campaign_round, max_rounds, campaign_tool_call_budget,
				campaign_tool_calls, stopped_at, created_at, updated_at, started_at, finished_at
		 FROM conversation_batches
		 WHERE id = ? AND owner_user_id = ?`,
		campaignID,
		ownerUserID,
	)
	var item ConversationBatch
	var createdAt, updatedAt, startedAt, finishedAt, stoppedAt int64
	if err := row.Scan(
		&item.ID,
		&item.OwnerUserID,
		&item.ProjectID,
		&item.ParentConversationID,
		&item.Title,
		&item.Instruction,
		&item.SourceText,
		&item.Total,
		&item.Status,
		&item.MaxConcurrency,
		&item.MaxAttemptsPerTask,
		&item.MaxSegmentsPerTask,
		&item.MaxToolCallsPerTask,
		&item.CampaignMode,
		&item.ResumeOnStart,
		&item.CampaignRound,
		&item.MaxRounds,
		&item.CampaignToolCallBudget,
		&item.CampaignToolCalls,
		&stoppedAt,
		&createdAt,
		&updatedAt,
		&startedAt,
		&finishedAt,
	); err != nil {
		return nil, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	item.StartedAt = unixTimeOrZero(startedAt)
	item.FinishedAt = unixTimeOrZero(finishedAt)
	item.StoppedAt = unixTimeOrZero(stoppedAt)
	return &item, nil
}

func (db *DB) UpdateCampaignStatus(
	ctx context.Context,
	campaignID string,
	ownerUserID string,
	status string,
) error {
	status = strings.TrimSpace(status)
	if status != CampaignStatusRunning &&
		status != CampaignStatusPaused &&
		status != CampaignStatusCompleted &&
		status != CampaignStatusFailed &&
		status != CampaignStatusStopped &&
		status != CampaignStatusDraft {
		return fmt.Errorf("campaign status invalid")
	}
	now := time.Now().UTC()
	_, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET status = ?,
		     started_at = CASE WHEN ? = 'running' AND started_at = 0 THEN ? ELSE started_at END,
		     finished_at = CASE WHEN ? IN ('completed','failed','stopped') THEN ? ELSE finished_at END,
		     updated_at = ?
		 WHERE id = ? AND owner_user_id = ?`,
		status,
		status,
		now.Unix(),
		status,
		now.Unix(),
		now.Unix(),
		campaignID,
		ownerUserID,
	)
	return err
}

func (db *DB) ClaimCampaignTasks(
	ctx context.Context,
	campaignID string,
	limit int,
) ([]CampaignTask, error) {
	return db.ClaimCampaignTasksExcluding(ctx, campaignID, limit, nil)
}

// ClaimCampaignTasksExcluding 领取任务时排除当前进程已占用的资产，并跳过尚未到退避时间的任务。
func (db *DB) ClaimCampaignTasksExcluding(
	ctx context.Context,
	campaignID string,
	limit int,
	excludedAssetIDs []string,
) ([]CampaignTask, error) {
	if limit <= 0 || limit > 50 {
		limit = 1
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	for _, assetID := range excludedAssetIDs {
		if strings.TrimSpace(assetID) == "" {
			return nil, fmt.Errorf("excluded asset id cannot be empty")
		}
	}

	now := time.Now().UTC()
	query := `SELECT campaign_tasks.id, campaign_tasks.campaign_id,
			campaign_tasks.group_id, campaign_tasks.asset_id,
			campaign_tasks.conversation_id, campaign_tasks.project_id,
			campaign_tasks.owner_user_id, campaign_tasks.kind,
			campaign_tasks.parent_task_id, campaign_tasks.source_type,
			campaign_tasks.source_ref, campaign_tasks.intent_json,
			campaign_tasks.status, campaign_tasks.priority, campaign_tasks.attempts,
			campaign_tasks.max_attempts, campaign_tasks.max_segments,
			campaign_tasks.max_tool_calls, campaign_tasks.tool_calls,
			campaign_tasks.result, campaign_tasks.error,
			campaign_tasks.next_attempt_at, campaign_tasks.failure_kind,
			campaign_tasks.started_at, campaign_tasks.finished_at,
			campaign_tasks.created_at, campaign_tasks.updated_at
		 FROM campaign_tasks
		 LEFT JOIN campaign_frontier f
		   ON f.task_id = campaign_tasks.id
		  AND f.status IN ('pending', 'running')
		 WHERE campaign_tasks.campaign_id = ? AND campaign_tasks.status = ?
		   AND campaign_tasks.attempts < campaign_tasks.max_attempts
		   AND campaign_tasks.next_attempt_at <= ?`
	args := []interface{}{campaignID, CampaignTaskStatusQueued, now.Unix()}
	if len(excludedAssetIDs) > 0 {
		query += ` AND campaign_tasks.asset_id NOT IN (` + placeholders(len(excludedAssetIDs)) + `)`
		for _, assetID := range excludedAssetIDs {
			args = append(args, strings.TrimSpace(assetID))
		}
	}
	query += `
		 ORDER BY COALESCE(f.roi, campaign_tasks.priority) DESC,
			campaign_tasks.priority DESC, campaign_tasks.created_at ASC
		 LIMIT ?`
	args = append(args, limit)
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	items := make([]CampaignTask, 0, limit)
	for rows.Next() {
		item, scanErr := scanCampaignTask(rows)
		if scanErr != nil {
			_ = rows.Close()
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	claimed := make([]CampaignTask, 0, len(items))
	for index := range items {
		result, err := tx.ExecContext(
			ctx,
			`UPDATE campaign_tasks
				 SET status = ?, attempts = attempts + 1, next_attempt_at = 0,
				     failure_kind = '', started_at = ?, updated_at = ?
				 WHERE id = ? AND status = ?`,
			CampaignTaskStatusRunning,
			now.Unix(),
			now.Unix(),
			items[index].ID,
			CampaignTaskStatusQueued,
		)
		if err != nil {
			return nil, err
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			continue
		}
		items[index].Status = CampaignTaskStatusRunning
		items[index].Attempts++
		items[index].StartedAt = now
		items[index].UpdatedAt = now
		claimed = append(claimed, items[index])
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return claimed, nil
}

// DeferCampaignTask 把因资产占用而暂不能执行的任务放回队列，并撤销本次领取计数。
func (db *DB) DeferCampaignTask(ctx context.Context, taskID string) error {
	now := time.Now().UTC().Unix()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(
		ctx,
		`UPDATE campaign_tasks
		 SET status = ?, attempts = MAX(attempts - 1, 0),
		     next_attempt_at = 0, started_at = 0, updated_at = ?
		 WHERE id = ? AND status = ?`,
		CampaignTaskStatusQueued,
		now,
		taskID,
		CampaignTaskStatusRunning,
	)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE campaign_frontier SET status = ?, updated_at = ? WHERE task_id = ?`,
		CampaignFrontierStatusPending,
		now,
		taskID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) CompleteCampaignTask(
	ctx context.Context,
	taskID string,
	status string,
	result string,
	errText string,
	toolCalls int,
) error {
	_, err := db.CompleteCampaignTaskWithRetry(
		ctx,
		taskID,
		status,
		result,
		errText,
		toolCalls,
		"",
		false,
	)
	return err
}

// CompleteCampaignTaskWithRetry 在可重试错误且仍有尝试次数时，将任务放回队列并记录退避时间。
func (db *DB) CompleteCampaignTaskWithRetry(
	ctx context.Context,
	taskID string,
	status string,
	result string,
	errText string,
	toolCalls int,
	failureKind string,
	retryable bool,
) (bool, error) {
	if status != CampaignTaskStatusCompleted &&
		status != CampaignTaskStatusFailed &&
		status != CampaignTaskStatusPaused {
		status = CampaignTaskStatusFailed
	}
	now := time.Now().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var campaignID, groupID, taskKind string
	var attempts, maxAttempts int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT campaign_id, group_id, kind, attempts, max_attempts
		 FROM campaign_tasks WHERE id = ?`,
		taskID,
	).Scan(&campaignID, &groupID, &taskKind, &attempts, &maxAttempts); err != nil {
		return false, err
	}
	nextAttemptAt := int64(0)
	retryScheduled := status == CampaignTaskStatusFailed &&
		retryable &&
		attempts < maxAttempts
	if retryScheduled {
		status = CampaignTaskStatusQueued
		nextAttemptAt = now.Add(campaignRetryDelay(attempts)).Unix()
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE campaign_tasks
		 SET status = ?, result = ?, error = ?, tool_calls = tool_calls + ?,
		     failure_kind = ?, next_attempt_at = ?,
		     finished_at = CASE WHEN ? = 'queued' THEN 0 ELSE ? END,
		     updated_at = ?
		 WHERE id = ? AND status = ?`,
		status,
		strings.TrimSpace(result),
		strings.TrimSpace(errText),
		toolCalls,
		strings.TrimSpace(failureKind),
		nextAttemptAt,
		status,
		now.Unix(),
		now.Unix(),
		taskID,
		CampaignTaskStatusRunning,
	); err != nil {
		return false, err
	}
	frontierStatus := CampaignFrontierStatusFailed
	if status == CampaignTaskStatusCompleted {
		frontierStatus = CampaignFrontierStatusCompleted
	} else if status == CampaignTaskStatusPaused || status == CampaignTaskStatusQueued {
		frontierStatus = CampaignFrontierStatusPending
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE campaign_frontier
		 SET status = ?, updated_at = ?
		 WHERE task_id = ?`,
		frontierStatus,
		now.Unix(),
		taskID,
	); err != nil {
		return false, err
	}
	if status == CampaignTaskStatusQueued {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE campaign_verifications
			 SET status = ?, updated_at = ?
			 WHERE campaign_id = ? AND task_id = ?`,
			CampaignVerificationStatusPending,
			now.Unix(),
			campaignID,
			taskID,
		); err != nil {
			return false, err
		}
	} else if status == CampaignTaskStatusCompleted || status == CampaignTaskStatusFailed {
		verificationStatus := CampaignVerificationStatusCompleted
		if status == CampaignTaskStatusFailed {
			verificationStatus = CampaignVerificationStatusFailed
		}
		trimmedResult := strings.TrimSpace(result)
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE campaign_verifications
			 SET status = CASE
			       WHEN ? = ? AND attempts + 1 < max_attempts THEN ?
			       ELSE ?
			     END,
			     attempts = attempts + 1,
			     result = CASE WHEN ? <> '' THEN ? ELSE result END,
			     updated_at = ?
			 WHERE campaign_id = ? AND task_id = ?`,
			status,
			CampaignTaskStatusFailed,
			CampaignVerificationStatusPending,
			verificationStatus,
			trimmedResult,
			trimmedResult,
			now.Unix(),
			campaignID,
			taskID,
		); err != nil {
			return false, err
		}
	}
	completedDelta := 0
	failedDelta := 0
	if taskKind == "asset_scan" {
		switch status {
		case CampaignTaskStatusCompleted:
			completedDelta = 1
		case CampaignTaskStatusFailed:
			failedDelta = 1
		}
	}
	if completedDelta != 0 || failedDelta != 0 {
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE campaign_groups
			 SET completed_assets = completed_assets + ?,
			     failed_assets = failed_assets + ?,
			     status = CASE
			       WHEN completed_assets + failed_assets + ? + ? >= total_assets THEN 'completed'
			       ELSE 'running'
			     END,
			     updated_at = ?
			 WHERE id = ?`,
			completedDelta,
			failedDelta,
			completedDelta,
			failedDelta,
			now.Unix(),
			groupID,
		); err != nil {
			return false, err
		}
	}
	if err := db.updateCampaignCompletionTx(ctx, tx, campaignID, now); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return retryScheduled, nil
}

func campaignRetryDelay(attempts int) time.Duration {
	switch {
	case attempts <= 1:
		return 5 * time.Second
	case attempts == 2:
		return 15 * time.Second
	default:
		return 45 * time.Second
	}
}

func (db *DB) updateCampaignCompletionTx(
	ctx context.Context,
	tx *sql.Tx,
	campaignID string,
	now time.Time,
) error {
	var pending, failed int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT
			COALESCE(SUM(CASE WHEN status IN ('queued','running','paused') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0)
		 FROM campaign_tasks WHERE campaign_id = ?`,
		campaignID,
	).Scan(&pending, &failed); err != nil {
		return err
	}
	if pending > 0 {
		return nil
	}
	status := CampaignStatusCompleted
	if failed > 0 {
		status = CampaignStatusFailed
	}
	_, err := tx.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET status = ?, finished_at = ?, updated_at = ?
		 WHERE id = ?`,
		status,
		now.Unix(),
		now.Unix(),
		campaignID,
	)
	return err
}

func (db *DB) UpdateCampaignTaskProgress(
	ctx context.Context,
	taskID string,
	toolCalls int,
) error {
	if toolCalls < 0 {
		toolCalls = 0
	}
	_, err := db.ExecContext(
		ctx,
		`UPDATE campaign_tasks
		 SET tool_calls = ?, updated_at = ?
		 WHERE id = ? AND status = ?`,
		toolCalls,
		time.Now().UTC().Unix(),
		taskID,
		CampaignTaskStatusRunning,
	)
	return err
}

func (db *DB) ListCampaignGroups(
	ctx context.Context,
	campaignID string,
) ([]CampaignGroup, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, project_id, owner_user_id, group_key, label,
			status, total_assets, completed_assets, failed_assets,
			business_system, business_priority, priority_score, priority_reason,
			priority_updated_at, created_at, updated_at
		 FROM campaign_groups
		 WHERE campaign_id = ?
		 ORDER BY label ASC`,
		campaignID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CampaignGroup, 0)
	for rows.Next() {
		var item CampaignGroup
		var createdAt, updatedAt, priorityUpdatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.CampaignID,
			&item.ProjectID,
			&item.OwnerUserID,
			&item.GroupKey,
			&item.Label,
			&item.Status,
			&item.TotalAssets,
			&item.CompletedAssets,
			&item.FailedAssets,
			&item.BusinessSystem,
			&item.BusinessPriority,
			&item.PriorityScore,
			&item.PriorityReason,
			&priorityUpdatedAt,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		item.UpdatedAt = time.Unix(updatedAt, 0)
		item.PriorityUpdatedAt = unixTimeOrZero(priorityUpdatedAt)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListCampaignTasks(
	ctx context.Context,
	campaignID string,
	status string,
	limit int,
	offset int,
) ([]CampaignTask, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where := `campaign_id = ?`
	args := []interface{}{campaignID}
	if value := strings.TrimSpace(status); value != "" {
		where += ` AND status = ?`
		args = append(args, value)
	}
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_tasks WHERE `+where,
		args...,
	).Scan(&total); err != nil {
		return nil, 0, err
	}
	queryArgs := append(append([]interface{}{}, args...), limit, offset)
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, group_id, asset_id, conversation_id,
			project_id, owner_user_id, kind, parent_task_id, source_type,
			source_ref, intent_json, status, priority, attempts,
			max_attempts, max_segments, max_tool_calls, tool_calls,
				result, error, next_attempt_at, failure_kind,
				started_at, finished_at, created_at, updated_at
		 FROM campaign_tasks
		 WHERE `+where+`
		 ORDER BY priority DESC, created_at ASC
		 LIMIT ? OFFSET ?`,
		queryArgs...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]CampaignTask, 0, limit)
	for rows.Next() {
		item, scanErr := scanCampaignTask(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	return items, total, rows.Err()
}

func (db *DB) GetCampaignTaskByConversation(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
) (*CampaignTask, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, campaign_id, group_id, asset_id, conversation_id,
			project_id, owner_user_id, kind, parent_task_id, source_type,
			source_ref, intent_json, status, priority, attempts,
			max_attempts, max_segments, max_tool_calls, tool_calls,
				result, error, next_attempt_at, failure_kind,
				started_at, finished_at, created_at, updated_at
		 FROM campaign_tasks
		 WHERE conversation_id = ? AND owner_user_id = ?
		 ORDER BY created_at DESC, rowid DESC
		 LIMIT 1`,
		conversationID,
		ownerUserID,
	)
	item, err := scanCampaignTask(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func (db *DB) GetCampaignTaskByID(
	ctx context.Context,
	taskID string,
	ownerUserID string,
) (*CampaignTask, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, campaign_id, group_id, asset_id, conversation_id,
			project_id, owner_user_id, kind, parent_task_id, source_type,
			source_ref, intent_json, status, priority, attempts,
			max_attempts, max_segments, max_tool_calls, tool_calls,
				result, error, next_attempt_at, failure_kind,
				started_at, finished_at, created_at, updated_at
		 FROM campaign_tasks
		 WHERE id = ? AND owner_user_id = ?`,
		strings.TrimSpace(taskID),
		strings.TrimSpace(ownerUserID),
	)
	item, err := scanCampaignTask(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &item, nil
}

func (db *DB) ListCampaignEndpoints(
	ctx context.Context,
	campaignID string,
	limit int,
	offset int,
) ([]CampaignEndpoint, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_endpoints WHERE campaign_id = ?`,
		campaignID,
	).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, campaign_id, group_id, asset_id, project_id, owner_user_id,
			method, url, host, path, fingerprint, status, risk_score, created_at, updated_at
		 FROM campaign_endpoints
		 WHERE campaign_id = ?
		 ORDER BY risk_score DESC, created_at ASC
		 LIMIT ? OFFSET ?`,
		campaignID,
		limit,
		offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]CampaignEndpoint, 0, limit)
	for rows.Next() {
		var item CampaignEndpoint
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.CampaignID,
			&item.GroupID,
			&item.AssetID,
			&item.ProjectID,
			&item.OwnerUserID,
			&item.Method,
			&item.URL,
			&item.Host,
			&item.Path,
			&item.Fingerprint,
			&item.Status,
			&item.RiskScore,
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

// CampaignContainsAsset 判断资产是否属于某个 Campaign 的授权范围。
func (db *DB) CampaignContainsAsset(
	ctx context.Context,
	campaignID string,
	assetID string,
) (bool, error) {
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_endpoints
		 WHERE campaign_id = ? AND asset_id = ?`,
		strings.TrimSpace(campaignID),
		strings.TrimSpace(assetID),
	).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// ListCampaignAssets 返回 Campaign 授权范围内的资产，用于 Policy Engine 范围校验。
func (db *DB) ListCampaignAssets(
	ctx context.Context,
	campaignID string,
	ownerUserID string,
) ([]Asset, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT DISTINCT a.id, a.project_id, a.owner_user_id, a.name, a.kind,
			a.value, a.status, a.criticality, a.risk_score,
			a.created_at, a.updated_at
		 FROM assets a
		 JOIN campaign_endpoints e ON e.asset_id = a.id
		 WHERE e.campaign_id = ? AND e.owner_user_id = ?
		 ORDER BY a.id ASC`,
		strings.TrimSpace(campaignID),
		strings.TrimSpace(ownerUserID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Asset, 0)
	for rows.Next() {
		var item Asset
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.OwnerUserID,
			&item.Name,
			&item.Kind,
			&item.Value,
			&item.Status,
			&item.Criticality,
			&item.RiskScore,
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

func (db *DB) CampaignSummary(
	ctx context.Context,
	campaignID string,
) (*CampaignStatus, error) {
	item := &CampaignStatus{ID: campaignID}
	if err := db.QueryRowContext(
		ctx,
		`SELECT status, campaign_mode, campaign_round, max_rounds,
			campaign_tool_call_budget, campaign_tool_calls
		 FROM conversation_batches WHERE id = ?`,
		campaignID,
	).Scan(
		&item.Status,
		&item.CampaignMode,
		&item.CampaignRound,
		&item.MaxRounds,
		&item.CampaignToolCallBudget,
		&item.CampaignToolCalls,
	); err != nil {
		return nil, err
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(SUM(total_assets),0) FROM campaign_groups WHERE campaign_id = ?`,
		campaignID,
	).Scan(&item.TotalGroups, &item.TotalAssets); err != nil {
		return nil, err
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_endpoints WHERE campaign_id = ?`,
		campaignID,
	).Scan(&item.TotalEndpoints); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT status, COUNT(*) FROM campaign_tasks WHERE campaign_id = ? GROUP BY status`,
		campaignID,
	)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			_ = rows.Close()
			return nil, err
		}
		switch status {
		case CampaignTaskStatusQueued:
			item.QueuedTasks = count
		case CampaignTaskStatusRunning:
			item.RunningTasks = count
		case CampaignTaskStatusCompleted:
			item.CompletedTasks = count
		case CampaignTaskStatusFailed:
			item.FailedTasks = count
		case CampaignTaskStatusPaused:
			item.PausedTasks = count
		}
	}
	_ = rows.Close()
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status IN ('tested_clean','confirmed','blocked','suspicious') THEN 1 ELSE 0 END), 0)
		 FROM campaign_coverage WHERE campaign_id = ?`,
		campaignID,
	).Scan(&item.CoverageTotal, &item.CoverageCompleted); err != nil {
		return nil, err
	}
	pendingFrontier, pendingVerification, linkCount, err := db.CampaignP1Counts(ctx, campaignID)
	if err != nil {
		return nil, err
	}
	item.PendingFrontier = pendingFrontier
	item.PendingVerification = pendingVerification
	item.LinkCount = linkCount
	chainCount, hotCount, coldCount, err := db.CampaignP2Counts(ctx, campaignID)
	if err != nil {
		return nil, err
	}
	item.ChainCount = chainCount
	item.HotMemoryCount = hotCount
	item.ColdMemoryCount = coldCount
	return item, nil
}

func (db *DB) UpsertCampaignCoverage(
	ctx context.Context,
	campaignID string,
	assetID string,
	dimension string,
	technique string,
	status string,
	evidenceRefs []string,
) error {
	if strings.TrimSpace(campaignID) == "" || strings.TrimSpace(assetID) == "" {
		return nil
	}
	refs, err := encodeEvidenceRefs(evidenceRefs)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO campaign_coverage (
			campaign_id, asset_id, dimension, technique, status,
			attempts, evidence_refs, updated_at
		) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
		ON CONFLICT(campaign_id, asset_id, dimension, technique) DO UPDATE SET
			status = excluded.status,
			attempts = campaign_coverage.attempts + 1,
			evidence_refs = excluded.evidence_refs,
			updated_at = excluded.updated_at`,
		campaignID,
		assetID,
		strings.TrimSpace(dimension),
		strings.TrimSpace(technique),
		strings.TrimSpace(status),
		refs,
		now,
	)
	return err
}

func (db *DB) RequeueCampaignFailedTasks(
	ctx context.Context,
	campaignID string,
) (int, error) {
	result, err := db.ExecContext(
		ctx,
		`UPDATE campaign_tasks
		 SET status = ?, next_attempt_at = 0, failure_kind = '', updated_at = ?
		 WHERE campaign_id = ? AND status IN (?, ?) AND attempts < max_attempts`,
		CampaignTaskStatusQueued,
		time.Now().UTC().Unix(),
		campaignID,
		CampaignTaskStatusFailed,
		CampaignTaskStatusPaused,
	)
	if err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	return int(affected), nil
}

func (db *DB) CampaignHasPendingTasks(
	ctx context.Context,
	campaignID string,
) (bool, error) {
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_tasks
		 WHERE campaign_id = ? AND status IN ('queued','running')`,
		campaignID,
	).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (db *DB) CampaignHasPausedTasks(
	ctx context.Context,
	campaignID string,
) (bool, error) {
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM campaign_tasks
		 WHERE campaign_id = ? AND status = 'paused'`,
		campaignID,
	).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (db *DB) PauseRunningCampaigns(ctx context.Context) (int, error) {
	now := time.Now().UTC().Unix()
	result, err := db.ExecContext(
		ctx,
		`UPDATE conversation_batches
		 SET status = ?, updated_at = ?
		 WHERE status = ?`,
		CampaignStatusPaused,
		now,
		CampaignStatusRunning,
	)
	if err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	_, _ = db.ExecContext(
		ctx,
		`UPDATE campaign_tasks
		 SET status = CASE WHEN attempts < max_attempts THEN ? ELSE ? END,
		     updated_at = ?
		 WHERE status = ?`,
		CampaignTaskStatusQueued,
		CampaignTaskStatusFailed,
		now,
		CampaignTaskStatusRunning,
	)
	return int(affected), nil
}

type campaignTaskScanner interface {
	Scan(dest ...interface{}) error
}

func scanCampaignTask(scanner campaignTaskScanner) (CampaignTask, error) {
	var item CampaignTask
	var nextAttemptAt, startedAt, finishedAt, createdAt, updatedAt int64
	if err := scanner.Scan(
		&item.ID,
		&item.CampaignID,
		&item.GroupID,
		&item.AssetID,
		&item.ConversationID,
		&item.ProjectID,
		&item.OwnerUserID,
		&item.Kind,
		&item.ParentTaskID,
		&item.SourceType,
		&item.SourceRef,
		&item.IntentJSON,
		&item.Status,
		&item.Priority,
		&item.Attempts,
		&item.MaxAttempts,
		&item.MaxSegments,
		&item.MaxToolCalls,
		&item.ToolCalls,
		&item.Result,
		&item.Error,
		&nextAttemptAt,
		&item.FailureKind,
		&startedAt,
		&finishedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return CampaignTask{}, err
	}
	item.StartedAt = unixTimeOrZero(startedAt)
	item.FinishedAt = unixTimeOrZero(finishedAt)
	item.NextAttemptAt = unixTimeOrZero(nextAttemptAt)
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return item, nil
}
