package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	AssetAuthorizationDiscovered = "discovered"
	AssetAuthorizationAuthorized = "authorized"
	AssetAuthorizationOutOfScope = "out_of_scope"

	AssetWorkQueued        = "queued"
	AssetWorkActive        = "active"
	AssetWorkTesting       = "testing"
	AssetWorkNeedsFollowup = "needs_followup"
	AssetWorkBlocked       = "blocked"
	AssetWorkAwaitingUser  = "awaiting_user"
	AssetWorkComplete      = "complete"
	AssetWorkReopened      = "reopened"

	AssetUserStopReason = "user_asset_stopped"
)

var ErrAssetWorkNotStoppable = errors.New("资产当前状态不允许停止")

var assetAuthorizationStates = map[string]bool{
	AssetAuthorizationDiscovered: true,
	AssetAuthorizationAuthorized: true,
	AssetAuthorizationOutOfScope: true,
}

var assetWorkStates = map[string]bool{
	AssetWorkQueued:        true,
	AssetWorkActive:        true,
	AssetWorkTesting:       true,
	AssetWorkNeedsFollowup: true,
	AssetWorkBlocked:       true,
	AssetWorkAwaitingUser:  true,
	AssetWorkComplete:      true,
	AssetWorkReopened:      true,
}

type ProjectAssetWork struct {
	ProjectID           string    `json:"projectId"`
	OwnerUserID         string    `json:"ownerUserId"`
	AssetID             string    `json:"assetId"`
	AssetName           string    `json:"assetName"`
	AssetKind           string    `json:"assetKind"`
	AssetValue          string    `json:"assetValue"`
	QualityStatus       string    `json:"qualityStatus"`
	AssetStatus         string    `json:"assetStatus"`
	Criticality         string    `json:"criticality"`
	RiskScore           int       `json:"riskScore"`
	AuthorizationState  string    `json:"authorizationState"`
	WorkState           string    `json:"workState"`
	Priority            int       `json:"priority"`
	StateReason         string    `json:"stateReason"`
	LeaseOwner          string    `json:"leaseOwner"`
	LeaseConversationID string    `json:"leaseConversationId"`
	LeaseUntil          time.Time `json:"leaseUntil"`
	LastProgressAt      time.Time `json:"lastProgressAt"`
	CloseoutReason      string    `json:"closeoutReason"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

type ProjectAssetStopResult struct {
	AssetID        string `json:"assetId"`
	StoppedIntents int64  `json:"stoppedIntents"`
	StoppedTests   int64  `json:"stoppedTests"`
}

func NormalizeAssetWorkState(value string) (string, bool) {
	state := strings.ToLower(strings.TrimSpace(value))
	if state == "" {
		state = AssetWorkQueued
	}
	return state, assetWorkStates[state]
}

// SyncProjectAssetWork projects current assets into the persisted work queue.
// Coverage and test results remain the source of truth; this table only stores
// scheduling, authorization and closeout state.
func (db *DB) SyncProjectAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) error {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if projectID == "" || ownerUserID == "" {
		return fmt.Errorf("项目或用户不能为空")
	}
	project, err := db.GetProject(ctx, projectID, ownerUserID)
	if err != nil {
		return err
	}
	assets, err := db.ListProjectAssets(ctx, projectID, ownerUserID)
	if err != nil {
		return err
	}
	existing, err := db.listProjectAssetWorkRows(ctx, projectID, ownerUserID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, asset := range assets {
		current, ok := existing[asset.ID]
		authorization := assetAuthorizationState(project.Scope, asset)
		state := AssetWorkQueued
		reason := ""
		switch {
		case !isActionableAssetKind(asset.Kind):
			state = AssetWorkBlocked
			reason = "历史资产类型不再进入工作队列"
		case asset.Status != "" && !strings.EqualFold(asset.Status, "active"):
			state = AssetWorkBlocked
			reason = "资产未启用"
		case asset.QualityStatus == AssetQualityDuplicate ||
			asset.QualityStatus == AssetQualityCrossTypeDuplicate ||
			asset.QualityStatus == AssetQualityInvalid ||
			asset.QualityStatus == AssetQualityLegacyUnsupported:
			state = AssetWorkAwaitingUser
			reason = "资产质量需要人工确认: " + asset.QualityStatus
		case asset.QualityStatus == AssetQualitySuspicious:
			state = AssetWorkAwaitingUser
			reason = "资产质量可疑，需要确认后测试"
		case authorization != AssetAuthorizationAuthorized:
			state = AssetWorkBlocked
			reason = "资产尚未获得项目测试授权"
		}
		priority := projectAssetWorkPriority(asset)
		if !ok {
			_, err = db.ExecContext(
				ctx,
				`INSERT INTO project_asset_work (
					project_id, owner_user_id, asset_id, authorization_state, work_state,
					priority, state_reason, lease_owner, lease_conversation_id, lease_until,
					last_progress_at, closeout_reason, created_at, updated_at
				) VALUES (?, ?, ?, ?, ?, ?, ?, '', '', 0, 0, '', ?, ?)`,
				projectID,
				ownerUserID,
				asset.ID,
				authorization,
				state,
				priority,
				reason,
				now.Unix(),
				now.Unix(),
			)
			if err != nil {
				return err
			}
			continue
		}

		nextState := current.WorkState
		nextReason := current.StateReason
		clearLease := false
		if isActiveAssetWork(current) && !current.LeaseUntil.IsZero() && !current.LeaseUntil.After(now) {
			nextState = AssetWorkQueued
			nextReason = "资产租约已过期，重新排队"
			clearLease = true
		} else if authorization != AssetAuthorizationAuthorized && !isActiveAssetWork(current) {
			nextState = AssetWorkBlocked
			nextReason = "资产尚未获得项目测试授权"
		} else if state != AssetWorkQueued && !isActiveAssetWork(current) && current.WorkState != AssetWorkComplete {
			nextState = state
			nextReason = reason
		} else if state != AssetWorkQueued && isActiveAssetWork(current) {
			nextState = state
			nextReason = reason
			clearLease = true
		} else if state == AssetWorkQueued &&
			(current.WorkState == AssetWorkQueued || current.WorkState == AssetWorkReopened) {
			nextState = current.WorkState
			nextReason = current.StateReason
		}
		if authorization != AssetAuthorizationAuthorized && isActiveAssetWork(current) {
			nextState = AssetWorkBlocked
			nextReason = "资产授权已失效，停止继续测试"
			clearLease = true
		}
		if !clearLease &&
			current.AuthorizationState == authorization &&
			current.WorkState == nextState &&
			current.Priority == priority &&
			current.StateReason == nextReason {
			continue
		}
		if clearLease {
			_, err = db.ExecContext(
				ctx,
				`UPDATE project_asset_work
				 SET authorization_state = ?, work_state = ?, priority = ?, state_reason = ?,
				     lease_owner = '', lease_conversation_id = '', lease_until = 0, updated_at = ?
				 WHERE project_id = ? AND asset_id = ?`,
				authorization,
				nextState,
				priority,
				nextReason,
				now.Unix(),
				projectID,
				asset.ID,
			)
		} else {
			_, err = db.ExecContext(
				ctx,
				`UPDATE project_asset_work
				 SET authorization_state = ?, work_state = ?, priority = ?, state_reason = ?, updated_at = ?
				 WHERE project_id = ? AND asset_id = ?`,
				authorization,
				nextState,
				priority,
				nextReason,
				now.Unix(),
				projectID,
				asset.ID,
			)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) listProjectAssetWorkRows(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) (map[string]ProjectAssetWork, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT w.project_id, w.owner_user_id, w.asset_id, a.name, a.kind, a.value,
		        a.quality_status, a.status, a.criticality, a.risk_score,
		        w.authorization_state, w.work_state, w.priority, w.state_reason,
		        w.lease_owner, w.lease_conversation_id, w.lease_until,
		        w.last_progress_at, w.closeout_reason, w.created_at, w.updated_at
		 FROM project_asset_work w
		 JOIN assets a ON a.id = w.asset_id AND a.project_id = w.project_id AND a.owner_user_id = w.owner_user_id
		 WHERE w.project_id = ? AND w.owner_user_id = ?`,
		projectID,
		ownerUserID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := map[string]ProjectAssetWork{}
	for rows.Next() {
		item, scanErr := scanProjectAssetWork(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items[item.AssetID] = item
	}
	return items, rows.Err()
}

func (db *DB) ListProjectAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) ([]ProjectAssetWork, error) {
	if err := db.SyncProjectAssetWork(ctx, projectID, ownerUserID); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT w.project_id, w.owner_user_id, w.asset_id, a.name, a.kind, a.value,
		        a.quality_status, a.status, a.criticality, a.risk_score,
		        w.authorization_state, w.work_state, w.priority, w.state_reason,
		        w.lease_owner, w.lease_conversation_id, w.lease_until,
		        w.last_progress_at, w.closeout_reason, w.created_at, w.updated_at
		 FROM project_asset_work w
		 JOIN assets a ON a.id = w.asset_id AND a.project_id = w.project_id AND a.owner_user_id = w.owner_user_id
		 WHERE w.project_id = ? AND w.owner_user_id = ?
		 ORDER BY CASE w.work_state
		     WHEN 'active' THEN 0
		     WHEN 'testing' THEN 1
		     WHEN 'reopened' THEN 2
		     WHEN 'queued' THEN 3
		     WHEN 'needs_followup' THEN 4
		     WHEN 'awaiting_user' THEN 5
		     WHEN 'blocked' THEN 6
		     WHEN 'complete' THEN 7
		     ELSE 8
		   END, w.priority DESC, w.updated_at ASC`,
		projectID,
		ownerUserID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectAssetWork, 0)
	for rows.Next() {
		item, scanErr := scanProjectAssetWork(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListAuthorizedProjectAssets returns the only assets that may enter the
// execution policy. Asset authorization is stricter than the project's asset
// inventory: inactive, out-of-scope and non-actionable assets remain visible in
// the UI but must not become policy scope entries.
func (db *DB) ListAuthorizedProjectAssets(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) ([]Asset, error) {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if projectID == "" || ownerUserID == "" {
		return nil, fmt.Errorf("项目或用户不能为空")
	}
	project, err := db.GetProject(ctx, projectID, ownerUserID)
	if err != nil {
		return nil, err
	}
	assets, err := db.ListProjectAssets(ctx, projectID, ownerUserID)
	if err != nil {
		return nil, err
	}
	authorized := make([]Asset, 0, len(assets))
	for _, asset := range assets {
		if !assetTestingEligible(project.Scope, asset) {
			continue
		}
		authorized = append(authorized, asset)
	}
	return authorized, nil
}

// ProjectHasAssetWork reports whether this project has been projected into the
// asset work state. It lets legacy sessions fall back to the old hypothesis
// queue only when no asset isolation state exists at all.
func (db *DB) ProjectHasAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) (bool, error) {
	var exists bool
	err := db.QueryRowContext(
		ctx,
		`SELECT EXISTS(
			SELECT 1 FROM project_asset_work
			WHERE project_id = ? AND owner_user_id = ?
		)`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
	).Scan(&exists)
	return exists, err
}

func (db *DB) GetProjectAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
) (*ProjectAssetWork, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT w.project_id, w.owner_user_id, w.asset_id, a.name, a.kind, a.value,
		        a.quality_status, a.status, a.criticality, a.risk_score,
		        w.authorization_state, w.work_state, w.priority, w.state_reason,
		        w.lease_owner, w.lease_conversation_id, w.lease_until,
		        w.last_progress_at, w.closeout_reason, w.created_at, w.updated_at
		 FROM project_asset_work w
		 JOIN assets a ON a.id = w.asset_id AND a.project_id = w.project_id AND a.owner_user_id = w.owner_user_id
		 WHERE w.project_id = ? AND w.owner_user_id = ? AND w.asset_id = ?`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(assetID),
	)
	item, err := scanProjectAssetWork(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) GetActiveProjectAssetWorkForConversation(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	conversationID string,
) (*ProjectAssetWork, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT w.project_id, w.owner_user_id, w.asset_id, a.name, a.kind, a.value,
		        a.quality_status, a.status, a.criticality, a.risk_score,
		        w.authorization_state, w.work_state, w.priority, w.state_reason,
		        w.lease_owner, w.lease_conversation_id, w.lease_until,
		        w.last_progress_at, w.closeout_reason, w.created_at, w.updated_at
		 FROM project_asset_work w
		 JOIN assets a ON a.id = w.asset_id AND a.project_id = w.project_id AND a.owner_user_id = w.owner_user_id
		 WHERE w.project_id = ? AND w.owner_user_id = ? AND w.lease_conversation_id = ?
		   AND w.lease_until > ?
		   AND w.work_state IN ('active', 'testing', 'needs_followup')
		 ORDER BY w.updated_at DESC LIMIT 1`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(conversationID),
		time.Now().UTC().Unix(),
	)
	item, err := scanProjectAssetWork(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) ClaimNextProjectAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	conversationID string,
	leaseOwner string,
	ttl time.Duration,
) (*ProjectAssetWork, error) {
	return db.claimNextProjectAssetWork(
		ctx,
		projectID,
		ownerUserID,
		conversationID,
		leaseOwner,
		ttl,
		nil,
	)
}

func (db *DB) ClaimNextProjectAssetWorkExcluding(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	conversationID string,
	leaseOwner string,
	ttl time.Duration,
	excludedAssetIDs []string,
) (*ProjectAssetWork, error) {
	return db.claimNextProjectAssetWork(
		ctx,
		projectID,
		ownerUserID,
		conversationID,
		leaseOwner,
		ttl,
		excludedAssetIDs,
	)
}

func (db *DB) claimNextProjectAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	conversationID string,
	leaseOwner string,
	ttl time.Duration,
	excludedAssetIDs []string,
) (*ProjectAssetWork, error) {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	conversationID = strings.TrimSpace(conversationID)
	leaseOwner = strings.TrimSpace(leaseOwner)
	if projectID == "" || ownerUserID == "" || conversationID == "" || leaseOwner == "" {
		return nil, fmt.Errorf("项目、用户、会话和租约所有者不能为空")
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if err := db.SyncProjectAssetWork(ctx, projectID, ownerUserID); err != nil {
		return nil, err
	}
	excludedFilter := ""
	excludedArgs := make([]interface{}, 0, len(excludedAssetIDs))
	if len(excludedAssetIDs) > 0 {
		excludedFilter = " AND candidate.asset_id NOT IN (" + placeholders(len(excludedAssetIDs)) + ")"
		for _, assetID := range excludedAssetIDs {
			excludedArgs = append(excludedArgs, strings.TrimSpace(assetID))
		}
	}
	now := time.Now().UTC()
	queryArgs := []interface{}{
		leaseOwner,
		conversationID,
		now.Add(ttl).Unix(),
		now.Unix(),
		now.Unix(),
		projectID,
		ownerUserID,
	}
	queryArgs = append(queryArgs, excludedArgs...)
	queryArgs = append(queryArgs, now.Unix())
	row := db.QueryRowContext(
		ctx,
		`UPDATE project_asset_work
		 SET work_state = 'active', lease_owner = ?, lease_conversation_id = ?,
		     lease_until = ?, last_progress_at = ?, updated_at = ?
		 WHERE (project_id, asset_id) = (
			SELECT candidate.project_id, candidate.asset_id
			FROM project_asset_work AS candidate
			WHERE candidate.project_id = ? AND candidate.owner_user_id = ?
			  `+excludedFilter+`
			  AND candidate.authorization_state = 'authorized'
			  AND candidate.work_state IN ('queued', 'reopened', 'needs_followup')
			  AND (candidate.lease_until = 0 OR candidate.lease_until <= ?)
			ORDER BY candidate.priority DESC, candidate.updated_at ASC, candidate.asset_id ASC
			LIMIT 1
		 )
		 RETURNING project_id, owner_user_id, asset_id,
		           authorization_state, work_state, priority, state_reason,
		           lease_owner, lease_conversation_id, lease_until,
		           last_progress_at, closeout_reason, created_at, updated_at`,
		queryArgs...,
	)
	item, err := scanProjectAssetWorkLease(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	full, err := db.GetProjectAssetWork(ctx, projectID, ownerUserID, item.AssetID)
	if err != nil {
		return nil, err
	}
	if full != nil {
		return full, nil
	}
	return &item, nil
}

func (db *DB) RenewProjectAssetWorkLease(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
	conversationID string,
	ttl time.Duration,
) error {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_asset_work
		 SET lease_until = ?, last_progress_at = ?, updated_at = ?
		 WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?
		   AND lease_conversation_id = ? AND lease_until >= ?
		   AND work_state IN ('active', 'testing', 'needs_followup')`,
		now.Add(ttl).Unix(),
		now.Unix(),
		now.Unix(),
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(assetID),
		strings.TrimSpace(conversationID),
		now.Unix(),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("资产租约已失效或不属于当前会话")
	}
	return nil
}

func (db *DB) MarkProjectAssetWorkTesting(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
	conversationID string,
) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_asset_work
		 SET work_state = 'testing', updated_at = ?
		 WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?
		   AND lease_conversation_id = ? AND lease_until >= ?`,
		time.Now().UTC().Unix(),
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(assetID),
		strings.TrimSpace(conversationID),
		time.Now().UTC().Unix(),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("资产租约已失效或不属于当前会话")
	}
	return nil
}

func (db *DB) UpdateProjectAssetWorkState(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
	state string,
	reason string,
) error {
	state, ok := NormalizeAssetWorkState(state)
	if !ok {
		return fmt.Errorf("资产工作状态不合法")
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_asset_work
		 SET work_state = ?, state_reason = ?, lease_owner = '', lease_conversation_id = '',
		     lease_until = 0, last_progress_at = ?, updated_at = ?
		 WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?`,
		state,
		strings.TrimSpace(reason),
		now.Unix(),
		now.Unix(),
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(assetID),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) RecentTerminalProjectTestResultsByAsset(
	ctx context.Context,
	projectID string,
	assetID string,
	since time.Time,
	limit int,
) ([]ProjectTestResult, error) {
	projectID = strings.TrimSpace(projectID)
	assetID = strings.TrimSpace(assetID)
	if projectID == "" || assetID == "" {
		return nil, fmt.Errorf("项目和资产不能为空")
	}
	if limit <= 0 || limit > 20 {
		limit = 2
	}
	if since.IsZero() {
		since = time.Now().UTC().Add(-10 * time.Minute)
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectTestResultColumns+`
		 FROM project_test_results
		 WHERE project_id = ? AND asset_id = ?
		   AND status IN ('tested_clean', 'confirmed', 'blocked', 'suspicious', 'stopped', 'exhausted')
		   AND COALESCE(NULLIF(last_finished_at, 0), updated_at) >= ?
		 ORDER BY
			CASE WHEN last_finished_at > 0 THEN last_finished_at ELSE updated_at END DESC,
			updated_at DESC, id DESC
		 LIMIT ?`,
		projectID,
		assetID,
		since.UTC().Unix(),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectTestResult, 0, limit)
	for rows.Next() {
		item, scanErr := scanProjectTestResult(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ProjectAssetWorkBlocked(
	ctx context.Context,
	projectID string,
	assetID string,
) (bool, error) {
	projectID = strings.TrimSpace(projectID)
	assetID = strings.TrimSpace(assetID)
	if projectID == "" || assetID == "" {
		return false, nil
	}
	var state string
	err := db.QueryRowContext(
		ctx,
		`SELECT work_state FROM project_asset_work
		 WHERE project_id = ? AND asset_id = ?
		 LIMIT 1`,
		projectID,
		assetID,
	).Scan(&state)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(state)) {
	case AssetWorkBlocked, AssetWorkAwaitingUser:
		return true, nil
	default:
		return false, nil
	}
}

// BlockProjectAssetForAccessFailure atomically blocks the asset work item and
// every non-terminal intent that belongs to it.
func (db *DB) BlockProjectAssetForAccessFailure(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
	reason string,
) (int, error) {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	assetID = strings.TrimSpace(assetID)
	reason = strings.TrimSpace(reason)
	if projectID == "" || ownerUserID == "" || assetID == "" || reason == "" {
		return 0, fmt.Errorf("项目、用户、资产和阻断原因不能为空")
	}
	if err := db.SyncProjectAssetWork(ctx, projectID, ownerUserID); err != nil {
		return 0, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var state string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT work_state FROM project_asset_work
		 WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?`,
		projectID,
		ownerUserID,
		assetID,
	).Scan(&state); err != nil {
		return 0, err
	}
	switch strings.ToLower(strings.TrimSpace(state)) {
	case AssetWorkBlocked, AssetWorkAwaitingUser:
		return 0, nil
	}

	now := time.Now().UTC()
	result, err := tx.ExecContext(
		ctx,
		`UPDATE project_graph_nodes
		 SET status = 'blocked',
		     detail = CASE
		       WHEN TRIM(detail) = '' THEN ?
		       ELSE detail || char(10) || char(10) || ?
		     END,
		     updated_at = ?
		 WHERE project_id = ? AND asset_id = ? AND kind = 'intent'
		   AND status IN ('open', 'running', 'paused', 'blocked', 'capacity_blocked')`,
		reason,
		reason,
		now.Unix(),
		projectID,
		assetID,
	)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE project_asset_work
		 SET work_state = ?, state_reason = ?,
		     lease_owner = '', lease_conversation_id = '', lease_until = 0,
		     last_progress_at = ?, updated_at = ?
		 WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?`,
		AssetWorkBlocked,
		reason,
		now.Unix(),
		now.Unix(),
		projectID,
		ownerUserID,
		assetID,
	); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(affected), nil
}

func (db *DB) StopProjectAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
	reason string,
) (*ProjectAssetStopResult, error) {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	assetID = strings.TrimSpace(assetID)
	reason = strings.TrimSpace(reason)
	if projectID == "" || ownerUserID == "" || assetID == "" {
		return nil, fmt.Errorf("项目、用户和资产不能为空")
	}
	if reason == "" {
		reason = "用户停止资产探测"
	}
	if err := db.SyncProjectAssetWork(ctx, projectID, ownerUserID); err != nil {
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	var currentState string
	if err := tx.QueryRowContext(
		ctx,
		`SELECT work_state FROM project_asset_work
		 WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?`,
		projectID,
		ownerUserID,
		assetID,
	).Scan(&currentState); err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(currentState)) {
	case AssetWorkQueued, AssetWorkActive, AssetWorkTesting,
		AssetWorkNeedsFollowup, AssetWorkReopened:
	default:
		return nil, ErrAssetWorkNotStoppable
	}

	now := time.Now().UTC()
	testResult, err := tx.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'stopped', execution_state = 'stopped', outcome_state = 'unknown',
		     state_reason = ?, last_finished_at = ?, updated_at = ?
		 WHERE project_id = ? AND asset_id = ?
		   AND status IN ('untested', 'running', 'paused')`,
		AssetUserStopReason,
		now.Unix(),
		now.Unix(),
		projectID,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	stoppedTests, err := testResult.RowsAffected()
	if err != nil {
		return nil, err
	}
	intentResult, err := tx.ExecContext(
		ctx,
		`UPDATE project_graph_nodes
		 SET status = 'stopped',
		     detail = CASE
		       WHEN TRIM(detail) = '' THEN ?
		       ELSE detail || char(10) || char(10) || ?
		     END,
		     updated_at = ?
		 WHERE project_id = ? AND asset_id = ? AND kind = 'intent'
		   AND status IN ('open', 'running', 'paused', 'capacity_blocked')`,
		reason,
		reason,
		now.Unix(),
		projectID,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	stoppedIntents, err := intentResult.RowsAffected()
	if err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(
		ctx,
		`UPDATE project_asset_work
		 SET work_state = ?, state_reason = ?,
		     lease_owner = '', lease_conversation_id = '', lease_until = 0,
		     last_progress_at = ?, updated_at = ?
		 WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?`,
		AssetWorkBlocked,
		reason,
		now.Unix(),
		now.Unix(),
		projectID,
		ownerUserID,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil {
		return nil, rowsErr
	} else if affected == 0 {
		return nil, sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &ProjectAssetStopResult{
		AssetID:        assetID,
		StoppedIntents: stoppedIntents,
		StoppedTests:   stoppedTests,
	}, nil
}

func (db *DB) ReleaseProjectAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
	conversationID string,
	state string,
	reason string,
) error {
	state, ok := NormalizeAssetWorkState(state)
	if !ok {
		return fmt.Errorf("资产工作状态不合法")
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_asset_work
		 SET work_state = ?, state_reason = ?, lease_owner = '', lease_conversation_id = '',
		     lease_until = 0, last_progress_at = ?, updated_at = ?
		 WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?
		   AND (lease_conversation_id = ? OR lease_conversation_id = '')`,
		state,
		strings.TrimSpace(reason),
		now.Unix(),
		now.Unix(),
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(assetID),
		strings.TrimSpace(conversationID),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("资产工作项不存在或租约不属于当前会话")
	}
	return nil
}

func (db *DB) CompleteProjectAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
	conversationID string,
	reason string,
) error {
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_asset_work
		 SET work_state = 'complete', state_reason = '关闭门禁通过', closeout_reason = ?,
		     lease_owner = '', lease_conversation_id = '', lease_until = 0,
		     last_progress_at = ?, updated_at = ?
		 WHERE project_id = ? AND owner_user_id = ? AND asset_id = ?
		   AND (lease_conversation_id = ? OR lease_conversation_id = '')`,
		strings.TrimSpace(reason),
		now.Unix(),
		now.Unix(),
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		strings.TrimSpace(assetID),
		strings.TrimSpace(conversationID),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("资产工作项不存在或租约不属于当前会话")
	}
	return nil
}

func (db *DB) ReopenProjectAssetWork(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetID string,
	reason string,
) error {
	return db.UpdateProjectAssetWorkState(
		ctx,
		projectID,
		ownerUserID,
		assetID,
		AssetWorkReopened,
		reason,
	)
}

func scanProjectAssetWork(scanner interface{ Scan(...interface{}) error }) (ProjectAssetWork, error) {
	var item ProjectAssetWork
	var leaseUntil, lastProgress, createdAt, updatedAt int64
	err := scanner.Scan(
		&item.ProjectID,
		&item.OwnerUserID,
		&item.AssetID,
		&item.AssetName,
		&item.AssetKind,
		&item.AssetValue,
		&item.QualityStatus,
		&item.AssetStatus,
		&item.Criticality,
		&item.RiskScore,
		&item.AuthorizationState,
		&item.WorkState,
		&item.Priority,
		&item.StateReason,
		&item.LeaseOwner,
		&item.LeaseConversationID,
		&leaseUntil,
		&lastProgress,
		&item.CloseoutReason,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	item.LeaseUntil = unixTime(leaseUntil)
	item.LastProgressAt = unixTime(lastProgress)
	item.CreatedAt = unixTime(createdAt)
	item.UpdatedAt = unixTime(updatedAt)
	return item, nil
}

func scanProjectAssetWorkLease(scanner interface{ Scan(...interface{}) error }) (ProjectAssetWork, error) {
	var item ProjectAssetWork
	var leaseUntil, lastProgress, createdAt, updatedAt int64
	err := scanner.Scan(
		&item.ProjectID,
		&item.OwnerUserID,
		&item.AssetID,
		&item.AuthorizationState,
		&item.WorkState,
		&item.Priority,
		&item.StateReason,
		&item.LeaseOwner,
		&item.LeaseConversationID,
		&leaseUntil,
		&lastProgress,
		&item.CloseoutReason,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	item.LeaseUntil = unixTime(leaseUntil)
	item.LastProgressAt = unixTime(lastProgress)
	item.CreatedAt = unixTime(createdAt)
	item.UpdatedAt = unixTime(updatedAt)
	return item, nil
}

func isActionableAssetKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "ip", "domain", "url", "source":
		return true
	default:
		return false
	}
}

func isActiveAssetWork(item ProjectAssetWork) bool {
	return item.WorkState == AssetWorkActive ||
		item.WorkState == AssetWorkTesting ||
		item.WorkState == AssetWorkNeedsFollowup
}

func projectAssetWorkPriority(asset Asset) int {
	score := asset.RiskScore
	switch strings.ToLower(strings.TrimSpace(asset.Criticality)) {
	case "critical":
		score += 80
	case "high":
		score += 60
	case "medium":
		score += 30
	case "low":
		score += 10
	}
	return score
}

func assetAuthorizationState(projectScope string, asset Asset) string {
	if !isActionableAssetKind(asset.Kind) {
		return AssetAuthorizationOutOfScope
	}
	if strings.EqualFold(asset.Kind, "source") {
		return AssetAuthorizationAuthorized
	}
	scope := strings.TrimSpace(projectScope)
	if scope == "" {
		switch NormalizeAssetSource(asset.Source) {
		case AssetSourceScope, AssetSourceManual, AssetSourceBatch:
			return AssetAuthorizationAuthorized
		default:
			return AssetAuthorizationDiscovered
		}
	}
	if projectScopeAllowsAsset(scope, asset) {
		return AssetAuthorizationAuthorized
	}
	switch NormalizeAssetSource(asset.Source) {
	case AssetSourceScope, AssetSourceManual, AssetSourceBatch:
		return AssetAuthorizationDiscovered
	default:
		return AssetAuthorizationDiscovered
	}
}

func assetTestingEligible(projectScope string, asset Asset) bool {
	return coverageAssetEligible(asset) &&
		assetAuthorizationState(projectScope, asset) == AssetAuthorizationAuthorized
}

func projectScopeAllowsAsset(scope string, asset Asset) bool {
	items := ParseProjectScopeAssets(scope)
	if len(items) == 0 {
		return false
	}
	targets := assetScopeTargets(asset)
	for _, item := range items {
		for _, target := range targets {
			if scopeValueAllows(item.Value, target) {
				return true
			}
		}
	}
	return false
}

func assetScopeTargets(asset Asset) []string {
	values := uniqueStrings([]string{strings.TrimSpace(asset.Value), strings.TrimSpace(asset.Name)})
	if strings.EqualFold(asset.Kind, "url") {
		if parsed, err := url.Parse(asset.Value); err == nil && parsed.Hostname() != "" {
			values = append(values, parsed.Hostname())
		}
	}
	result := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = normalizeScopeTarget(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func normalizeScopeTarget(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.Trim(value, "<>")))
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.ToLower(strings.Trim(host, "[]"))
	}
	return strings.Trim(strings.TrimSuffix(value, "."), "[]")
}

func scopeValueAllows(scopeValue string, target string) bool {
	scopeValue = normalizeScopeTarget(scopeValue)
	target = normalizeScopeTarget(target)
	if scopeValue == "" || target == "" {
		return false
	}
	if _, network, err := net.ParseCIDR(scopeValue); err == nil {
		ip := net.ParseIP(target)
		return ip != nil && network.Contains(ip)
	}
	if strings.HasPrefix(scopeValue, "*.") {
		suffix := strings.TrimPrefix(scopeValue, "*")
		return strings.HasSuffix(target, suffix) && len(target) > len(suffix)
	}
	if scopeValue == target {
		return true
	}
	if strings.Contains(scopeValue, ".") {
		return strings.HasSuffix(target, "."+scopeValue)
	}
	return false
}
