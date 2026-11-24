package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type ProjectTestResult struct {
	ID                   string    `json:"id"`
	ProjectID            string    `json:"projectId"`
	AssetID              string    `json:"assetId"`
	Dimension            string    `json:"dimension"`
	Technique            string    `json:"technique"`
	Status               string    `json:"status"`
	ExecutionState       string    `json:"executionState"`
	OutcomeState         string    `json:"outcomeState"`
	StateReason          string    `json:"stateReason"`
	Result               string    `json:"result"`
	Evidence             string    `json:"evidence"`
	EvidenceRefs         []string  `json:"evidenceRefs"`
	Confidence           int       `json:"confidence"`
	FindingID            string    `json:"findingId"`
	IntentID             string    `json:"intentId"`
	OriginConversationID string    `json:"originConversationId"`
	OriginRunID          string    `json:"originRunId"`
	Rationale            string    `json:"rationale"`
	Expected             string    `json:"expectedEvidence"`
	Priority             int       `json:"priority"`
	ParentID             string    `json:"parentFindingId"`
	Attempts             int       `json:"attempts"`
	Required             bool      `json:"required"`
	LastWorkerSessionID  string    `json:"lastWorkerSessionId"`
	LastStartedAt        time.Time `json:"lastStartedAt"`
	LastFinishedAt       time.Time `json:"lastFinishedAt"`
	CreatedAt            time.Time `json:"createdAt"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

// AssetTestCoverage 是按资产聚合后的测试覆盖统计，不受列表分页上限影响。
type AssetTestCoverage struct {
	TestsTotal         int
	TestsCovered       int
	TestsConfirmed     int
	TestsOpen          int
	TestsBlocked       int
	TestsSuspicious    int
	RequiredTotal      int
	RequiredCovered    int
	RequiredOpen       int
	RequiredBlocked    int
	RequiredSuspicious int
}

var projectTestResultStatuses = map[string]bool{
	"untested":     true,
	"running":      true,
	"paused":       true,
	"tested_clean": true,
	"blocked":      true,
	"suspicious":   true,
	"confirmed":    true,
	"stopped":      true,
	"exhausted":    true,
}

const (
	ProjectExecutionOpen      = "open"
	ProjectExecutionRunning   = "running"
	ProjectExecutionPaused    = "paused"
	ProjectExecutionDone      = "done"
	ProjectExecutionStopped   = "stopped"
	ProjectExecutionExhausted = "exhausted"
	ProjectExecutionBlocked   = "blocked"

	ProjectOutcomeUnknown    = "unknown"
	ProjectOutcomeClean      = "clean"
	ProjectOutcomeSuspicious = "suspicious"
	ProjectOutcomeConfirmed  = "confirmed"

	ProjectHypothesisTransientRetryPrefix = "worker_transient_failure_retry"
	ProjectHypothesisServiceRestartPrefix = "worker_service_restart_retry"
)

func NormalizeProjectTestResultStatus(value string) (string, bool) {
	status := strings.ToLower(strings.TrimSpace(value))
	switch status {
	case "":
		status = "untested"
	case "open", "pending", "todo", "queued":
		status = "untested"
	case "working", "in_progress", "in-progress":
		status = "running"
	}
	return status, projectTestResultStatuses[status]
}

func NormalizeProjectExecutionState(value string) (string, bool) {
	switch state := strings.ToLower(strings.TrimSpace(value)); state {
	case "":
		return ProjectExecutionOpen, true
	case ProjectExecutionOpen,
		ProjectExecutionRunning,
		ProjectExecutionPaused,
		ProjectExecutionDone,
		ProjectExecutionStopped,
		ProjectExecutionExhausted,
		ProjectExecutionBlocked:
		return state, true
	default:
		return "", false
	}
}

func NormalizeProjectOutcomeState(value string) (string, bool) {
	switch state := strings.ToLower(strings.TrimSpace(value)); state {
	case "":
		return ProjectOutcomeUnknown, true
	case ProjectOutcomeUnknown,
		ProjectOutcomeClean,
		ProjectOutcomeSuspicious,
		ProjectOutcomeConfirmed:
		return state, true
	default:
		return "", false
	}
}

func projectExecutionStateFromStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "untested":
		return ProjectExecutionOpen
	case "running":
		return ProjectExecutionRunning
	case "paused":
		return ProjectExecutionPaused
	case "blocked":
		return ProjectExecutionBlocked
	case "stopped":
		return ProjectExecutionStopped
	case "exhausted":
		return ProjectExecutionExhausted
	case "tested_clean", "suspicious", "confirmed":
		return ProjectExecutionDone
	default:
		return ProjectExecutionOpen
	}
}

func projectOutcomeStateFromStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "tested_clean":
		return ProjectOutcomeClean
	case "suspicious":
		return ProjectOutcomeSuspicious
	case "confirmed":
		return ProjectOutcomeConfirmed
	default:
		return ProjectOutcomeUnknown
	}
}

func ProjectStatusFromExecution(executionState, outcomeState string) string {
	switch executionState {
	case ProjectExecutionOpen:
		return "untested"
	case ProjectExecutionRunning:
		return "running"
	case ProjectExecutionPaused:
		return "paused"
	case ProjectExecutionStopped:
		return "stopped"
	case ProjectExecutionExhausted:
		return "exhausted"
	case ProjectExecutionBlocked:
		return "blocked"
	case ProjectExecutionDone:
		switch outcomeState {
		case ProjectOutcomeConfirmed:
			return "confirmed"
		case ProjectOutcomeSuspicious:
			return "suspicious"
		default:
			return "tested_clean"
		}
	default:
		return "untested"
	}
}

const projectTestResultColumns = `id, project_id, asset_id, dimension, technique, status,
	execution_state, outcome_state, state_reason,
	result, evidence, evidence_refs, confidence, finding_id, intent_id,
	rationale, expected_evidence, priority, parent_finding_id, attempts, required,
	last_worker_session_id, last_started_at, last_finished_at, created_at, updated_at,
	origin_conversation_id, origin_run_id`

func scanProjectTestResult(scanner rowScanner) (ProjectTestResult, error) {
	var item ProjectTestResult
	var evidenceRefs string
	var lastStartedAt, lastFinishedAt int64
	var createdAt int64
	var updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.ProjectID,
		&item.AssetID,
		&item.Dimension,
		&item.Technique,
		&item.Status,
		&item.ExecutionState,
		&item.OutcomeState,
		&item.StateReason,
		&item.Result,
		&item.Evidence,
		&evidenceRefs,
		&item.Confidence,
		&item.FindingID,
		&item.IntentID,
		&item.Rationale,
		&item.Expected,
		&item.Priority,
		&item.ParentID,
		&item.Attempts,
		&item.Required,
		&item.LastWorkerSessionID,
		&lastStartedAt,
		&lastFinishedAt,
		&createdAt,
		&updatedAt,
		&item.OriginConversationID,
		&item.OriginRunID,
	)
	if err != nil {
		return item, err
	}
	item.EvidenceRefs = decodeEvidenceRefs(evidenceRefs)
	if lastStartedAt > 0 {
		item.LastStartedAt = time.Unix(lastStartedAt, 0).UTC()
	}
	if lastFinishedAt > 0 {
		item.LastFinishedAt = time.Unix(lastFinishedAt, 0).UTC()
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return item, nil
}

func (db *DB) UpsertProjectTestResult(
	ctx context.Context,
	item ProjectTestResult,
) (*ProjectTestResult, error) {
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.AssetID = strings.TrimSpace(item.AssetID)
	item.Dimension = strings.TrimSpace(item.Dimension)
	item.Technique = strings.TrimSpace(item.Technique)
	item.Result = strings.TrimSpace(item.Result)
	item.Evidence = strings.TrimSpace(item.Evidence)
	item.FindingID = strings.TrimSpace(item.FindingID)
	item.IntentID = strings.TrimSpace(item.IntentID)
	item.OriginConversationID = strings.TrimSpace(item.OriginConversationID)
	item.OriginRunID = strings.TrimSpace(item.OriginRunID)
	item.Rationale = strings.TrimSpace(item.Rationale)
	item.Expected = strings.TrimSpace(item.Expected)
	item.ParentID = strings.TrimSpace(item.ParentID)
	item.StateReason = strings.TrimSpace(item.StateReason)
	item.LastWorkerSessionID = strings.TrimSpace(item.LastWorkerSessionID)
	rawStatus := strings.TrimSpace(item.Status)
	rawExecution := strings.TrimSpace(item.ExecutionState)
	rawOutcome := strings.TrimSpace(item.OutcomeState)
	var (
		status      string
		execution   string
		outcome     string
		statusOK    bool
		executionOK bool
		outcomeOK   bool
	)
	if rawExecution == "" && rawOutcome == "" {
		status, statusOK = NormalizeProjectTestResultStatus(rawStatus)
		if !statusOK {
			return nil, fmt.Errorf("测试状态不合法")
		}
		execution = projectExecutionStateFromStatus(status)
		outcome = projectOutcomeStateFromStatus(status)
	} else {
		execution, executionOK = NormalizeProjectExecutionState(rawExecution)
		outcome, outcomeOK = NormalizeProjectOutcomeState(rawOutcome)
		if !executionOK || !outcomeOK {
			return nil, fmt.Errorf("测试执行状态或结果状态不合法")
		}
		status = ProjectStatusFromExecution(execution, outcome)
		if rawStatus != "" && rawStatus != status {
			if normalized, ok := NormalizeProjectTestResultStatus(rawStatus); ok &&
				normalized != "untested" && normalized != "running" {
				status = normalized
				execution = projectExecutionStateFromStatus(normalized)
				outcome = projectOutcomeStateFromStatus(normalized)
			}
		}
	}
	if item.ProjectID == "" || item.Dimension == "" {
		return nil, fmt.Errorf("项目和测试维度不能为空")
	}
	if item.Confidence < 0 {
		item.Confidence = 0
	}
	if item.Confidence > 100 {
		item.Confidence = 100
	}
	if item.Priority < 0 {
		item.Priority = 0
	}
	if item.Priority > 100 {
		item.Priority = 100
	}
	if item.Attempts < 0 {
		item.Attempts = 0
	}
	if !item.Required && strings.TrimSpace(item.ParentID) == "" {
		item.Required = true
	}
	evidenceRefs, err := encodeEvidenceRefs(item.EvidenceRefs)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if item.ID == "" {
		item.ID = newID()
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = now
	}
	if execution == ProjectExecutionRunning && item.LastStartedAt.IsZero() {
		item.LastStartedAt = now
	}
	if isTerminalExecutionState(execution) && item.LastFinishedAt.IsZero() {
		item.LastFinishedAt = now
	}
	item.Status = status
	item.ExecutionState = execution
	item.OutcomeState = outcome
	item.UpdatedAt = now
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO project_test_results (
			id, project_id, asset_id, dimension, technique, status,
			execution_state, outcome_state, state_reason, result,
			evidence, evidence_refs, confidence, finding_id, intent_id,
			rationale, expected_evidence, priority, parent_finding_id, attempts,
			required, last_worker_session_id, last_started_at, last_finished_at,
			created_at, updated_at, origin_conversation_id, origin_run_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, asset_id, dimension, technique) DO UPDATE SET
			status = CASE
				WHEN project_test_results.status IN ('tested_clean', 'confirmed', 'blocked', 'suspicious', 'stopped', 'exhausted')
					AND excluded.status IN ('untested', 'running')
				THEN project_test_results.status
				ELSE excluded.status
			END,
			execution_state = CASE
				WHEN project_test_results.execution_state IN ('done', 'blocked', 'stopped', 'exhausted')
					AND excluded.execution_state IN ('open', 'running')
				THEN project_test_results.execution_state
				ELSE excluded.execution_state
			END,
			outcome_state = CASE
				WHEN project_test_results.outcome_state = 'confirmed' THEN 'confirmed'
				WHEN project_test_results.outcome_state = 'suspicious' AND excluded.outcome_state IN ('unknown', 'clean')
				THEN 'suspicious'
				WHEN project_test_results.outcome_state = 'clean' AND excluded.outcome_state = 'unknown'
				THEN 'clean'
				ELSE excluded.outcome_state
			END,
			state_reason = CASE
				WHEN excluded.state_reason <> '' THEN excluded.state_reason
				ELSE project_test_results.state_reason
			END,
			result = CASE
				WHEN excluded.result = '' THEN project_test_results.result
				ELSE excluded.result
			END,
			evidence = CASE
				WHEN excluded.evidence = '' THEN project_test_results.evidence
				ELSE excluded.evidence
			END,
			evidence_refs = CASE
				WHEN excluded.evidence_refs IN ('', '[]') THEN project_test_results.evidence_refs
				ELSE excluded.evidence_refs
			END,
			confidence = CASE
				WHEN excluded.confidence > project_test_results.confidence THEN excluded.confidence
				ELSE project_test_results.confidence
			END,
			finding_id = CASE
				WHEN excluded.finding_id <> '' THEN excluded.finding_id
				ELSE project_test_results.finding_id
			END,
			intent_id = CASE
				WHEN excluded.intent_id <> '' THEN excluded.intent_id
				ELSE project_test_results.intent_id
			END,
			rationale = CASE
				WHEN excluded.rationale <> '' THEN excluded.rationale
				ELSE project_test_results.rationale
			END,
			expected_evidence = CASE
				WHEN excluded.expected_evidence <> '' THEN excluded.expected_evidence
				ELSE project_test_results.expected_evidence
			END,
			priority = CASE
				WHEN excluded.priority > project_test_results.priority THEN excluded.priority
				ELSE project_test_results.priority
			END,
			parent_finding_id = CASE
				WHEN excluded.parent_finding_id <> '' THEN excluded.parent_finding_id
				ELSE project_test_results.parent_finding_id
			END,
			attempts = CASE
				WHEN excluded.attempts > project_test_results.attempts THEN excluded.attempts
				ELSE project_test_results.attempts
			END,
			required = CASE
				WHEN project_test_results.required = 1 THEN 1
				ELSE excluded.required
			END,
			last_worker_session_id = CASE
				WHEN excluded.last_worker_session_id <> '' THEN excluded.last_worker_session_id
				ELSE project_test_results.last_worker_session_id
			END,
			last_started_at = CASE
				WHEN excluded.last_started_at > project_test_results.last_started_at
				THEN excluded.last_started_at
				ELSE project_test_results.last_started_at
			END,
			last_finished_at = CASE
				WHEN excluded.last_finished_at > project_test_results.last_finished_at
				THEN excluded.last_finished_at
				ELSE project_test_results.last_finished_at
			END,
			origin_conversation_id = CASE
				WHEN project_test_results.origin_conversation_id <> ''
				THEN project_test_results.origin_conversation_id
				ELSE excluded.origin_conversation_id
			END,
			origin_run_id = CASE
				WHEN project_test_results.origin_run_id <> ''
				THEN project_test_results.origin_run_id
				ELSE excluded.origin_run_id
			END,
			updated_at = excluded.updated_at`,
		item.ID,
		item.ProjectID,
		item.AssetID,
		item.Dimension,
		item.Technique,
		status,
		execution,
		outcome,
		item.StateReason,
		item.Result,
		item.Evidence,
		evidenceRefs,
		item.Confidence,
		item.FindingID,
		item.IntentID,
		item.Rationale,
		item.Expected,
		item.Priority,
		item.ParentID,
		item.Attempts,
		boolToInt(item.Required),
		item.LastWorkerSessionID,
		zeroTimeUnix(item.LastStartedAt),
		zeroTimeUnix(item.LastFinishedAt),
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
		item.OriginConversationID,
		item.OriginRunID,
	)
	if err != nil {
		return nil, err
	}
	return db.GetProjectTestResult(
		ctx,
		item.ProjectID,
		item.AssetID,
		item.Dimension,
		item.Technique,
	)
}

func (db *DB) GetProjectTestResult(
	ctx context.Context,
	projectID string,
	assetID string,
	dimension string,
	technique string,
) (*ProjectTestResult, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT `+projectTestResultColumns+`
		 FROM project_test_results
		 WHERE project_id = ? AND asset_id = ? AND dimension = ? AND technique = ?`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(assetID),
		strings.TrimSpace(dimension),
		strings.TrimSpace(technique),
	)
	item, err := scanProjectTestResult(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) ListProjectTestResults(
	ctx context.Context,
	projectID string,
	limit int,
) ([]ProjectTestResult, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("项目不能为空")
	}
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectTestResultColumns+`
		 FROM project_test_results
		 WHERE project_id = ?
		 ORDER BY updated_at DESC, id DESC
		 LIMIT ?`,
		projectID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectTestResult, 0)
	for rows.Next() {
		item, scanErr := scanProjectTestResult(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListProjectTestResultsByStatus 返回所有项目中指定状态的假设，用于启动时证据复核。
func (db *DB) ListProjectTestResultsByStatus(
	ctx context.Context,
	status string,
	limit int,
) ([]ProjectTestResult, error) {
	normalized, ok := NormalizeProjectTestResultStatus(status)
	if !ok {
		return nil, fmt.Errorf("测试状态不合法: %s", status)
	}
	if limit <= 0 || limit > 10000 {
		limit = 5000
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectTestResultColumns+`
		 FROM project_test_results
		 WHERE status = ?
		 ORDER BY updated_at DESC, id DESC
		 LIMIT ?`,
		normalized,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectTestResult, 0)
	for rows.Next() {
		item, scanErr := scanProjectTestResult(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListProjectTestResultsByAsset 返回单个资产的测试与假设，用于资产级上下文。
func (db *DB) ListProjectTestResultsByAsset(
	ctx context.Context,
	projectID string,
	assetID string,
	limit int,
) ([]ProjectTestResult, error) {
	projectID = strings.TrimSpace(projectID)
	assetID = strings.TrimSpace(assetID)
	if projectID == "" || assetID == "" {
		return nil, fmt.Errorf("项目和资产不能为空")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectTestResultColumns+`
		 FROM project_test_results
		 WHERE project_id = ? AND asset_id = ?
		 ORDER BY
			CASE status
				WHEN 'running' THEN 0
				WHEN 'suspicious' THEN 1
				WHEN 'blocked' THEN 2
				WHEN 'untested' THEN 3
				WHEN 'confirmed' THEN 4
				ELSE 5
			END,
			priority DESC,
			updated_at DESC,
			id DESC
		 LIMIT ?`,
		projectID,
		assetID,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectTestResult, 0)
	for rows.Next() {
		item, scanErr := scanProjectTestResult(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// AggregateProjectTestCoverage 按资产聚合全部测试结果，避免覆盖率统计被列表 LIMIT 截断。
func (db *DB) AggregateProjectTestCoverage(
	ctx context.Context,
	projectID string,
) (map[string]AssetTestCoverage, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("项目不能为空")
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT
			asset_id,
			COUNT(*),
			COALESCE(SUM(CASE
				WHEN status IN ('tested_clean', 'suspicious', 'confirmed') THEN 1
				ELSE 0
			END), 0),
			COALESCE(SUM(CASE WHEN status = 'confirmed' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status IN ('untested', 'running', 'paused') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN required = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE
				WHEN required = 1 AND status IN ('tested_clean', 'confirmed') THEN 1
				ELSE 0
			END), 0),
			COALESCE(SUM(CASE
				WHEN required = 1 AND status IN ('untested', 'running', 'paused') THEN 1
				ELSE 0
			END), 0),
			COALESCE(SUM(CASE
				WHEN required = 1 AND status = 'blocked' THEN 1
				ELSE 0
			END), 0),
			COALESCE(SUM(CASE
				WHEN required = 1 AND status = 'suspicious' THEN 1
				ELSE 0
			END), 0)
		 FROM project_test_results
		 WHERE project_id = ?
		 GROUP BY asset_id`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]AssetTestCoverage)
	for rows.Next() {
		var assetID string
		var item AssetTestCoverage
		if err := rows.Scan(
			&assetID,
			&item.TestsTotal,
			&item.TestsCovered,
			&item.TestsConfirmed,
			&item.TestsOpen,
			&item.TestsBlocked,
			&item.TestsSuspicious,
			&item.RequiredTotal,
			&item.RequiredCovered,
			&item.RequiredOpen,
			&item.RequiredBlocked,
			&item.RequiredSuspicious,
		); err != nil {
			return nil, err
		}
		if strings.TrimSpace(assetID) != "" {
			result[strings.TrimSpace(assetID)] = item
		}
	}
	return result, rows.Err()
}

func (db *DB) ListProjectHypotheses(
	ctx context.Context,
	projectID string,
	status string,
	limit int,
) ([]ProjectTestResult, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("项目不能为空")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	status = strings.ToLower(strings.TrimSpace(status))
	query := `SELECT ` + projectTestResultColumns + `
		FROM project_test_results
		WHERE project_id = ?
		  AND (
		    execution_state IN ('open', 'running', 'paused')
		    OR status IN ('untested', 'running', 'paused', 'suspicious')
		  )`
	args := []interface{}{projectID}
	if status != "" {
		if _, ok := NormalizeProjectTestResultStatus(status); !ok {
			return nil, fmt.Errorf("测试状态不合法")
		}
		query = `SELECT ` + projectTestResultColumns + `
			FROM project_test_results
			WHERE project_id = ? AND (status = ? OR execution_state = ?)`
		args = append(args, status)
		if execution, ok := NormalizeProjectExecutionState(status); ok {
			args = append(args, execution)
		} else {
			args = append(args, status)
		}
	}
	query += ` ORDER BY
		CASE execution_state
			WHEN 'running' THEN 0
			WHEN 'open' THEN 1
			WHEN 'paused' THEN 2
			ELSE 3
		END,
		priority DESC, updated_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectTestResult, 0)
	for rows.Next() {
		item, scanErr := scanProjectTestResult(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListActiveProjectHypotheses returns all open/running/paused hypotheses for
// planner deduplication without a pagination cap.
func (db *DB) ListActiveProjectHypotheses(
	ctx context.Context,
	projectID string,
) ([]ProjectTestResult, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("项目不能为空")
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT `+projectTestResultColumns+`
		 FROM project_test_results
		 WHERE project_id = ?
		   AND execution_state IN ('open', 'running', 'paused')`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ProjectTestResult, 0)
	for rows.Next() {
		item, scanErr := scanProjectTestResult(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetProjectTestResultByID(
	ctx context.Context,
	projectID string,
	id string,
) (*ProjectTestResult, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT `+projectTestResultColumns+`
		 FROM project_test_results
		 WHERE project_id = ? AND id = ?`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(id),
	)
	item, err := scanProjectTestResult(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) StartProjectHypothesis(
	ctx context.Context,
	projectID string,
	id string,
) (*ProjectTestResult, error) {
	item, err := db.GetProjectTestResultByID(ctx, projectID, id)
	if err != nil {
		return nil, err
	}
	if IsProjectTestResultTerminal(item.Status) {
		return nil, fmt.Errorf("测试已结束，不能重复开始")
	}
	item.Status = "running"
	item.ExecutionState = ProjectExecutionRunning
	item.StateReason = ""
	item.Attempts++
	item.LastStartedAt = time.Now().UTC()
	item.UpdatedAt = time.Now().UTC()
	return db.UpsertProjectTestResult(ctx, *item)
}

// ClaimNextProjectHypothesis atomically moves the highest-priority untested
// hypothesis to running so concurrent workers cannot claim the same work.
func (db *DB) ClaimNextProjectHypothesis(
	ctx context.Context,
	projectID string,
) (*ProjectTestResult, error) {
	return db.claimNextProjectHypothesis(ctx, projectID, "")
}

func (db *DB) ClaimNextProjectHypothesisForConversation(
	ctx context.Context,
	projectID string,
	conversationID string,
) (*ProjectTestResult, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return nil, nil
	}
	return db.claimNextProjectHypothesis(ctx, projectID, conversationID)
}

func (db *DB) claimNextProjectHypothesis(
	ctx context.Context,
	projectID string,
	originConversationID string,
) (*ProjectTestResult, error) {
	now := time.Now().UTC()
	originFilter := ""
	if strings.TrimSpace(originConversationID) != "" {
		originFilter = " AND candidate.origin_conversation_id = ?"
	}
	query := `UPDATE project_test_results
		 SET status = 'running',
		     execution_state = 'running',
		     state_reason = CASE
		         WHEN state_reason LIKE ? OR state_reason LIKE ? THEN state_reason
		         ELSE ''
		     END,
		     attempts = attempts + 1,
		     last_started_at = ?,
		     updated_at = ?
		 WHERE id = (
			SELECT candidate.id FROM project_test_results AS candidate
			WHERE candidate.project_id = ?
			  ` + originFilter + `
			  AND (candidate.execution_state = 'open' OR candidate.status = 'untested')
			ORDER BY (
				candidate.priority + MIN(
					30,
					MAX(
						0,
						(CAST(strftime('%s','now') AS INTEGER) - candidate.created_at) / 600
					)
				)
			) DESC,
				candidate.created_at ASC,
				candidate.id ASC
			LIMIT 1
		 )
		 RETURNING ` + projectTestResultColumns
	args := []interface{}{
		ProjectHypothesisTransientRetryPrefix + "%",
		ProjectHypothesisServiceRestartPrefix + "%",
		now.Unix(),
		now.Unix(),
		strings.TrimSpace(projectID),
	}
	if strings.TrimSpace(originConversationID) != "" {
		args = append(args, strings.TrimSpace(originConversationID))
	}
	row := db.QueryRowContext(ctx, query, args...)
	item, err := scanProjectTestResult(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

// IncrementProjectHypothesisExecutionAttempt records each additional sub-agent
// execution within the same claimed hypothesis.
func (db *DB) IncrementProjectHypothesisExecutionAttempt(
	ctx context.Context,
	id string,
) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET attempts = attempts + 1,
		     updated_at = ?
		 WHERE id = ?
		   AND (execution_state = 'running' OR status = 'running')`,
		time.Now().UTC().Unix(),
		strings.TrimSpace(id),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("假设已不在运行状态，不能增加执行次数")
	}
	return nil
}

// ResetProjectHypothesisIfRunning 释放没有 Worker 继续持有的假设，保留尝试次数和已有证据。
func (db *DB) ResetProjectHypothesisIfRunning(
	ctx context.Context,
	id string,
	reason string,
) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	reason = strings.TrimSpace(reason)
	now := time.Now().UTC()
	_, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'untested',
		     execution_state = 'open',
		     state_reason = ?,
		     evidence = CASE
		         WHEN ? = '' OR instr(evidence, ?) > 0 THEN evidence
		         WHEN evidence = '' THEN ?
		         ELSE evidence || char(10) || char(10) || ?
		     END,
		     updated_at = ?
		 WHERE id = ?
		   AND (execution_state = 'running' OR status = 'running')`,
		reason,
		reason,
		reason,
		reason,
		reason,
		now.Unix(),
		id,
	)
	return err
}

// ResetRunningProjectHypotheses 在服务启动时释放上一次进程遗留的 running 假设。
func (db *DB) ResetRunningProjectHypotheses(
	ctx context.Context,
	reason string,
) (int64, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = ProjectHypothesisServiceRestartPrefix + ": 服务重启导致 Worker 中断，已释放为待重试"
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'untested',
		     execution_state = 'open',
		     state_reason = ?,
		     evidence = CASE
		         WHEN instr(evidence, ?) > 0 THEN evidence
		         WHEN evidence = '' THEN ?
		         ELSE evidence || char(10) || char(10) || ?
		     END,
		     updated_at = ?
		 WHERE execution_state = 'running' OR status = 'running'`,
		reason,
		reason,
		reason,
		reason,
		now.Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) PauseRunningProjectHypotheses(
	ctx context.Context,
	projectID string,
	reason string,
) (int64, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "任务暂停，Worker 已释放为可恢复状态"
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'paused',
		     execution_state = 'paused',
		     state_reason = ?,
		     updated_at = ?
		 WHERE project_id = ?
		   AND (execution_state = 'running' OR status = 'running')`,
		reason,
		time.Now().UTC().Unix(),
		strings.TrimSpace(projectID),
	)
	if err != nil {
		return 0, err
	}
	_, _ = db.ExecContext(
		ctx,
		`UPDATE project_graph_nodes
		 SET status = 'paused', updated_at = ?
		 WHERE project_id = ? AND kind = 'intent'
		   AND id IN (
		     SELECT intent_id FROM project_test_results
		     WHERE project_id = ? AND execution_state = 'paused' AND intent_id <> ''
		   )`,
		time.Now().UTC().Unix(),
		strings.TrimSpace(projectID),
		strings.TrimSpace(projectID),
	)
	return result.RowsAffected()
}

func (db *DB) ResumePausedProjectHypotheses(
	ctx context.Context,
	projectID string,
	stateReasonPrefixes ...string,
) (int64, error) {
	projectID = strings.TrimSpace(projectID)
	reasonPrefix := ""
	if len(stateReasonPrefixes) > 0 {
		reasonPrefix = strings.TrimSpace(stateReasonPrefixes[0])
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(
		ctx,
		`SELECT intent_id FROM project_test_results
		 WHERE project_id = ?
		   AND (execution_state = 'paused' OR status = 'paused')
		   AND (? = '' OR instr(state_reason, ?) = 1)
		   AND intent_id <> ''`,
		projectID,
		reasonPrefix,
		reasonPrefix,
	)
	if err != nil {
		return 0, err
	}
	intentIDs := make([]string, 0)
	for rows.Next() {
		var intentID string
		if err := rows.Scan(&intentID); err != nil {
			_ = rows.Close()
			return 0, err
		}
		if intentID = strings.TrimSpace(intentID); intentID != "" {
			intentIDs = append(intentIDs, intentID)
		}
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	result, err := tx.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'untested',
		     execution_state = 'open',
		     state_reason = '',
		     updated_at = ?
		 WHERE project_id = ?
		   AND (execution_state = 'paused' OR status = 'paused')
		   AND (? = '' OR instr(state_reason, ?) = 1)`,
		time.Now().UTC().Unix(),
		projectID,
		reasonPrefix,
		reasonPrefix,
	)
	if err != nil {
		return 0, err
	}
	if len(intentIDs) > 0 {
		args := buildIDArgs([]interface{}{time.Now().UTC().Unix(), projectID}, intentIDs)
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE project_graph_nodes
			 SET status = 'open', updated_at = ?
			 WHERE project_id = ? AND kind = 'intent'
			   AND id IN (`+placeholders(len(intentIDs))+`)`,
			args...,
		); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	affected, _ := result.RowsAffected()
	return affected, nil
}

func (db *DB) StopRunningProjectHypotheses(
	ctx context.Context,
	projectID string,
	reason string,
) (int64, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "用户停止任务"
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'stopped',
		     execution_state = 'stopped',
		     state_reason = ?,
		     last_finished_at = ?,
		     updated_at = ?
		 WHERE project_id = ?
		   AND (execution_state IN ('running', 'paused') OR status IN ('running', 'paused'))`,
		reason,
		now.Unix(),
		now.Unix(),
		strings.TrimSpace(projectID),
	)
	if err != nil {
		return 0, err
	}
	_, _ = db.ExecContext(
		ctx,
		`UPDATE project_graph_nodes
		 SET status = 'stopped', updated_at = ?
		 WHERE project_id = ? AND kind = 'intent'
		   AND id IN (
		     SELECT intent_id FROM project_test_results
		     WHERE project_id = ? AND execution_state = 'stopped' AND intent_id <> ''
		   )`,
		now.Unix(),
		strings.TrimSpace(projectID),
		strings.TrimSpace(projectID),
	)
	return result.RowsAffected()
}

func (db *DB) CountProjectHypotheses(ctx context.Context, projectID string) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_test_results
		 WHERE project_id = ?
		   AND (
		     execution_state IN ('open', 'running', 'paused')
		     OR status IN ('untested', 'running', 'paused', 'suspicious')
		   )`,
		strings.TrimSpace(projectID),
	).Scan(&count)
	return count, err
}

func (db *DB) CountActiveProjectHypotheses(
	ctx context.Context,
	projectID string,
) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_test_results
		 WHERE project_id = ?
		   AND (
		     execution_state IN ('open', 'running', 'paused')
		     OR status IN ('untested', 'running', 'paused')
		   )`,
		strings.TrimSpace(projectID),
	).Scan(&count)
	return count, err
}

func (db *DB) CountActiveProjectHypothesesForConversation(
	ctx context.Context,
	projectID string,
	conversationID string,
) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_test_results
		 WHERE project_id = ?
		   AND origin_conversation_id = ?
		   AND (
		     execution_state IN ('open', 'running', 'paused')
		     OR status IN ('untested', 'running', 'paused')
		   )`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(conversationID),
	).Scan(&count)
	return count, err
}

func (db *DB) CountActiveRequiredProjectHypothesesForConversation(
	ctx context.Context,
	projectID string,
	conversationID string,
) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_test_results
		 WHERE project_id = ?
		   AND origin_conversation_id = ?
		   AND required = 1
		   AND (
		     execution_state IN ('open', 'running', 'paused')
		     OR status IN ('untested', 'running', 'paused')
		   )`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(conversationID),
	).Scan(&count)
	return count, err
}

func (db *DB) PauseRunningProjectHypothesesForConversation(
	ctx context.Context,
	projectID string,
	conversationID string,
	reason string,
) (int64, error) {
	projectID = strings.TrimSpace(projectID)
	conversationID = strings.TrimSpace(conversationID)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "任务暂停，Worker 已释放为可恢复状态"
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'paused',
		     execution_state = 'paused',
		     state_reason = ?,
		     updated_at = ?
		 WHERE project_id = ?
		   AND origin_conversation_id = ?
		   AND (execution_state = 'running' OR status = 'running')`,
		reason,
		now.Unix(),
		projectID,
		conversationID,
	)
	if err != nil {
		return 0, err
	}
	_, _ = db.ExecContext(
		ctx,
		`UPDATE project_graph_nodes
		 SET status = 'paused', updated_at = ?
		 WHERE project_id = ? AND kind = 'intent'
		   AND id IN (
		     SELECT intent_id FROM project_test_results
		     WHERE project_id = ? AND origin_conversation_id = ?
		       AND execution_state = 'paused' AND intent_id <> ''
		   )`,
		now.Unix(),
		projectID,
		projectID,
		conversationID,
	)
	return result.RowsAffected()
}

func (db *DB) ResumePausedProjectHypothesesForConversation(
	ctx context.Context,
	projectID string,
	conversationID string,
	stateReasonPrefixes ...string,
) (int64, error) {
	projectID = strings.TrimSpace(projectID)
	conversationID = strings.TrimSpace(conversationID)
	reasonPrefix := ""
	if len(stateReasonPrefixes) > 0 {
		reasonPrefix = strings.TrimSpace(stateReasonPrefixes[0])
	}
	now := time.Now().UTC()
	rows, err := db.QueryContext(
		ctx,
		`SELECT intent_id FROM project_test_results
		 WHERE project_id = ?
		   AND origin_conversation_id = ?
		   AND (execution_state = 'paused' OR status = 'paused')
		   AND (? = '' OR instr(state_reason, ?) = 1)
		   AND intent_id <> ''`,
		projectID,
		conversationID,
		reasonPrefix,
		reasonPrefix,
	)
	if err != nil {
		return 0, err
	}
	intentIDs := make([]string, 0)
	for rows.Next() {
		var intentID string
		if err := rows.Scan(&intentID); err != nil {
			_ = rows.Close()
			return 0, err
		}
		if intentID = strings.TrimSpace(intentID); intentID != "" {
			intentIDs = append(intentIDs, intentID)
		}
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'untested',
		     execution_state = 'open',
		     state_reason = '',
		     updated_at = ?
		 WHERE project_id = ?
		   AND origin_conversation_id = ?
		   AND (execution_state = 'paused' OR status = 'paused')
		   AND (? = '' OR instr(state_reason, ?) = 1)`,
		now.Unix(),
		projectID,
		conversationID,
		reasonPrefix,
		reasonPrefix,
	)
	if err != nil {
		return 0, err
	}
	if len(intentIDs) > 0 {
		args := buildIDArgs([]interface{}{now.Unix(), projectID}, intentIDs)
		if _, err := db.ExecContext(
			ctx,
			`UPDATE project_graph_nodes
			 SET status = 'open', updated_at = ?
			 WHERE project_id = ? AND kind = 'intent'
			   AND id IN (`+placeholders(len(intentIDs))+`)`,
			args...,
		); err != nil {
			return 0, err
		}
	}
	return result.RowsAffected()
}

func (db *DB) StopRunningProjectHypothesesForConversation(
	ctx context.Context,
	projectID string,
	conversationID string,
	reason string,
) (int64, error) {
	projectID = strings.TrimSpace(projectID)
	conversationID = strings.TrimSpace(conversationID)
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "用户停止任务"
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'stopped',
		     execution_state = 'stopped',
		     state_reason = ?,
		     last_finished_at = ?,
		     updated_at = ?
		 WHERE project_id = ?
		   AND origin_conversation_id = ?
		   AND (execution_state IN ('running', 'paused') OR status IN ('running', 'paused'))`,
		reason,
		now.Unix(),
		now.Unix(),
		projectID,
		conversationID,
	)
	if err != nil {
		return 0, err
	}
	_, _ = db.ExecContext(
		ctx,
		`UPDATE project_graph_nodes
		 SET status = 'stopped', updated_at = ?
		 WHERE project_id = ? AND kind = 'intent'
		   AND id IN (
		     SELECT intent_id FROM project_test_results
		     WHERE project_id = ? AND origin_conversation_id = ?
		       AND execution_state = 'stopped' AND intent_id <> ''
		   )`,
		now.Unix(),
		projectID,
		projectID,
		conversationID,
	)
	return result.RowsAffected()
}

func (db *DB) ReassignActiveProjectHypothesesToConversation(
	ctx context.Context,
	projectID string,
	conversationID string,
	runID string,
) (int64, error) {
	projectID = strings.TrimSpace(projectID)
	conversationID = strings.TrimSpace(conversationID)
	runID = strings.TrimSpace(runID)
	if projectID == "" || conversationID == "" {
		return 0, fmt.Errorf("项目和会话不能为空")
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET origin_conversation_id = ?,
		     origin_run_id = CASE WHEN ? <> '' THEN ? ELSE origin_run_id END,
		     updated_at = ?
		 WHERE project_id = ?
		   AND (
		     execution_state IN ('open', 'paused')
		     OR status IN ('untested', 'paused')
		   )`,
		conversationID,
		runID,
		runID,
		time.Now().UTC().Unix(),
		projectID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) ReassignPausedLegacyProjectHypothesesToConversation(
	ctx context.Context,
	projectID string,
	conversationID string,
	runID string,
) (int64, error) {
	projectID = strings.TrimSpace(projectID)
	conversationID = strings.TrimSpace(conversationID)
	runID = strings.TrimSpace(runID)
	if projectID == "" || conversationID == "" {
		return 0, fmt.Errorf("项目和会话不能为空")
	}
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET origin_conversation_id = ?,
		     origin_run_id = CASE WHEN ? <> '' THEN ? ELSE origin_run_id END,
		     updated_at = ?
		 WHERE project_id = ?
		   AND origin_conversation_id = ''
		   AND (execution_state = 'paused' OR status = 'paused')`,
		conversationID,
		runID,
		runID,
		time.Now().UTC().Unix(),
		projectID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (db *DB) CountRunningProjectHypotheses(
	ctx context.Context,
	projectID string,
) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_test_results
		 WHERE project_id = ?
		   AND (execution_state = 'running' OR status = 'running')`,
		strings.TrimSpace(projectID),
	).Scan(&count)
	return count, err
}

func IsProjectTestResultCovered(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "tested_clean", "suspicious", "confirmed":
		return true
	default:
		return false
	}
}

func IsProjectTestResultTerminal(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "tested_clean", "confirmed", "blocked", "suspicious", "stopped", "exhausted":
		return true
	default:
		return false
	}
}

func isTerminalExecutionState(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case ProjectExecutionDone,
		ProjectExecutionBlocked,
		ProjectExecutionStopped,
		ProjectExecutionExhausted:
		return true
	default:
		return false
	}
}

func zeroTimeUnix(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}
