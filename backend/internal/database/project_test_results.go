package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type ProjectTestResult struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"projectId"`
	AssetID      string    `json:"assetId"`
	Dimension    string    `json:"dimension"`
	Technique    string    `json:"technique"`
	Status       string    `json:"status"`
	Result       string    `json:"result"`
	Evidence     string    `json:"evidence"`
	EvidenceRefs []string  `json:"evidenceRefs"`
	Confidence   int       `json:"confidence"`
	FindingID    string    `json:"findingId"`
	IntentID     string    `json:"intentId"`
	Rationale    string    `json:"rationale"`
	Expected     string    `json:"expectedEvidence"`
	Priority     int       `json:"priority"`
	ParentID     string    `json:"parentFindingId"`
	Attempts     int       `json:"attempts"`
	Required     bool      `json:"required"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
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
	"tested_clean": true,
	"blocked":      true,
	"suspicious":   true,
	"confirmed":    true,
}

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

const projectTestResultColumns = `id, project_id, asset_id, dimension, technique, status,
	result, evidence, evidence_refs, confidence, finding_id, intent_id,
	rationale, expected_evidence, priority, parent_finding_id, attempts, required,
	created_at, updated_at`

func scanProjectTestResult(scanner rowScanner) (ProjectTestResult, error) {
	var item ProjectTestResult
	var evidenceRefs string
	var createdAt int64
	var updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.ProjectID,
		&item.AssetID,
		&item.Dimension,
		&item.Technique,
		&item.Status,
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
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	item.EvidenceRefs = decodeEvidenceRefs(evidenceRefs)
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
	item.Rationale = strings.TrimSpace(item.Rationale)
	item.Expected = strings.TrimSpace(item.Expected)
	item.ParentID = strings.TrimSpace(item.ParentID)
	status, ok := NormalizeProjectTestResultStatus(item.Status)
	if !ok {
		return nil, fmt.Errorf("测试状态不合法")
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
	item.UpdatedAt = now
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO project_test_results (
			id, project_id, asset_id, dimension, technique, status, result,
			evidence, evidence_refs, confidence, finding_id, intent_id,
			rationale, expected_evidence, priority, parent_finding_id, attempts,
			required, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, asset_id, dimension, technique) DO UPDATE SET
			status = CASE
				WHEN project_test_results.status IN ('tested_clean', 'confirmed', 'blocked', 'suspicious')
					AND excluded.status IN ('untested', 'running')
				THEN project_test_results.status
				ELSE excluded.status
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
			updated_at = excluded.updated_at`,
		item.ID,
		item.ProjectID,
		item.AssetID,
		item.Dimension,
		item.Technique,
		status,
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
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
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
			COALESCE(SUM(CASE WHEN status IN ('untested', 'running') THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN required = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE
				WHEN required = 1 AND status IN ('tested_clean', 'confirmed') THEN 1
				ELSE 0
			END), 0),
			COALESCE(SUM(CASE
				WHEN required = 1 AND status IN ('untested', 'running') THEN 1
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
		WHERE project_id = ? AND status IN ('untested', 'running', 'suspicious')`
	args := []interface{}{projectID}
	if status != "" {
		if _, ok := NormalizeProjectTestResultStatus(status); !ok {
			return nil, fmt.Errorf("测试状态不合法")
		}
		query = `SELECT ` + projectTestResultColumns + `
			FROM project_test_results
			WHERE project_id = ? AND status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY priority DESC, updated_at DESC, id DESC LIMIT ?`
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
	item.Attempts++
	item.UpdatedAt = time.Now().UTC()
	return db.UpsertProjectTestResult(ctx, *item)
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
		     evidence = CASE
		         WHEN ? = '' OR instr(evidence, ?) > 0 THEN evidence
		         WHEN evidence = '' THEN ?
		         ELSE evidence || char(10) || char(10) || ?
		     END,
		     updated_at = ?
		 WHERE id = ? AND status = 'running'`,
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
		reason = "服务重启导致 Worker 中断，已释放为待重试"
	}
	now := time.Now().UTC()
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_test_results
		 SET status = 'untested',
		     evidence = CASE
		         WHEN instr(evidence, ?) > 0 THEN evidence
		         WHEN evidence = '' THEN ?
		         ELSE evidence || char(10) || char(10) || ?
		     END,
		     updated_at = ?
		 WHERE status = 'running'`,
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

func (db *DB) CountProjectHypotheses(ctx context.Context, projectID string) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_test_results
		 WHERE project_id = ?
		   AND status IN ('untested', 'running', 'suspicious')`,
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
	case "tested_clean", "confirmed", "blocked", "suspicious":
		return true
	default:
		return false
	}
}
