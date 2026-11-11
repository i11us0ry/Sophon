package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var cleanupFactDateSuffix = regexp.MustCompile(`[\(\[]?20\d{6}[\)\]]?$`)

type ProjectMemoryCleanupStats struct {
	ArchivedTestResultFacts int `json:"archivedTestResultFacts"`
	ArchivedFindingFacts    int `json:"archivedFindingFacts"`
	SkippedTestResultFacts  int `json:"skippedTestResultFacts"`
	SkippedFindingFacts     int `json:"skippedFindingFacts"`
	MergedGroups            int `json:"mergedGroups"`
	ArchivedDuplicateFacts  int `json:"archivedDuplicateFacts"`
	GraphFactNodesBefore    int `json:"graphFactNodesBefore"`
	GraphFactNodesAfter     int `json:"graphFactNodesAfter"`
}

// CleanupProjectMemory 归档跨表重复事实、合并日期/措辞变体并重建攻击路径事实投影。
// 原始事实不会被物理删除；被合并或归档的记录通过 valid_to / superseded_by 保留。
func (db *DB) CleanupProjectMemory(
	ctx context.Context,
	projectID string,
) (*ProjectMemoryCleanupStats, error) {
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return nil, fmt.Errorf("project_id 不能为空")
	}
	stats := &ProjectMemoryCleanupStats{}
	now := time.Now().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := cleanupProjectFactsTx(ctx, tx, projectID, now, stats); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	activeFacts, err := db.ListProjectFacts(ctx, projectID)
	if err != nil {
		return nil, err
	}

	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes
		 WHERE project_id = ? AND kind = 'fact' AND source = 'auto-sync'`,
		projectID,
	).Scan(&stats.GraphFactNodesBefore); err != nil {
		return nil, err
	}
	keepFacts := projectFactsForGraph(activeFacts)
	if err := db.deleteAutoSyncFactNodes(ctx, projectID); err != nil {
		return nil, err
	}
	for _, fact := range keepFacts {
		detail := strings.TrimSpace(fact.Body)
		if detail == "" {
			detail = fact.Summary
		}
		if _, err := db.UpsertProjectGraphNode(ctx, GraphNode{
			ID:          newID(),
			ProjectID:   projectID,
			Kind:        "fact",
			Title:       fact.Key,
			Detail:      detail,
			Status:      "confirmed",
			Confidence:  fact.Confidence,
			AssetID:     fact.AssetID,
			Source:      "auto-sync",
			SourceRefID: fact.ID,
			CreatedAt:   now,
			UpdatedAt:   now,
		}); err != nil {
			return nil, err
		}
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes
		 WHERE project_id = ? AND kind = 'fact' AND source = 'auto-sync'`,
		projectID,
	).Scan(&stats.GraphFactNodesAfter); err != nil {
		return nil, err
	}
	var ownerUserID string
	if err := db.QueryRowContext(
		ctx,
		`SELECT owner_user_id FROM projects WHERE id = ?`,
		projectID,
	).Scan(&ownerUserID); err != nil {
		return nil, err
	}
	if project, projectErr := db.GetProject(ctx, projectID, ownerUserID); projectErr == nil {
		_, _ = db.SyncProjectGraph(ctx, *project)
	}
	if err := db.pruneProjectGraphSingleEdges(ctx, projectID); err != nil {
		return nil, err
	}
	return stats, nil
}

func cleanupProjectFactsTx(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	now time.Time,
	stats *ProjectMemoryCleanupStats,
) error {
	rules := []struct {
		factType  string
		archived  *int
		skipped   *int
		verifySQL string
	}{
		{
			factType: "test_result",
			archived: &stats.ArchivedTestResultFacts,
			skipped:  &stats.SkippedTestResultFacts,
			verifySQL: `SELECT EXISTS(
				SELECT 1 FROM project_test_results
				WHERE project_id = ? AND (? = '' OR asset_id = ?)
				LIMIT 1
			)`,
		},
		{
			factType: "finding",
			archived: &stats.ArchivedFindingFacts,
			skipped:  &stats.SkippedFindingFacts,
			verifySQL: `SELECT EXISTS(
				SELECT 1 FROM vulnerabilities
				WHERE project_id = ? AND (? = '' OR asset_id = ?)
				LIMIT 1
			)`,
		},
	}
	for _, rule := range rules {
		rows, err := tx.QueryContext(
			ctx,
			`SELECT id, asset_id FROM project_facts
			 WHERE project_id = ? AND fact_type = ?
			   AND valid_to = 0 AND superseded_by = ''`,
			projectID,
			rule.factType,
		)
		if err != nil {
			return err
		}
		type candidate struct {
			id      string
			assetID string
		}
		candidates := make([]candidate, 0)
		for rows.Next() {
			var item candidate
			if err := rows.Scan(&item.id, &item.assetID); err != nil {
				_ = rows.Close()
				return err
			}
			candidates = append(candidates, item)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()
		for _, item := range candidates {
			var verified bool
			if err := tx.QueryRowContext(
				ctx,
				rule.verifySQL,
				projectID,
				item.assetID,
				item.assetID,
			).Scan(&verified); err != nil {
				return err
			}
			if !verified {
				*rule.skipped++
				continue
			}
			if _, err := tx.ExecContext(
				ctx,
				`UPDATE project_facts
				 SET valid_to = ?, updated_at = ?
				 WHERE id = ?`,
				now.Unix(),
				now.Unix(),
				item.id,
			); err != nil {
				return err
			}
			*rule.archived++
		}
	}

	rows, err := tx.QueryContext(
		ctx,
		`SELECT `+projectFactSelectColumns+`
		 FROM project_facts
		 WHERE project_id = ? AND valid_to = 0
		 ORDER BY updated_at DESC`,
		projectID,
	)
	if err != nil {
		return err
	}
	facts := make([]ProjectFact, 0)
	for rows.Next() {
		fact, scanErr := scanProjectFact(rows)
		if scanErr != nil {
			_ = rows.Close()
			return scanErr
		}
		facts = append(facts, fact)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	groups := make(map[string][]ProjectFact)
	for _, fact := range facts {
		groups[cleanupFactGroupKey(fact)] = append(groups[cleanupFactGroupKey(fact)], fact)
	}
	for _, items := range groups {
		if len(items) < 2 {
			continue
		}
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].Confidence != items[j].Confidence {
				return items[i].Confidence > items[j].Confidence
			}
			if items[i].Priority != items[j].Priority {
				return items[i].Priority > items[j].Priority
			}
			return items[i].UpdatedAt.After(items[j].UpdatedAt)
		})
		winner := items[0]
		mergedBody := strings.TrimSpace(winner.Body)
		mergedEvidence := strings.TrimSpace(winner.Evidence)
		pinned := winner.Pinned
		confidence := winner.Confidence
		priority := winner.Priority
		importance := winner.Importance
		canonicalKey := cleanupCanonicalKey(winner.Key, winner.FactType, winner.MemoryKind)
		for _, loser := range items[1:] {
			if loser.Confidence > confidence {
				confidence = loser.Confidence
			}
			if loser.Priority > priority {
				priority = loser.Priority
			}
			if loser.Importance > importance {
				importance = loser.Importance
			}
			pinned = pinned || loser.Pinned
			mergedBody = appendCleanupText(mergedBody, loser.Summary, loser.Body)
			mergedEvidence = appendCleanupEvidence(mergedEvidence, loser.Evidence)
		}
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE project_facts
			 SET value = ?, summary = ?, body = ?, evidence = ?,
			     confidence = ?, importance = ?, priority = ?, pinned = ?,
			     fact_fingerprint = ?, updated_at = ?
			 WHERE id = ?`,
			winner.Summary,
			winner.Summary,
			mergedBody,
			mergedEvidence,
			confidence,
			importance,
			priority,
			boolToInt(pinned),
			cleanupFactFingerprint(projectID, winner.AssetID, canonicalKey, winner.SubjectKey, winner.Predicate),
			now.Unix(),
			winner.ID,
		); err != nil {
			return err
		}
		for _, loser := range items[1:] {
			if _, err := tx.ExecContext(
				ctx,
				`UPDATE project_facts
				 SET valid_to = ?, superseded_by = ?, updated_at = ?
				 WHERE id = ?`,
				now.Unix(),
				winner.ID,
				now.Unix(),
				loser.ID,
			); err != nil {
				return err
			}
		}
		stats.MergedGroups++
		stats.ArchivedDuplicateFacts += len(items) - 1
	}

	for _, fact := range facts {
		if !fact.ValidTo.IsZero() {
			continue
		}
		fingerprint := cleanupFactFingerprint(
			projectID,
			fact.AssetID,
			cleanupCanonicalKey(fact.Key, fact.FactType, fact.MemoryKind),
			fact.SubjectKey,
			fact.Predicate,
		)
		if _, err := tx.ExecContext(
			ctx,
			`UPDATE project_facts
			 SET fact_fingerprint = ?
			 WHERE id = ? AND (fact_fingerprint = '' OR fact_fingerprint = ?)`,
			fingerprint,
			fact.ID,
			fingerprint,
		); err != nil {
			return err
		}
	}
	return nil
}

func cleanupFactGroupKey(fact ProjectFact) string {
	return strings.Join([]string{
		strings.TrimSpace(fact.AssetID),
		strings.ToLower(strings.TrimSpace(fact.FactType)),
		cleanupFactBaseKey(fact.Key),
		strings.ToLower(strings.TrimSpace(fact.SubjectKey)),
		strings.ToLower(strings.TrimSpace(fact.Predicate)),
	}, "\x00")
}

// RestoreProjectFact 撤销一次归档，将事实恢复为活跃状态。
func (db *DB) RestoreProjectFact(ctx context.Context, projectID string, factID string) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_facts
		 SET valid_to = 0, superseded_by = '', updated_at = ?
		 WHERE id = ? AND project_id = ?`,
		time.Now().UTC().Unix(),
		strings.TrimSpace(factID),
		strings.TrimSpace(projectID),
	)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("事实不存在")
	}
	return nil
}

func (db *DB) deleteAutoSyncFactNodes(ctx context.Context, projectID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM project_graph_edges
		 WHERE project_id = ?
		   AND (
			src_id IN (
				SELECT id FROM project_graph_nodes
				WHERE project_id = ? AND kind = 'fact' AND source = 'auto-sync'
			)
			OR dst_id IN (
				SELECT id FROM project_graph_nodes
				WHERE project_id = ? AND kind = 'fact' AND source = 'auto-sync'
			)
		   )`,
		projectID,
		projectID,
		projectID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM project_graph_nodes
		 WHERE project_id = ? AND kind = 'fact' AND source = 'auto-sync'`,
		projectID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func cleanupFactBaseKey(key string) string {
	value := strings.ToLower(strings.TrimSpace(key))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.Join(strings.Fields(value), "-")
	value = cleanupFactDateSuffix.ReplaceAllString(value, "")
	value = strings.Trim(value, "- _/()[]")
	for strings.Contains(value, "--") {
		value = strings.ReplaceAll(value, "--", "-")
	}
	if index := strings.Index(value, "/"); index >= 0 {
		value = strings.TrimSpace(value[index+1:])
	}
	return value
}

func cleanupCanonicalKey(key string, factType string, memoryKind string) string {
	base := cleanupFactBaseKey(key)
	if base == "" {
		return strings.TrimSpace(key)
	}
	if strings.Contains(base, "/") {
		return base
	}
	switch {
	case strings.Contains(strings.ToLower(factType), "credential"),
		strings.Contains(strings.ToLower(memoryKind), "credential"):
		return "auth/" + base
	default:
		return base
	}
}

func appendCleanupText(body string, summary string, detail string) string {
	part := strings.TrimSpace(strings.Join([]string{summary, detail}, "\n"))
	if part == "" || strings.Contains(body, part) {
		return body
	}
	if strings.TrimSpace(body) == "" {
		return part
	}
	return body + "\n\n---\n" + part
}

func appendCleanupEvidence(existing string, next string) string {
	next = strings.TrimSpace(next)
	if next == "" || strings.Contains(existing, next) {
		return existing
	}
	if strings.TrimSpace(existing) == "" {
		return next
	}
	return existing + "\n" + next
}

func cleanupFactFingerprint(projectID string, assetID string, key string, subjectKey string, predicate string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(projectID),
		strings.TrimSpace(assetID),
		strings.ToLower(strings.TrimSpace(key)),
		strings.ToLower(strings.TrimSpace(subjectKey)),
		strings.ToLower(strings.TrimSpace(predicate)),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}
