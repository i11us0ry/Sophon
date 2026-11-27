package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// CreateProjectIntentWithHypothesis atomically writes the intent node, its
// graph edges, and the corresponding test hypothesis.
func (db *DB) CreateProjectIntentWithHypothesis(
	ctx context.Context,
	node GraphNode,
	edges []GraphEdge,
	result ProjectTestResult,
) (*ProjectTestResult, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	savedNode, err := upsertProjectGraphNodeTx(ctx, tx, node)
	if err != nil {
		return nil, err
	}
	if result.IntentID == "" || result.IntentID == node.ID {
		result.IntentID = savedNode.ID
	}
	if result.Technique == "direct_intent_"+node.ID {
		result.Technique = "direct_intent_" + savedNode.ID
	}
	for _, edge := range edges {
		if edge.SrcID == node.ID {
			edge.SrcID = savedNode.ID
		}
		if edge.DstID == node.ID {
			edge.DstID = savedNode.ID
		}
		if edge.SrcID == "" || edge.DstID == "" || edge.SrcID == edge.DstID {
			continue
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO project_graph_edges (
				id, project_id, src_id, dst_id, rel, created_at
			) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(project_id, src_id, dst_id, rel) DO NOTHING`,
			edge.ID,
			edge.ProjectID,
			edge.SrcID,
			edge.DstID,
			edge.Rel,
			edge.CreatedAt.Unix(),
		); err != nil {
			return nil, err
		}
	}
	saved, err := upsertProjectTestResult(ctx, tx, result)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &saved, nil
}

func upsertProjectGraphNodeTx(
	ctx context.Context,
	tx *sql.Tx,
	item GraphNode,
) (*GraphNode, error) {
	conflictTarget := `(project_id, kind, asset_id, title) WHERE source_ref_id = ''`
	if strings.TrimSpace(item.SourceRefID) != "" {
		conflictTarget = `(project_id, kind, source_ref_id) WHERE source_ref_id <> ''`
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO project_graph_nodes (
			id, project_id, kind, title, detail, status, confidence, severity,
			asset_id, source, source_ref_id, pos_x, pos_y, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT`+conflictTarget+` DO UPDATE SET
			detail = excluded.detail,
			status = excluded.status,
			confidence = excluded.confidence,
			severity = excluded.severity,
			asset_id = excluded.asset_id,
			source = excluded.source,
			updated_at = excluded.updated_at`,
		item.ID,
		item.ProjectID,
		item.Kind,
		item.Title,
		item.Detail,
		item.Status,
		item.Confidence,
		item.Severity,
		item.AssetID,
		item.Source,
		item.SourceRefID,
		item.PosX,
		item.PosY,
		item.CreatedAt.Unix(),
		item.UpdatedAt.Unix(),
	); err != nil {
		return nil, err
	}
	query := `SELECT id FROM project_graph_nodes
		WHERE project_id = ? AND kind = ? AND asset_id = ? AND title = ?
		  AND source_ref_id = ''`
	args := []interface{}{item.ProjectID, item.Kind, item.AssetID, item.Title}
	if strings.TrimSpace(item.SourceRefID) != "" {
		query = `SELECT id FROM project_graph_nodes
			WHERE project_id = ? AND kind = ? AND source_ref_id = ?`
		args = []interface{}{item.ProjectID, item.Kind, item.SourceRefID}
	}
	var savedID string
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&savedID); err != nil {
		return nil, fmt.Errorf("读取意图节点失败: %w", err)
	}
	item.ID = savedID
	return &item, nil
}
