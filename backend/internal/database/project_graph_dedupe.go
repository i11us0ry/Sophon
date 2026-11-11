package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// dedupeProjectGraph 清理历史重复的攻击路径节点与连线，并建立唯一索引（幂等）。
// 背景：并发同步（多个写工具一轮内并行触发）曾产生重复节点/连线。
// 规则：每组 (project_id, kind, asset_id, title/source_ref_id) 保留最早的一条，指向重复节点的连线重映射到保留节点，
// 随后删除重复节点、自环与重复连线，最后创建唯一索引防止再次发生。
func (db *DB) dedupeProjectGraph(ctx context.Context) error {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, kind, title, source_ref_id, asset_id
		 FROM project_graph_nodes ORDER BY rowid`,
	)
	if err != nil {
		return err
	}
	canonical := make(map[string]string)
	remap := make(map[string]string)
	duplicates := make([]string, 0)
	for rows.Next() {
		var id, projectID, kind, title, sourceRefID, assetID string
		if err := rows.Scan(&id, &projectID, &kind, &title, &sourceRefID, &assetID); err != nil {
			rows.Close()
			return err
		}
		identity := "title:" + title
		if sourceRefID != "" {
			identity = "ref:" + sourceRefID
		}
		key := projectID + "\x00" + kind + "\x00" + assetID + "\x00" + identity
		if keep, ok := canonical[key]; ok {
			remap[id] = keep
			duplicates = append(duplicates, id)
			continue
		}
		canonical[key] = id
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for duplicateID, keepID := range remap {
		if _, err := db.ExecContext(
			ctx,
			`UPDATE project_graph_edges SET src_id = ? WHERE src_id = ?`,
			keepID,
			duplicateID,
		); err != nil {
			return err
		}
		if _, err := db.ExecContext(
			ctx,
			`UPDATE project_graph_edges SET dst_id = ? WHERE dst_id = ?`,
			keepID,
			duplicateID,
		); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM project_graph_edges WHERE src_id = dst_id`); err != nil {
		return err
	}
	if _, err := db.ExecContext(
		ctx,
		`DELETE FROM project_graph_edges WHERE rowid NOT IN (
			SELECT MIN(rowid) FROM project_graph_edges GROUP BY project_id, src_id, dst_id, rel
		)`,
	); err != nil {
		return err
	}
	for _, id := range duplicates {
		if _, err := db.ExecContext(ctx, `DELETE FROM project_graph_nodes WHERE id = ?`, id); err != nil {
			return err
		}
	}

	for _, statement := range []string{
		`DROP INDEX IF EXISTS idx_project_graph_nodes_unique`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_project_graph_nodes_ref_unique
		 ON project_graph_nodes(project_id, kind, asset_id, source_ref_id)
		 WHERE source_ref_id <> ''`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_project_graph_nodes_title_unique
		 ON project_graph_nodes(project_id, kind, asset_id, title)
		 WHERE source_ref_id = ''`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_project_graph_edges_unique
		 ON project_graph_edges(project_id, src_id, dst_id, rel)`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create project graph unique index: %w", err)
		}
	}
	return nil
}

// UpsertProjectGraphNode 按稳定来源 ID 或 (project_id, kind, asset_id, title) 幂等写入节点：
// 已存在则更新可变字段并返回既有节点，避免并发同步产生重复。
func (db *DB) UpsertProjectGraphNode(ctx context.Context, item GraphNode) (*GraphNode, error) {
	conflictTarget := `(project_id, kind, asset_id, title) WHERE source_ref_id = ''`
	if item.SourceRefID != "" {
		conflictTarget = `(project_id, kind, asset_id, source_ref_id) WHERE source_ref_id <> ''`
	}
	_, err := db.ExecContext(
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
	)
	if err != nil {
		return nil, err
	}
	return db.getProjectGraphNodeByIdentity(ctx, item)
}

func (db *DB) GetProjectGraphNodeBySourceRef(
	ctx context.Context,
	projectID string,
	kind string,
	assetID string,
	sourceRefID string,
) (*GraphNode, error) {
	sourceRefID = strings.TrimSpace(sourceRefID)
	if sourceRefID == "" {
		return nil, nil
	}
	return db.getProjectGraphNodeByIdentity(ctx, GraphNode{
		ProjectID:   strings.TrimSpace(projectID),
		Kind:        strings.TrimSpace(kind),
		AssetID:     strings.TrimSpace(assetID),
		SourceRefID: sourceRefID,
	})
}

func (db *DB) getProjectGraphNodeByIdentity(
	ctx context.Context,
	item GraphNode,
) (*GraphNode, error) {
	query := `SELECT id, project_id, kind, title, detail, status, confidence, severity,
		asset_id, source, source_ref_id, pos_x, pos_y, created_at, updated_at
		FROM project_graph_nodes
		WHERE project_id = ? AND kind = ? AND asset_id = ? AND source_ref_id = '' AND title = ?`
	args := []interface{}{item.ProjectID, item.Kind, item.AssetID, item.Title}
	if item.SourceRefID != "" {
		query = `SELECT id, project_id, kind, title, detail, status, confidence, severity,
			asset_id, source, source_ref_id, pos_x, pos_y, created_at, updated_at
			FROM project_graph_nodes
			WHERE project_id = ? AND kind = ? AND asset_id = ? AND source_ref_id = ?`
		args = []interface{}{item.ProjectID, item.Kind, item.AssetID, item.SourceRefID}
	}
	row := db.QueryRowContext(ctx, query, args...)
	var stored GraphNode
	var createdAt, updatedAt int64
	if err := row.Scan(
		&stored.ID,
		&stored.ProjectID,
		&stored.Kind,
		&stored.Title,
		&stored.Detail,
		&stored.Status,
		&stored.Confidence,
		&stored.Severity,
		&stored.AssetID,
		&stored.Source,
		&stored.SourceRefID,
		&stored.PosX,
		&stored.PosY,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	stored.CreatedAt = time.Unix(createdAt, 0)
	stored.UpdatedAt = time.Unix(updatedAt, 0)
	return &stored, nil
}
