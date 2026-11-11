package database

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type GraphNode struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"projectId"`
	Kind        string    `json:"kind"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail"`
	Status      string    `json:"status"`
	Confidence  int       `json:"confidence"`
	Severity    string    `json:"severity"`
	AssetID     string    `json:"assetId"`
	Source      string    `json:"source"`
	SourceRefID string    `json:"sourceRefId"`
	PosX        int       `json:"posX"`
	PosY        int       `json:"posY"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type GraphEdge struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"projectId"`
	SrcID     string    `json:"srcId"`
	DstID     string    `json:"dstId"`
	Rel       string    `json:"rel"`
	CreatedAt time.Time `json:"createdAt"`
}

func (db *DB) ListProjectGraphNodes(ctx context.Context, projectID string) ([]GraphNode, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, kind, title, detail, status, confidence, severity,
			asset_id, source, source_ref_id, pos_x, pos_y, created_at, updated_at
		 FROM project_graph_nodes
		 WHERE project_id = ?
		 ORDER BY kind ASC, created_at ASC`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]GraphNode, 0)
	for rows.Next() {
		item, err := scanGraphNode(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListActiveProjectIDs(ctx context.Context) ([]string, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id FROM projects WHERE status = 'active' ORDER BY updated_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		items = append(items, id)
	}
	return items, rows.Err()
}

func (db *DB) CountProjectGraphNodes(ctx context.Context, projectID string) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes WHERE project_id = ?`,
		strings.TrimSpace(projectID),
	).Scan(&count)
	return count, err
}

// ListProjectGraphNodesByAsset 返回指定资产节点和项目级公共节点。
func (db *DB) ListProjectGraphNodesByAsset(
	ctx context.Context,
	projectID string,
	assetID string,
) ([]GraphNode, error) {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return db.ListProjectGraphNodes(ctx, projectID)
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, kind, title, detail, status, confidence, severity,
			asset_id, source, source_ref_id, pos_x, pos_y, created_at, updated_at
		 FROM project_graph_nodes
		 WHERE project_id = ? AND (asset_id = ? OR asset_id = '')
		 ORDER BY kind ASC, created_at ASC`,
		projectID,
		assetID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]GraphNode, 0)
	for rows.Next() {
		item, err := scanGraphNode(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) GetProjectGraphNode(ctx context.Context, id, projectID string) (*GraphNode, error) {
	row := db.QueryRowContext(
		ctx,
		`SELECT id, project_id, kind, title, detail, status, confidence, severity,
			asset_id, source, source_ref_id, pos_x, pos_y, created_at, updated_at
		 FROM project_graph_nodes WHERE id = ? AND project_id = ?`,
		id,
		projectID,
	)
	item, err := scanGraphNode(row)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) CreateProjectGraphNode(ctx context.Context, item GraphNode) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO project_graph_nodes (
			id, project_id, kind, title, detail, status, confidence, severity,
			asset_id, source, source_ref_id, pos_x, pos_y, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
	return err
}

func (db *DB) CreateProjectGraphBatch(
	ctx context.Context,
	nodes []GraphNode,
	edges []GraphEdge,
) error {
	if len(nodes) == 0 && len(edges) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, item := range nodes {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO project_graph_nodes (
				id, project_id, kind, title, detail, status, confidence, severity,
				asset_id, source, source_ref_id, pos_x, pos_y, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
			return err
		}
	}
	for _, item := range edges {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO project_graph_edges (
				id, project_id, src_id, dst_id, rel, created_at
			) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(project_id, src_id, dst_id, rel) DO NOTHING`,
			item.ID,
			item.ProjectID,
			item.SrcID,
			item.DstID,
			item.Rel,
			item.CreatedAt.Unix(),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (db *DB) UpdateProjectGraphNode(ctx context.Context, item GraphNode) error {
	result, err := db.ExecContext(
		ctx,
		`UPDATE project_graph_nodes
		 SET kind = ?, title = ?, detail = ?, status = ?, confidence = ?,
			severity = ?, asset_id = ?, pos_x = ?, pos_y = ?, updated_at = ?
		 WHERE id = ? AND project_id = ?`,
		item.Kind,
		item.Title,
		item.Detail,
		item.Status,
		item.Confidence,
		item.Severity,
		item.AssetID,
		item.PosX,
		item.PosY,
		item.UpdatedAt.Unix(),
		item.ID,
		item.ProjectID,
	)
	return requireAffected(result, err)
}

func (db *DB) DeleteProjectGraphNode(ctx context.Context, id, projectID string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM project_graph_edges WHERE project_id = ? AND (src_id = ? OR dst_id = ?)`,
		projectID,
		id,
		id,
	); err != nil {
		return err
	}
	result, err := tx.ExecContext(
		ctx,
		`DELETE FROM project_graph_nodes WHERE id = ? AND project_id = ?`,
		id,
		projectID,
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
	return tx.Commit()
}

func (db *DB) CountProjectGraphNodesBySource(ctx context.Context, projectID, source string) (int, error) {
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes WHERE project_id = ? AND source = ?`,
		projectID,
		source,
	).Scan(&count)
	return count, err
}

// CountActiveProjectGraphNodes 统计某资产下仍在推进的 intent / hint。
func (db *DB) CountActiveProjectGraphNodes(
	ctx context.Context,
	projectID string,
	kind string,
	assetID string,
) (int, error) {
	statuses := []string{}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "intent":
		statuses = []string{"open", "running"}
	case "hint":
		statuses = []string{"active"}
	default:
		return 0, nil
	}
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes
		 WHERE project_id = ? AND kind = ? AND asset_id = ?
		   AND status IN (`+placeholders(len(statuses))+`)`,
		append([]interface{}{
			strings.TrimSpace(projectID),
			strings.ToLower(strings.TrimSpace(kind)),
			strings.TrimSpace(assetID),
		}, stringsToInterfaces(statuses)...)...,
	).Scan(&count)
	return count, err
}

func stringsToInterfaces(values []string) []interface{} {
	result := make([]interface{}, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

// CountActiveProjectGraphNodesByKind 统计项目级活跃 intent / hint。
func (db *DB) CountActiveProjectGraphNodesByKind(
	ctx context.Context,
	projectID string,
	kind string,
) (int, error) {
	statuses := []string{}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "intent":
		statuses = []string{"open", "running"}
	case "hint":
		statuses = []string{"active"}
	default:
		return 0, nil
	}
	var count int
	err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_graph_nodes
		 WHERE project_id = ? AND kind = ?
		   AND status IN (`+placeholders(len(statuses))+`)`,
		append([]interface{}{
			strings.TrimSpace(projectID),
			strings.ToLower(strings.TrimSpace(kind)),
		}, stringsToInterfaces(statuses)...)...,
	).Scan(&count)
	return count, err
}

func (db *DB) ListProjectGraphEdges(ctx context.Context, projectID string) ([]GraphEdge, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, src_id, dst_id, rel, created_at
		 FROM project_graph_edges WHERE project_id = ? ORDER BY created_at ASC`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]GraphEdge, 0)
	for rows.Next() {
		var item GraphEdge
		var createdAt int64
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.SrcID, &item.DstID, &item.Rel, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

// ListProjectGraphEdgesForNodes 只返回两端都位于可见节点集合内的连线。
func (db *DB) ListProjectGraphEdgesForNodes(
	ctx context.Context,
	projectID string,
	nodeIDs []string,
) ([]GraphEdge, error) {
	if len(nodeIDs) == 0 {
		return []GraphEdge{}, nil
	}
	query := `SELECT id, project_id, src_id, dst_id, rel, created_at
		FROM project_graph_edges
		WHERE project_id = ? AND src_id IN (` + placeholders(len(nodeIDs)) + `)
		  AND dst_id IN (` + placeholders(len(nodeIDs)) + `)
		ORDER BY created_at ASC`
	args := []interface{}{projectID}
	args = append(args, buildIDArgs(nil, nodeIDs)...)
	args = append(args, buildIDArgs(nil, nodeIDs)...)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]GraphEdge, 0)
	for rows.Next() {
		var item GraphEdge
		var createdAt int64
		if err := rows.Scan(&item.ID, &item.ProjectID, &item.SrcID, &item.DstID, &item.Rel, &createdAt); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ListProjectGraphEdgesFromNode(
	ctx context.Context,
	projectID string,
	srcID string,
) ([]GraphEdge, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, src_id, dst_id, rel, created_at
		 FROM project_graph_edges
		 WHERE project_id = ? AND src_id = ?
		 ORDER BY created_at ASC`,
		strings.TrimSpace(projectID),
		strings.TrimSpace(srcID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]GraphEdge, 0)
	for rows.Next() {
		var item GraphEdge
		var createdAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ProjectID,
			&item.SrcID,
			&item.DstID,
			&item.Rel,
			&createdAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) CreateProjectGraphEdge(ctx context.Context, item GraphEdge) error {
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO project_graph_edges (id, project_id, src_id, dst_id, rel, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project_id, src_id, dst_id, rel) DO NOTHING`,
		item.ID,
		item.ProjectID,
		item.SrcID,
		item.DstID,
		item.Rel,
		item.CreatedAt.Unix(),
	)
	return err
}

func (db *DB) DeleteProjectGraphEdge(ctx context.Context, id, projectID string) error {
	result, err := db.ExecContext(
		ctx,
		`DELETE FROM project_graph_edges WHERE id = ? AND project_id = ?`,
		id,
		projectID,
	)
	return requireAffected(result, err)
}

type GraphLayoutItem struct {
	ID string `json:"id"`
	X  int    `json:"x"`
	Y  int    `json:"y"`
}

// UpdateProjectGraphLayout 批量保存画布坐标。
func (db *DB) UpdateProjectGraphLayout(
	ctx context.Context,
	projectID string,
	items []GraphLayoutItem,
) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Unix()
	for _, item := range items {
		result, err := tx.ExecContext(
			ctx,
			`UPDATE project_graph_nodes
			 SET pos_x = ?, pos_y = ?, updated_at = ?
			 WHERE id = ? AND project_id = ?`,
			item.X,
			item.Y,
			now,
			item.ID,
			projectID,
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
	}
	return tx.Commit()
}

func scanGraphNode(scanner rowScanner) (GraphNode, error) {
	var item GraphNode
	var createdAt int64
	var updatedAt int64
	err := scanner.Scan(
		&item.ID,
		&item.ProjectID,
		&item.Kind,
		&item.Title,
		&item.Detail,
		&item.Status,
		&item.Confidence,
		&item.Severity,
		&item.AssetID,
		&item.Source,
		&item.SourceRefID,
		&item.PosX,
		&item.PosY,
		&createdAt,
		&updatedAt,
	)
	if err != nil {
		return item, err
	}
	item.CreatedAt = time.Unix(createdAt, 0)
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return item, nil
}
