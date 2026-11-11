package database

import (
	"context"
	"fmt"
	"strings"
)

type ProjectFinalizationMetrics struct {
	AssetsTotal                      int
	TestsTotal                       int
	TestsCovered                     int
	TestsOpenRequired                int
	TestsOpenOptional                int
	TestsSuspicious                  int
	FindingsConfirmedWithoutEvidence int
}

// ProjectFinalizationMetrics 返回最终化检查所需的完整聚合指标，不受列表分页上限影响。
func (db *DB) ProjectFinalizationMetrics(
	ctx context.Context,
	projectID string,
	ownerUserID string,
) (ProjectFinalizationMetrics, error) {
	return db.projectFinalizationMetrics(ctx, projectID, ownerUserID, nil)
}

// ProjectFinalizationMetricsForAssets 按当前任务绑定的资产范围计算最终化指标。
func (db *DB) ProjectFinalizationMetricsForAssets(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetIDs []string,
) (ProjectFinalizationMetrics, error) {
	assetIDs = uniqueStrings(assetIDs)
	if len(assetIDs) == 0 {
		return ProjectFinalizationMetrics{}, nil
	}
	return db.projectFinalizationMetrics(ctx, projectID, ownerUserID, assetIDs)
}

func (db *DB) projectFinalizationMetrics(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	assetIDs []string,
) (ProjectFinalizationMetrics, error) {
	projectID = strings.TrimSpace(projectID)
	ownerUserID = strings.TrimSpace(ownerUserID)
	if projectID == "" || ownerUserID == "" {
		return ProjectFinalizationMetrics{}, fmt.Errorf("项目或用户不能为空")
	}
	if _, err := db.GetProject(ctx, projectID, ownerUserID); err != nil {
		return ProjectFinalizationMetrics{}, err
	}

	var metrics ProjectFinalizationMetrics
	assetFilter := ""
	assetIDFilter := ""
	assetArgs := make([]interface{}, 0, len(assetIDs))
	if len(assetIDs) > 0 {
		assetFilter = " AND asset_id IN (" + placeholders(len(assetIDs)) + ")"
		assetIDFilter = " AND id IN (" + placeholders(len(assetIDs)) + ")"
		for _, assetID := range assetIDs {
			assetArgs = append(assetArgs, assetID)
		}
	}
	assetQueryArgs := []interface{}{projectID, ownerUserID}
	if len(assetIDs) > 0 {
		assetQueryArgs = append(assetQueryArgs, assetArgs...)
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM assets
		 WHERE project_id = ? AND owner_user_id = ?`+assetIDFilter,
		assetQueryArgs...,
	).Scan(&metrics.AssetsTotal); err != nil {
		return metrics, err
	}
	testQueryArgs := []interface{}{projectID}
	testQueryArgs = append(testQueryArgs, assetArgs...)
	if err := db.QueryRowContext(
		ctx,
		`SELECT
			COUNT(*),
			COALESCE(SUM(CASE
				WHEN status IN ('tested_clean', 'suspicious', 'confirmed') THEN 1
				ELSE 0
			END), 0),
				COALESCE(SUM(CASE
					WHEN status IN ('untested', 'running') AND required = 1 THEN 1
					ELSE 0
				END), 0),
				COALESCE(SUM(CASE
					WHEN status IN ('untested', 'running') AND required = 0 THEN 1
					ELSE 0
				END), 0),
				COALESCE(SUM(CASE WHEN status = 'suspicious' THEN 1 ELSE 0 END), 0)
		 FROM project_test_results
		 WHERE project_id = ?`+assetFilter,
		testQueryArgs...,
	).Scan(
		&metrics.TestsTotal,
		&metrics.TestsCovered,
		&metrics.TestsOpenRequired,
		&metrics.TestsOpenOptional,
		&metrics.TestsSuspicious,
	); err != nil {
		return metrics, err
	}
	findingQueryArgs := []interface{}{projectID, ownerUserID}
	findingQueryArgs = append(findingQueryArgs, assetArgs...)
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM vulnerabilities
		 WHERE project_id = ?
		   AND owner_user_id = ?
		   AND status IN ('confirmed', 'fixed')
		   AND TRIM(evidence) = ''
		   AND TRIM(evidence_refs) IN ('', '[]')`+assetFilter,
		findingQueryArgs...,
	).Scan(&metrics.FindingsConfirmedWithoutEvidence); err != nil {
		return metrics, err
	}
	return metrics, nil
}
