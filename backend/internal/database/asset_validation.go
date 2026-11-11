package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidAsset   = errors.New("invalid asset")
	ErrAssetDuplicate = errors.New("asset already exists")
	ErrAssetInUse     = errors.New("asset is referenced")
)

var assetStatuses = map[string]bool{
	"unknown":  true,
	"active":   true,
	"inactive": true,
	"retired":  true,
}

var assetCriticalities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

var supportedAssetKinds = map[string]bool{
	"ip":     true,
	"domain": true,
	"url":    true,
	"port":   true,
	"host":   true,
}

const (
	assetNameMaxRunes  = 120
	assetValueMaxRunes = 4096
)

func IsSupportedAssetKind(kind string) bool {
	return supportedAssetKinds[strings.ToLower(strings.TrimSpace(kind))]
}

func normalizeAssetRecord(item *Asset) error {
	item.ID = strings.TrimSpace(item.ID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.OwnerUserID = strings.TrimSpace(item.OwnerUserID)
	item.Name = strings.TrimSpace(item.Name)
	item.Kind = strings.ToLower(strings.TrimSpace(item.Kind))
	item.Value = strings.TrimSpace(item.Value)
	item.Status = strings.ToLower(strings.TrimSpace(item.Status))
	item.Criticality = strings.ToLower(strings.TrimSpace(item.Criticality))

	if item.ID == "" || item.OwnerUserID == "" {
		return fmt.Errorf("%w: 资产 ID 和所有者不能为空", ErrInvalidAsset)
	}
	if item.Name == "" || len([]rune(item.Name)) > assetNameMaxRunes {
		return fmt.Errorf("%w: 资产名称不能为空且不能超过 %d 个字符", ErrInvalidAsset, assetNameMaxRunes)
	}
	if !IsSupportedAssetKind(item.Kind) {
		return fmt.Errorf("%w: 资产类型只能是 ip、domain、url、port 或 host", ErrInvalidAsset)
	}
	if item.Value == "" || len([]rune(item.Value)) > assetValueMaxRunes {
		return fmt.Errorf("%w: 资产值不能为空且不能超过 %d 个字符", ErrInvalidAsset, assetValueMaxRunes)
	}
	if item.Status == "" {
		item.Status = "unknown"
	}
	if !assetStatuses[item.Status] {
		return fmt.Errorf("%w: 资产状态不合法", ErrInvalidAsset)
	}
	if item.Criticality == "" {
		item.Criticality = "medium"
	}
	if !assetCriticalities[item.Criticality] {
		return fmt.Errorf("%w: 资产关键度不合法", ErrInvalidAsset)
	}
	if item.RiskScore < 0 || item.RiskScore > 100 {
		return fmt.Errorf("%w: 风险分必须在 0 到 100 之间", ErrInvalidAsset)
	}
	return nil
}

func assetDuplicateExists(
	ctx context.Context,
	tx *sql.Tx,
	item Asset,
	excludeID string,
) (bool, error) {
	query := `SELECT COUNT(*) FROM assets
		WHERE owner_user_id = ? AND project_id = ?
		  AND LOWER(TRIM(kind)) = LOWER(TRIM(?))
		  AND LOWER(TRIM(value)) = LOWER(TRIM(?))`
	args := []interface{}{item.OwnerUserID, item.ProjectID, item.Kind, item.Value}
	if excludeID != "" {
		query += ` AND id <> ?`
		args = append(args, excludeID)
	}
	var count int
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func assetRelationMatches(assetID, name, value string) []string {
	assetID = strings.ToLower(strings.TrimSpace(assetID))
	name = strings.ToLower(strings.TrimSpace(name))
	value = strings.ToLower(strings.TrimSpace(value))
	patterns := []string{"asset_id:" + assetID, "asset:" + assetID}
	if value != "" {
		patterns = append(patterns, "asset:"+value)
	}
	if name != "" {
		patterns = append(patterns, "asset:"+name)
	}
	return patterns
}

func assetHasReferences(
	ctx context.Context,
	tx *sql.Tx,
	item Asset,
	oldProjectID string,
	oldName string,
	oldValue string,
) (bool, error) {
	for _, query := range []string{
		`SELECT COUNT(*) FROM vulnerabilities WHERE asset_id = ?`,
		`SELECT COUNT(*) FROM project_graph_nodes WHERE asset_id = ?`,
	} {
		var count int
		if err := tx.QueryRowContext(ctx, query, item.ID).Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}

	patterns := assetRelationMatches(item.ID, oldName, oldValue)
	args := make([]interface{}, 0, len(patterns)+1)
	args = append(args, oldProjectID)
	for _, pattern := range patterns {
		args = append(args, pattern)
	}
	var count int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_facts
		 WHERE project_id = ? AND LOWER(TRIM(relation)) IN (`+placeholders(len(patterns))+`)`,
		args...,
	).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func clearAssetFactRelations(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	assetID string,
	name string,
	value string,
) error {
	patterns := assetRelationMatches(assetID, name, value)
	args := make([]interface{}, 0, len(patterns)+1)
	args = append(args, projectID)
	for _, pattern := range patterns {
		args = append(args, pattern)
	}
	_, err := tx.ExecContext(
		ctx,
		`UPDATE project_facts SET relation = ''
		 WHERE project_id = ? AND LOWER(TRIM(relation)) IN (`+placeholders(len(patterns))+`)`,
		args...,
	)
	return err
}

func canonicalizeAssetFactRelations(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	assetID string,
	name string,
	value string,
) error {
	patterns := assetRelationMatches(assetID, name, value)
	args := []interface{}{"asset_id:" + assetID, projectID}
	for _, pattern := range patterns {
		args = append(args, pattern)
	}
	_, err := tx.ExecContext(
		ctx,
		`UPDATE project_facts SET relation = ?
		 WHERE project_id = ? AND LOWER(TRIM(relation)) IN (`+placeholders(len(patterns))+`)`,
		args...,
	)
	return err
}
