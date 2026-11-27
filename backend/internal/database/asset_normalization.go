package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func (db *DB) backfillAssetNormalization(ctx context.Context) error {
	type identity struct {
		owner, project, kind, value string
	}
	seenKind := map[identity]string{}
	seenValue := map[string]string{}
	existingRows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, kind, normalized_value
		 FROM assets
		 WHERE TRIM(normalized_value) <> ''`,
	)
	if err != nil {
		return err
	}
	for existingRows.Next() {
		var id, projectID, ownerID, kind, normalized string
		if err := existingRows.Scan(&id, &projectID, &ownerID, &kind, &normalized); err != nil {
			existingRows.Close()
			return err
		}
		key := identity{
			owner:   strings.TrimSpace(ownerID),
			project: strings.TrimSpace(projectID),
			kind:    strings.ToLower(strings.TrimSpace(kind)),
			value:   strings.ToLower(strings.TrimSpace(normalized)),
		}
		seenKind[key] = id
		crossKey := strings.Join([]string{key.owner, key.project, key.value}, "\x00")
		if seenValue[crossKey] == "" {
			seenValue[crossKey] = key.kind
		}
	}
	if err := existingRows.Err(); err != nil {
		existingRows.Close()
		return err
	}
	existingRows.Close()

	rows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, kind, value
		 FROM assets
		 WHERE TRIM(normalized_value) = ''
		    OR TRIM(quality_status) IN ('', 'invalid')
		 ORDER BY rowid`,
	)
	if err != nil {
		return err
	}
	type assetRow struct {
		id, projectID, ownerID, kind, value string
	}
	items := make([]assetRow, 0)
	for rows.Next() {
		var item assetRow
		if err := rows.Scan(&item.id, &item.projectID, &item.ownerID, &item.kind, &item.value); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, item := range items {
		normalized, normalizeErr := NormalizeAssetValue(item.kind, item.value)
		if normalizeErr != nil {
			if _, err := db.ExecContext(
				ctx,
				`UPDATE assets SET normalized_value = '', quality_status = ? WHERE id = ?`,
				AssetQualityInvalid,
				item.id,
			); err != nil {
				return err
			}
			continue
		}
		quality := AssetQualityValid
		if suspiciousRepeatedWWW(normalized) {
			quality = AssetQualitySuspicious
		}
		kindKey := identity{
			owner:   strings.TrimSpace(item.ownerID),
			project: strings.TrimSpace(item.projectID),
			kind:    strings.ToLower(strings.TrimSpace(item.kind)),
			value:   strings.ToLower(strings.TrimSpace(normalized)),
		}
		if seenKind[kindKey] != "" {
			if _, err := db.ExecContext(
				ctx,
				`UPDATE assets SET normalized_value = '', quality_status = ? WHERE id = ?`,
				AssetQualityDuplicate,
				item.id,
			); err != nil {
				return err
			}
			continue
		}
		seenKind[kindKey] = item.id
		crossKey := strings.Join([]string{
			kindKey.owner,
			kindKey.project,
			kindKey.value,
		}, "\x00")
		if previousKind := seenValue[crossKey]; previousKind != "" && previousKind != kindKey.kind {
			quality = AssetQualityCrossTypeDuplicate
		} else {
			seenValue[crossKey] = kindKey.kind
		}
		if _, err := db.ExecContext(
			ctx,
			`UPDATE assets SET normalized_value = ?, quality_status = ? WHERE id = ?`,
			normalized,
			quality,
			item.id,
		); err != nil {
			return err
		}
	}
	_, err = db.ExecContext(
		ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_normalized_unique
		 ON assets(owner_user_id, project_id, kind, normalized_value)
		 WHERE normalized_value <> ''`,
	)
	if err != nil {
		return fmt.Errorf("create normalized asset index: %w", err)
	}
	return nil
}

func markCrossTypeAssetQuality(
	ctx context.Context,
	tx *sql.Tx,
	item *Asset,
) error {
	if item == nil || strings.TrimSpace(item.NormalizedValue) == "" {
		return nil
	}
	var count int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM assets
		 WHERE owner_user_id = ? AND project_id = ?
		   AND LOWER(TRIM(kind)) <> LOWER(TRIM(?))
		   AND LOWER(TRIM(normalized_value)) = LOWER(TRIM(?))
		   AND id <> ?`,
		item.OwnerUserID,
		item.ProjectID,
		item.Kind,
		item.NormalizedValue,
		item.ID,
	).Scan(&count); err != nil {
		return err
	}
	if count > 0 && item.QualityStatus == AssetQualityValid {
		item.QualityStatus = AssetQualityCrossTypeDuplicate
	}
	return nil
}
