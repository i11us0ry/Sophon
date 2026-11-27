package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

func (db *DB) getAppMetadata(ctx context.Context, key string) (string, bool, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", false, nil
	}
	var value string
	err := db.QueryRowContext(
		ctx,
		`SELECT value FROM app_metadata WHERE key = ?`,
		key,
	).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

func (db *DB) setAppMetadata(ctx context.Context, key, value string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO app_metadata (key, value, updated_at)
		 VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET
			value = excluded.value,
			updated_at = excluded.updated_at`,
		key,
		strings.TrimSpace(value),
		time.Now().UTC().Unix(),
	)
	return err
}
