package database

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const intelCipherPrefix = "intel:v1:"

type IntelSettings struct {
	Enabled   bool
	FOFAEmail string
	FOFAKey   string
	HunterKey string
	UpdatedAt time.Time
}

func (db *DB) GetIntelSettings(ctx context.Context) (IntelSettings, error) {
	var item IntelSettings
	var enabled int
	var fofaKey string
	var hunterKey string
	var updatedAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT enabled, fofa_email, fofa_key_cipher, hunter_key_cipher, updated_at
		 FROM intel_settings WHERE id = 'default'`,
	).Scan(&enabled, &item.FOFAEmail, &fofaKey, &hunterKey, &updatedAt)
	if err == sql.ErrNoRows {
		return IntelSettings{}, nil
	}
	if err != nil {
		return IntelSettings{}, err
	}
	item.Enabled = enabled != 0
	item.FOFAEmail = strings.TrimSpace(item.FOFAEmail)
	if item.FOFAKey, err = openSecret(db.jobKey, fofaKey, intelCipherPrefix, "FOFA Key"); err != nil {
		return IntelSettings{}, err
	}
	if item.HunterKey, err = openSecret(db.jobKey, hunterKey, intelCipherPrefix, "Hunter Key"); err != nil {
		return IntelSettings{}, err
	}
	item.UpdatedAt = time.Unix(updatedAt, 0)
	return item, nil
}

func (db *DB) SaveIntelSettings(ctx context.Context, item IntelSettings) error {
	fofaKey, err := sealSecret(db.jobKey, strings.TrimSpace(item.FOFAKey), intelCipherPrefix)
	if err != nil {
		return err
	}
	hunterKey, err := sealSecret(db.jobKey, strings.TrimSpace(item.HunterKey), intelCipherPrefix)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = db.ExecContext(
		ctx,
		`INSERT INTO intel_settings (
			id, enabled, fofa_email, fofa_key_cipher, hunter_key_cipher, updated_at
		) VALUES ('default', ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			enabled = excluded.enabled,
			fofa_email = excluded.fofa_email,
			fofa_key_cipher = excluded.fofa_key_cipher,
			hunter_key_cipher = excluded.hunter_key_cipher,
			updated_at = excluded.updated_at`,
		boolInt(item.Enabled),
		strings.TrimSpace(item.FOFAEmail),
		fofaKey,
		hunterKey,
		now.Unix(),
	)
	return err
}
