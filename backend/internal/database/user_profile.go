package database

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type UserProfile struct {
	UserID          string
	AssistantName   string
	AssistantAvatar string
	UserAvatar      string
	UpdatedAt       time.Time
}

func (db *DB) GetUserProfile(ctx context.Context, userID string) (*UserProfile, error) {
	profile := &UserProfile{
		UserID:        strings.TrimSpace(userID),
		AssistantName: "Sophon",
	}
	var updatedAt int64
	err := db.QueryRowContext(
		ctx,
		`SELECT assistant_name, assistant_avatar, user_avatar, updated_at
		 FROM user_profiles WHERE user_id = ?`,
		profile.UserID,
	).Scan(
		&profile.AssistantName,
		&profile.AssistantAvatar,
		&profile.UserAvatar,
		&updatedAt,
	)
	if err == sql.ErrNoRows {
		return profile, nil
	}
	if err != nil {
		return nil, err
	}
	profile.UpdatedAt = time.Unix(updatedAt, 0)
	return profile, nil
}

func (db *DB) UpdateUserProfile(
	ctx context.Context,
	userID string,
	displayName string,
	assistantName string,
	assistantAvatar string,
	userAvatar string,
) error {
	userID = strings.TrimSpace(userID)
	now := time.Now().Unix()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE users SET display_name = ? WHERE id = ?`,
		strings.TrimSpace(displayName),
		userID,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO user_profiles (
			user_id, assistant_name, assistant_avatar, user_avatar, updated_at
		) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			assistant_name = excluded.assistant_name,
			assistant_avatar = excluded.assistant_avatar,
			user_avatar = excluded.user_avatar,
			updated_at = excluded.updated_at`,
		userID,
		strings.TrimSpace(assistantName),
		strings.TrimSpace(assistantAvatar),
		strings.TrimSpace(userAvatar),
		now,
	); err != nil {
		return err
	}
	return tx.Commit()
}
