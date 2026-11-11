package database

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestDeleteExpiredSessions(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "session-cleanup.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateUser(ctx, User{
		ID:           "user-session-cleanup",
		Username:     "session-cleanup",
		PasswordHash: "hash",
		Role:         "admin",
		Enabled:      true,
		CreatedAt:    now,
	}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(
		ctx,
		`INSERT INTO sessions (
			id, user_id, token_hash, csrf_hash, expires_at, created_at, last_seen_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	expiredCount := sessionCleanupBatchSize + 2
	for index := 0; index < expiredCount; index++ {
		if _, err := stmt.ExecContext(
			ctx,
			fmt.Sprintf("expired-%04d", index),
			"user-session-cleanup",
			fmt.Sprintf("expired-token-%04d", index),
			fmt.Sprintf("expired-csrf-%04d", index),
			now.Add(-time.Hour).Unix(),
			now.Add(-2*time.Hour).Unix(),
			now.Add(-time.Hour).Unix(),
		); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := stmt.ExecContext(
		ctx,
		"active-session",
		"user-session-cleanup",
		"active-token",
		"active-csrf",
		now.Add(time.Hour).Unix(),
		now.Unix(),
		now.Unix(),
	); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	deleted, err := db.DeleteExpiredSessions(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != int64(expiredCount) {
		t.Fatalf("应分批清理 %d 个过期会话，实际 %d", expiredCount, deleted)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("有效会话应保留，实际总数 %d", count)
	}
}
