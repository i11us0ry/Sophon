package database

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

func openStorageTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "storage.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func insertAuditRows(t *testing.T, db *DB, prefix string, count int, createdAt int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("开启事务失败: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	for index := 0; index < count; index++ {
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO audit_logs (id, user_id, username, action, result, detail, created_at)
			 VALUES (?, '', '', 'test', 'ok', '', ?)`,
			fmt.Sprintf("%s-%d", prefix, index),
			createdAt,
		); err != nil {
			t.Fatalf("插入审计日志失败: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交审计日志失败: %v", err)
	}
}

func TestDeleteExpiredRowsBatches(t *testing.T) {
	db := openStorageTestDB(t)
	ctx := context.Background()
	cutoff := int64(1_700_000_000)
	const expired = 2*cleanupDeleteBatchSize + 3
	insertAuditRows(t, db, "expired", expired, cutoff-60)
	insertAuditRows(t, db, "fresh", 1, cutoff+60)

	deleted, err := db.DeleteExpiredRows(ctx, "audit_logs", "created_at", "", cutoff)
	if err != nil {
		t.Fatalf("分批删除失败: %v", err)
	}
	if deleted != expired {
		t.Fatalf("删除行数应为 %d，实际 %d", expired, deleted)
	}
	remaining, err := db.CountRows(ctx, "audit_logs", "")
	if err != nil {
		t.Fatalf("统计剩余行失败: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("应保留 1 条未过期记录，实际 %d", remaining)
	}
}

func TestDeleteAllRowsBatches(t *testing.T) {
	db := openStorageTestDB(t)
	ctx := context.Background()
	total := 2*cleanupDeleteBatchSize + 7
	insertAuditRows(t, db, "all", total, int64(1_700_000_000))

	deleted, err := db.DeleteAllRows(ctx, "audit_logs", "")
	if err != nil {
		t.Fatalf("分批清空失败: %v", err)
	}
	if deleted != total {
		t.Fatalf("清空行数应为 %d，实际 %d", total, deleted)
	}
	remaining, err := db.CountRows(ctx, "audit_logs", "")
	if err != nil || remaining != 0 {
		t.Fatalf("清空后应无剩余记录，实际 %d, err=%v", remaining, err)
	}
}
