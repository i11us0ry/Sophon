package database

import (
	"context"
	"strings"
)

// cleanupDeleteBatchSize 是清理类删除的单批行数：每批独立提交，
// 避免大表一次性删除长时间持有写锁并撑大 WAL。
const cleanupDeleteBatchSize = 5000

func (db *DB) CountRows(
	ctx context.Context,
	table string,
	extraWhere string,
) (int, error) {
	query := "SELECT COUNT(*) FROM " + table
	if extraWhere != "" {
		query += " WHERE " + extraWhere
	}
	var count int
	err := db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

func (db *DB) DeleteAllRows(
	ctx context.Context,
	table string,
	extraWhere string,
) (int, error) {
	return db.deleteRowsBatched(ctx, table, strings.TrimSpace(extraWhere), nil)
}

// ClearTextColumn 清空指定列（如 messages.reasoning_content）以回收存储，
// cutoff 为 0 表示不限制时间（手动清理）。表名/列名来自 internal/storage 固定定义。
func (db *DB) ClearTextColumn(
	ctx context.Context,
	table string,
	column string,
	timeColumn string,
	extraWhere string,
	cutoff int64,
) (int, error) {
	query := "UPDATE " + table + " SET " + column + " = '' WHERE " + column + " <> ''"
	args := make([]interface{}, 0, 2)
	if cutoff > 0 && strings.TrimSpace(timeColumn) != "" {
		query += " AND " + timeColumn + " < ?"
		args = append(args, cutoff)
	}
	if extra := strings.TrimSpace(extraWhere); extra != "" {
		query += " AND " + extra
	}
	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(affected), nil
}

// 表名与时间列来自 internal/storage 的固定定义，不接受外部输入。
func (db *DB) CountExpiredRows(
	ctx context.Context,
	table string,
	timeColumn string,
	extraWhere string,
	cutoff int64,
) (int, error) {
	query := "SELECT COUNT(*) FROM " + table + " WHERE " + timeColumn + " < ?"
	if extraWhere != "" {
		query += " AND " + extraWhere
	}
	var count int
	err := db.QueryRowContext(ctx, query, cutoff).Scan(&count)
	return count, err
}

func (db *DB) DeleteExpiredRows(
	ctx context.Context,
	table string,
	timeColumn string,
	extraWhere string,
	cutoff int64,
) (int, error) {
	where := timeColumn + " < ?"
	if extra := strings.TrimSpace(extraWhere); extra != "" {
		where += " AND " + extra
	}
	return db.deleteRowsBatched(ctx, table, where, []interface{}{cutoff})
}

// deleteRowsBatched 按 rowid 递增分批删除，每批一条独立 DELETE。
// rowid 游标让每批只扫描后续行；单连接下 SELECT 的 rows 必须在 DELETE
// 前关闭，否则会等待自身释放连接。
func (db *DB) deleteRowsBatched(
	ctx context.Context,
	table string,
	where string,
	args []interface{},
) (int, error) {
	if where == "" {
		where = "rowid > ?"
	} else {
		where += " AND rowid > ?"
	}
	selectQuery := "SELECT rowid FROM " + table + " WHERE " + where + " ORDER BY rowid LIMIT ?"

	total := 0
	cursor := int64(0)
	for {
		queryArgs := make([]interface{}, 0, len(args)+2)
		queryArgs = append(queryArgs, args...)
		queryArgs = append(queryArgs, cursor, cleanupDeleteBatchSize)

		rows, err := db.QueryContext(ctx, selectQuery, queryArgs...)
		if err != nil {
			return total, err
		}
		ids := make([]int64, 0, cleanupDeleteBatchSize)
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return total, err
			}
			ids = append(ids, id)
		}
		scanErr := rows.Err()
		rows.Close()
		if scanErr != nil {
			return total, scanErr
		}
		if len(ids) == 0 {
			return total, nil
		}
		cursor = ids[len(ids)-1]

		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
		deleteArgs := make([]interface{}, 0, len(ids))
		for _, id := range ids {
			deleteArgs = append(deleteArgs, id)
		}
		result, err := db.ExecContext(
			ctx,
			"DELETE FROM "+table+" WHERE rowid IN ("+placeholders+")",
			deleteArgs...,
		)
		if err != nil {
			return total, err
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return total, err
		}
		total += int(affected)
		if len(ids) < cleanupDeleteBatchSize {
			return total, nil
		}
	}
}
