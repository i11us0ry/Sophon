package database

import (
	"context"
	"database/sql"
	"time"
)

// ContextMetrics 汇总当前用户的上下文压缩与记忆写入指标（审计监控页使用）。
type ContextMetrics struct {
	Compactions      int
	CompactionsMinor int
	CompactionsMajor int
	AvgRatio         float64
	AvgLatencyMs     float64
	LastAt           time.Time
	MemoryAdd        int
	MemoryUpdate     int
	MemoryNone       int
	MemorySupersede  int
	MemoryTotal      int
	Injections       int
}

// ContextMetrics 汇总压缩与记忆指标；all=true 时返回全局数据（仅管理员调用）。
func (db *DB) ContextMetrics(ctx context.Context, userID string, all bool) (*ContextMetrics, error) {
	metrics := &ContextMetrics{}
	var avgRatio, avgLatency sql.NullFloat64
	var lastAt sql.NullInt64
	compactionQuery := `SELECT COUNT(*),
		        COALESCE(SUM(CASE WHEN c.kind = 'minor' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN c.kind = 'major' THEN 1 ELSE 0 END), 0),
		        AVG(CASE WHEN c.tokens_before > 0 THEN CAST(c.tokens_after AS REAL) / c.tokens_before END),
		        AVG(c.latency_ms),
		        MAX(c.created_at)
		 FROM context_compactions c`
	compactionArgs := []interface{}{}
	if !all {
		compactionQuery += ` JOIN conversations conv ON conv.id = c.conversation_id
		 WHERE conv.owner_user_id = ?`
		compactionArgs = append(compactionArgs, userID)
	}
	if err := db.QueryRowContext(
		ctx,
		compactionQuery,
		compactionArgs...,
	).Scan(
		&metrics.Compactions,
		&metrics.CompactionsMinor,
		&metrics.CompactionsMajor,
		&avgRatio,
		&avgLatency,
		&lastAt,
	); err != nil {
		return nil, err
	}
	if avgRatio.Valid {
		metrics.AvgRatio = avgRatio.Float64
	}
	if avgLatency.Valid {
		metrics.AvgLatencyMs = avgLatency.Float64
	}
	if lastAt.Valid && lastAt.Int64 > 0 {
		metrics.LastAt = time.Unix(lastAt.Int64, 0)
	}

	memoryQuery := `SELECT COUNT(*),
		        COALESCE(SUM(CASE WHEN w.action = 'ADD' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN w.action = 'UPDATE' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN w.action = 'NONE' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN w.action = 'SUPERSEDE' THEN 1 ELSE 0 END), 0)
		 FROM memory_writes w`
	memoryArgs := []interface{}{}
	if !all {
		memoryQuery += ` JOIN projects p ON p.id = w.project_id
		 WHERE p.owner_user_id = ?`
		memoryArgs = append(memoryArgs, userID)
	}
	if err := db.QueryRowContext(
		ctx,
		memoryQuery,
		memoryArgs...,
	).Scan(
		&metrics.MemoryTotal,
		&metrics.MemoryAdd,
		&metrics.MemoryUpdate,
		&metrics.MemoryNone,
		&metrics.MemorySupersede,
	); err != nil {
		return nil, err
	}
	injections, err := db.CountInjectionEvents(ctx, userID, all)
	if err != nil {
		return nil, err
	}
	metrics.Injections = injections
	return metrics, nil
}
