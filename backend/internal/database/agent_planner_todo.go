package database

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	PlannerTodoPending    = "pending"
	PlannerTodoInProgress = "in_progress"
	PlannerTodoCompleted  = "completed"
)

type AgentPlannerTodo struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversationId"`
	ProjectID      string    `json:"projectId"`
	Content        string    `json:"content"`
	Status         string    `json:"status"`
	SourceIntentID string    `json:"sourceIntentId"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

func normalizePlannerTodoStatus(value string) (string, bool) {
	switch status := strings.ToLower(strings.TrimSpace(value)); status {
	case "", "todo", "open":
		return PlannerTodoPending, true
	case "doing", "in-progress", "running":
		return PlannerTodoInProgress, true
	case "done", "complete":
		return PlannerTodoCompleted, true
	case PlannerTodoPending, PlannerTodoInProgress, PlannerTodoCompleted:
		return status, true
	default:
		return "", false
	}
}

func (db *DB) ListAgentPlannerTodos(
	ctx context.Context,
	conversationID string,
) ([]AgentPlannerTodo, error) {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, conversation_id, project_id, content, status,
			source_intent_id, created_at, updated_at
		 FROM agent_planner_todos
		 WHERE conversation_id = ?
		 ORDER BY created_at ASC, rowid ASC`,
		strings.TrimSpace(conversationID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AgentPlannerTodo, 0)
	for rows.Next() {
		var item AgentPlannerTodo
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.ConversationID,
			&item.ProjectID,
			&item.Content,
			&item.Status,
			&item.SourceIntentID,
			&createdAt,
			&updatedAt,
		); err != nil {
			return nil, err
		}
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		items = append(items, item)
	}
	return items, rows.Err()
}

func (db *DB) ReplaceAgentPlannerTodos(
	ctx context.Context,
	conversationID string,
	projectID string,
	items []AgentPlannerTodo,
) ([]AgentPlannerTodo, error) {
	conversationID = strings.TrimSpace(conversationID)
	projectID = strings.TrimSpace(projectID)
	if conversationID == "" {
		return nil, fmt.Errorf("Planner Todo 会话不能为空")
	}
	if len(items) > 100 {
		items = items[:100]
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM agent_planner_todos WHERE conversation_id = ?`,
		conversationID,
	); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for index := range items {
		item := &items[index]
		item.Content = strings.TrimSpace(item.Content)
		if item.Content == "" {
			continue
		}
		status, ok := normalizePlannerTodoStatus(item.Status)
		if !ok {
			return nil, fmt.Errorf("Planner Todo 状态不合法: %s", item.Status)
		}
		if item.ID == "" {
			item.ID = newID()
		}
		item.ConversationID = conversationID
		item.ProjectID = projectID
		item.Status = status
		item.SourceIntentID = strings.TrimSpace(item.SourceIntentID)
		item.CreatedAt = now
		item.UpdatedAt = now
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO agent_planner_todos (
				id, conversation_id, project_id, content, status,
				source_intent_id, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			item.ID,
			item.ConversationID,
			item.ProjectID,
			item.Content,
			item.Status,
			item.SourceIntentID,
			item.CreatedAt.Unix(),
			item.UpdatedAt.Unix(),
		); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return db.ListAgentPlannerTodos(ctx, conversationID)
}
