package database

import (
	"context"
	"strings"
)

func (db *DB) QueuedCampaignConversationIDs(
	ctx context.Context,
	ownerUserID string,
	conversationIDs []string,
) (map[string]bool, error) {
	result := make(map[string]bool)
	ids := make([]string, 0, len(conversationIDs))
	for _, id := range conversationIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return result, nil
	}

	query := `SELECT DISTINCT conversation_id
		FROM campaign_tasks
		WHERE owner_user_id = ? AND status = ?
		  AND conversation_id IN (` + placeholders(len(ids)) + `)`
	args := make([]interface{}, 0, len(ids)+2)
	args = append(args, strings.TrimSpace(ownerUserID), CampaignTaskStatusQueued)
	for _, id := range ids {
		args = append(args, id)
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result[id] = true
	}
	return result, rows.Err()
}
