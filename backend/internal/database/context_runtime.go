package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ConversationTurnDirective struct {
	ID              string    `json:"id"`
	ConversationID  string    `json:"conversationId"`
	ProjectID       string    `json:"projectId"`
	UserMessageID   string    `json:"userMessageId"`
	RunID           string    `json:"runId"`
	Kind            string    `json:"kind"`
	MissionMode     string    `json:"missionMode"`
	Objective       string    `json:"objective"`
	ScopeText       string    `json:"scopeText"`
	TargetRefsJSON  string    `json:"targetRefsJson"`
	CapabilityMode  string    `json:"capabilityMode"`
	Confidence      int       `json:"confidence"`
	ResolverVersion string    `json:"resolverVersion"`
	CreatedAt       time.Time `json:"createdAt"`
}

type ContextSnapshot struct {
	ID             string                   `json:"id"`
	RunID          string                   `json:"runId"`
	ConversationID string                   `json:"conversationId"`
	ProjectID      string                   `json:"projectId"`
	DirectiveID    string                   `json:"directiveId"`
	Mode           string                   `json:"mode"`
	CapabilityMode string                   `json:"capabilityMode"`
	Model          string                   `json:"model"`
	ToolSchemaHash string                   `json:"toolSchemaHash"`
	SummaryVersion int                      `json:"summaryVersion"`
	TotalTokens    int                      `json:"totalTokens"`
	Degraded       bool                     `json:"degraded"`
	CreatedAt      time.Time                `json:"createdAt"`
	Sections       []ContextSnapshotSection `json:"sections,omitempty"`
}

type ContextSnapshotSection struct {
	ID            string    `json:"id"`
	SnapshotID    string    `json:"snapshotId"`
	SectionName   string    `json:"sectionName"`
	SourceType    string    `json:"sourceType"`
	SourceIDsJSON string    `json:"sourceIdsJson"`
	ContentHash   string    `json:"contentHash"`
	TokenEstimate int       `json:"tokenEstimate"`
	TrustLevel    string    `json:"trustLevel"`
	Included      bool      `json:"included"`
	Truncated     bool      `json:"truncated"`
	OmittedReason string    `json:"omittedReason"`
	CreatedAt     time.Time `json:"createdAt"`
}

func (db *DB) CreateConversationTurnDirective(
	ctx context.Context,
	item ConversationTurnDirective,
) (ConversationTurnDirective, error) {
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.UserMessageID = strings.TrimSpace(item.UserMessageID)
	item.RunID = strings.TrimSpace(item.RunID)
	item.Kind = strings.ToLower(strings.TrimSpace(item.Kind))
	item.MissionMode = strings.TrimSpace(item.MissionMode)
	item.Objective = strings.TrimSpace(item.Objective)
	item.ScopeText = strings.TrimSpace(item.ScopeText)
	item.TargetRefsJSON = strings.TrimSpace(item.TargetRefsJSON)
	item.CapabilityMode = strings.ToLower(strings.TrimSpace(item.CapabilityMode))
	item.ResolverVersion = strings.TrimSpace(item.ResolverVersion)
	if item.ConversationID == "" || item.ProjectID == "" || item.Kind == "" {
		return ConversationTurnDirective{}, fmt.Errorf("指令会话、项目和类型不能为空")
	}
	if item.CapabilityMode == "" {
		item.CapabilityMode = "read_only"
	}
	switch item.Kind {
	case "clarify", "continue", "inspect", "modify", "redo", "new_task":
	default:
		return ConversationTurnDirective{}, fmt.Errorf("未知的指令类型: %s", item.Kind)
	}
	switch item.CapabilityMode {
	case "read_only", "analyze", "execute", "write", "admin":
	default:
		return ConversationTurnDirective{}, fmt.Errorf("未知的指令能力模式: %s", item.CapabilityMode)
	}
	if item.TargetRefsJSON == "" {
		item.TargetRefsJSON = "{}"
	}
	if !json.Valid([]byte(item.TargetRefsJSON)) {
		return ConversationTurnDirective{}, fmt.Errorf("指令目标引用不是有效 JSON")
	}
	if item.Confidence < 0 {
		item.Confidence = 0
	}
	if item.Confidence > 100 {
		item.Confidence = 100
	}
	if item.ID == "" {
		item.ID = newID()
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	_, err := db.ExecContext(
		ctx,
		`INSERT INTO conversation_turn_directives (
			id, conversation_id, project_id, user_message_id, run_id, kind,
			mission_mode, objective, scope_text, target_refs_json,
			capability_mode, confidence, resolver_version, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.ConversationID,
		item.ProjectID,
		item.UserMessageID,
		item.RunID,
		item.Kind,
		item.MissionMode,
		item.Objective,
		item.ScopeText,
		item.TargetRefsJSON,
		item.CapabilityMode,
		item.Confidence,
		item.ResolverVersion,
		item.CreatedAt.Unix(),
	)
	if err != nil {
		return ConversationTurnDirective{}, err
	}
	return item, nil
}

func (db *DB) CreateContextSnapshot(
	ctx context.Context,
	item ContextSnapshot,
) (ContextSnapshot, error) {
	item.RunID = strings.TrimSpace(item.RunID)
	item.ConversationID = strings.TrimSpace(item.ConversationID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	if item.RunID == "" || item.ConversationID == "" || item.ProjectID == "" {
		return ContextSnapshot{}, fmt.Errorf("上下文快照运行、会话和项目不能为空")
	}
	if item.ID == "" {
		item.ID = newID()
	}
	if item.CreatedAt.IsZero() {
		item.CreatedAt = time.Now().UTC()
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ContextSnapshot{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO context_snapshots (
			id, run_id, conversation_id, project_id, directive_id, mode,
			capability_mode, model, tool_schema_hash, summary_version,
			total_tokens, degraded, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID,
		item.RunID,
		item.ConversationID,
		item.ProjectID,
		item.DirectiveID,
		item.Mode,
		item.CapabilityMode,
		item.Model,
		item.ToolSchemaHash,
		item.SummaryVersion,
		item.TotalTokens,
		boolToInt(item.Degraded),
		item.CreatedAt.Unix(),
	); err != nil {
		return ContextSnapshot{}, err
	}
	sections := make([]ContextSnapshotSection, 0, len(item.Sections))
	for _, section := range item.Sections {
		section.SectionName = strings.TrimSpace(section.SectionName)
		if section.SectionName == "" {
			continue
		}
		if section.ID == "" {
			section.ID = newID()
		}
		section.SnapshotID = item.ID
		if section.SourceIDsJSON == "" {
			section.SourceIDsJSON = "[]"
		}
		if section.SourceIDsJSON == "null" {
			section.SourceIDsJSON = "[]"
		}
		if !json.Valid([]byte(section.SourceIDsJSON)) {
			return ContextSnapshot{}, fmt.Errorf("上下文分节 %s 的来源 ID 不是有效 JSON", section.SectionName)
		}
		if section.TokenEstimate < 0 {
			section.TokenEstimate = 0
		}
		if section.CreatedAt.IsZero() {
			section.CreatedAt = item.CreatedAt
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO context_snapshot_sections (
				id, snapshot_id, section_name, source_type, source_ids_json,
				content_hash, token_estimate, trust_level, included, truncated,
				omitted_reason, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			section.ID,
			section.SnapshotID,
			section.SectionName,
			section.SourceType,
			section.SourceIDsJSON,
			section.ContentHash,
			section.TokenEstimate,
			section.TrustLevel,
			boolToInt(section.Included),
			boolToInt(section.Truncated),
			section.OmittedReason,
			section.CreatedAt.Unix(),
		); err != nil {
			return ContextSnapshot{}, err
		}
		sections = append(sections, section)
	}
	if err := tx.Commit(); err != nil {
		return ContextSnapshot{}, err
	}
	item.Sections = sections
	return item, nil
}

func (db *DB) GetContextSnapshot(ctx context.Context, runID string) (*ContextSnapshot, error) {
	var item ContextSnapshot
	var createdAt int64
	var degraded int
	err := db.QueryRowContext(
		ctx,
		`SELECT id, run_id, conversation_id, project_id, directive_id, mode,
			capability_mode, model, tool_schema_hash, summary_version,
			total_tokens, degraded, created_at
		 FROM context_snapshots
		 WHERE run_id = ?`,
		strings.TrimSpace(runID),
	).Scan(
		&item.ID,
		&item.RunID,
		&item.ConversationID,
		&item.ProjectID,
		&item.DirectiveID,
		&item.Mode,
		&item.CapabilityMode,
		&item.Model,
		&item.ToolSchemaHash,
		&item.SummaryVersion,
		&item.TotalTokens,
		&degraded,
		&createdAt,
	)
	if err != nil {
		return nil, err
	}
	item.Degraded = degraded != 0
	item.CreatedAt = time.Unix(createdAt, 0).UTC()
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, snapshot_id, section_name, source_type, source_ids_json,
			content_hash, token_estimate, trust_level, included, truncated,
			omitted_reason, created_at
		 FROM context_snapshot_sections
		 WHERE snapshot_id = ?
		 ORDER BY created_at ASC, rowid ASC`,
		item.ID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var section ContextSnapshotSection
		var sectionCreatedAt int64
		var included, truncated int
		if err := rows.Scan(
			&section.ID,
			&section.SnapshotID,
			&section.SectionName,
			&section.SourceType,
			&section.SourceIDsJSON,
			&section.ContentHash,
			&section.TokenEstimate,
			&section.TrustLevel,
			&included,
			&truncated,
			&section.OmittedReason,
			&sectionCreatedAt,
		); err != nil {
			return nil, err
		}
		section.Included = included != 0
		section.Truncated = truncated != 0
		section.CreatedAt = time.Unix(sectionCreatedAt, 0).UTC()
		item.Sections = append(item.Sections, section)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &item, nil
}
