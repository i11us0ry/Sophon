package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrInvalidVulnerabilityEvidence = errors.New("invalid vulnerability evidence")

type EvidenceReferenceOptions struct {
	ProjectID         string
	UserID            string
	Refs              []string
	ArtifactRoot      string
	RequireStructured bool
}

type evidenceRowQuerier interface {
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

// ValidateEvidenceReferences 校验漏洞证据引用是否真实存在且属于当前用户和项目。
func (db *DB) ValidateEvidenceReferences(
	ctx context.Context,
	options EvidenceReferenceOptions,
) error {
	return validateEvidenceReferences(ctx, db, options)
}

func validateEvidenceReferences(
	ctx context.Context,
	queryer evidenceRowQuerier,
	options EvidenceReferenceOptions,
) error {
	projectID := strings.TrimSpace(options.ProjectID)
	userID := strings.TrimSpace(options.UserID)
	validStructured := 0

	for _, item := range normalizeEvidenceRefs(options.Refs) {
		kind, value, ok := strings.Cut(item, ":")
		if !ok {
			continue
		}
		kind = strings.ToLower(strings.TrimSpace(kind))
		value = strings.TrimSpace(value)
		if value == "" {
			return invalidEvidenceReference("证据引用缺少内容: %s", item)
		}

		switch kind {
		case "tool":
			var ownerUserID string
			var status string
			var conversationOwnerID string
			var conversationProjectID string
			err := queryer.QueryRowContext(
				ctx,
				`SELECT t.user_id, t.status,
					COALESCE(c.owner_user_id, ''), COALESCE(c.project_id, '')
				 FROM tool_executions t
				 LEFT JOIN conversations c ON c.id = t.conversation_id
				 WHERE t.id = ?`,
				value,
			).Scan(
				&ownerUserID,
				&status,
				&conversationOwnerID,
				&conversationProjectID,
			)
			if err != nil ||
				ownerUserID != userID ||
				status != "completed" ||
				conversationOwnerID != userID ||
				conversationProjectID != projectID {
				return invalidEvidenceReference("证据工具执行无效或不属于当前项目: %s", item)
			}
			validStructured++
		case "fact":
			if err := validateEvidenceFactReference(
				ctx,
				queryer,
				projectID,
				value,
				item,
			); err != nil {
				return err
			}
			validStructured++
		case "artifact", "file":
			if err := validateEvidenceArtifactReference(
				ctx,
				queryer,
				value,
				options.ArtifactRoot,
				userID,
				projectID,
				item,
			); err != nil {
				return err
			}
			validStructured++
		case "conversation":
			var ownerUserID string
			var conversationProjectID string
			err := queryer.QueryRowContext(
				ctx,
				`SELECT owner_user_id, project_id
				 FROM conversations WHERE id = ?`,
				value,
			).Scan(&ownerUserID, &conversationProjectID)
			if err != nil ||
				ownerUserID != userID ||
				conversationProjectID != projectID {
				return invalidEvidenceReference("证据会话无效或不属于当前项目: %s", item)
			}
			validStructured++
		}
	}

	if options.RequireStructured && validStructured == 0 {
		return invalidEvidenceReference("至少需要一个有效的 tool/file/artifact/fact/conversation 证据引用")
	}
	return nil
}

func validateEvidenceFactReference(
	ctx context.Context,
	queryer evidenceRowQuerier,
	projectID string,
	value string,
	item string,
) error {
	var factProjectID string
	err := queryer.QueryRowContext(
		ctx,
		`SELECT project_id FROM project_facts
		 WHERE id = ? AND valid_to = 0`,
		value,
	).Scan(&factProjectID)
	if err != nil {
		err = queryer.QueryRowContext(
			ctx,
			`SELECT project_id FROM project_facts
			 WHERE project_id = ? AND key = ? AND valid_to = 0`,
			projectID,
			value,
		).Scan(&factProjectID)
	}
	if err != nil || factProjectID != projectID {
		return invalidEvidenceReference("证据事实无效或不属于当前项目: %s", item)
	}
	return nil
}

func validateEvidenceArtifactReference(
	ctx context.Context,
	queryer evidenceRowQuerier,
	value string,
	artifactRoot string,
	userID string,
	projectID string,
	item string,
) error {
	artifactRoot = strings.TrimSpace(artifactRoot)
	if artifactRoot == "" {
		return invalidEvidenceReference("artifact 根目录未配置: %s", item)
	}

	base := filepath.Join(artifactRoot, "data", "conversation_artifacts")
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return invalidEvidenceReference("artifact 根目录不可用: %s", item)
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return invalidEvidenceReference("证据文件路径不合法: %s", item)
	}
	resolvedPath, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return invalidEvidenceReference("证据文件不存在: %s", item)
	}
	relative, err := filepath.Rel(resolvedBase, resolvedPath)
	if err != nil ||
		relative == "." ||
		relative == ".." ||
		strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return invalidEvidenceReference("证据文件不在会话 artifact 目录: %s", item)
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) < 2 || strings.TrimSpace(parts[0]) == "" {
		return invalidEvidenceReference("证据文件不在会话 artifact 目录: %s", item)
	}
	info, err := os.Stat(resolvedPath)
	if err != nil || info.IsDir() {
		return invalidEvidenceReference("证据文件不存在或不是普通文件: %s", item)
	}

	var conversationOwnerID string
	var conversationProjectID string
	err = queryer.QueryRowContext(
		ctx,
		`SELECT owner_user_id, project_id
		 FROM conversations WHERE id = ?`,
		parts[0],
	).Scan(&conversationOwnerID, &conversationProjectID)
	if err != nil ||
		conversationOwnerID != userID ||
		conversationProjectID != projectID {
		return invalidEvidenceReference("证据文件所属会话无效或不属于当前项目: %s", item)
	}
	return nil
}

func validateVulnerabilityEvidenceForIDs(
	ctx context.Context,
	tx *sql.Tx,
	ids []string,
	ownerUserID string,
	artifactRoot string,
) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(
		ctx,
		`SELECT project_id, evidence_refs
		 FROM vulnerabilities
		 WHERE owner_user_id = ? AND id IN (`+placeholders(len(ids))+`)`,
		buildIDArgs([]interface{}{strings.TrimSpace(ownerUserID)}, ids)...,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var projectID string
		var evidenceRefs string
		if err := rows.Scan(&projectID, &evidenceRefs); err != nil {
			return err
		}
		if err := validateEvidenceReferences(
			ctx,
			tx,
			EvidenceReferenceOptions{
				ProjectID:         projectID,
				UserID:            ownerUserID,
				Refs:              decodeEvidenceRefs(evidenceRefs),
				ArtifactRoot:      artifactRoot,
				RequireStructured: true,
			},
		); err != nil {
			return err
		}
	}
	return rows.Err()
}

func invalidEvidenceReference(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidVulnerabilityEvidence, fmt.Sprintf(format, args...))
}
