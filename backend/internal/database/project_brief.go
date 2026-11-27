package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const (
	maxProjectGoalItems       = 5
	maxProjectConstraintItems = 20
	projectBriefGraphVersion  = "project-brief-graph-v1"
)

type ProjectBrief struct {
	Goals       []string
	Constraints []string
}

// ParseProjectBrief 将兼容的自由文本拆成目标和安全约束，避免红线进入 Goal。
func ParseProjectBrief(raw string) ProjectBrief {
	result := ProjectBrief{}
	goalSeen := map[string]bool{}
	constraintSeen := map[string]bool{}
	inConstraints := false

	appendGoal := func(value string) {
		value = normalizeProjectBriefLine(value)
		if value == "" || goalSeen[value] || len(result.Goals) >= maxProjectGoalItems {
			return
		}
		goalSeen[value] = true
		result.Goals = append(result.Goals, value)
	}
	appendConstraint := func(value string) {
		value = normalizeProjectBriefLine(value)
		if value == "" || constraintSeen[value] || len(result.Constraints) >= maxProjectConstraintItems {
			return
		}
		constraintSeen[value] = true
		result.Constraints = append(result.Constraints, value)
	}

	for _, rawLine := range strings.Split(raw, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		heading, content := splitProjectBriefHeading(line)
		if isProjectConstraintHeading(heading) {
			inConstraints = true
			if content != "" {
				appendConstraint(content)
			}
			continue
		}
		if isProjectObjectiveHeading(heading) {
			inConstraints = false
			appendGoal(line)
			continue
		}
		if inConstraints {
			for _, item := range splitProjectBriefItems(line) {
				appendConstraint(item)
			}
			continue
		}
		for _, item := range splitProjectBriefItems(line) {
			appendGoal(item)
		}
	}
	if len(result.Goals) == 0 {
		result.Goals = []string{"完成项目目标"}
	}
	return result
}

func ProjectConstraintsText(raw string) string {
	constraints := ParseProjectBrief(raw).Constraints
	if len(constraints) == 0 {
		return ""
	}
	return strings.Join(constraints, "\n")
}

func ProjectConstraintRef(value string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(value))))
	return "project-constraint:" + hex.EncodeToString(sum[:8])
}

func splitProjectBriefHeading(line string) (string, string) {
	line = strings.TrimSpace(strings.TrimLeft(line, "-*• "))
	for _, delimiter := range []string{"：", ":"} {
		if index := strings.Index(line, delimiter); index >= 0 {
			return strings.TrimSpace(line[:index]), strings.TrimSpace(line[index+len(delimiter):])
		}
	}
	return line, ""
}

func isProjectConstraintHeading(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Contains(value, "安全红线") ||
		strings.Contains(value, "安全约束") ||
		strings.Contains(value, "禁止事项") ||
		strings.Contains(value, "constraints") ||
		strings.Contains(value, "red lines")
}

func isProjectObjectiveHeading(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{
		"资产扩展", "漏洞目标", "权限目标", "测试目标", "评估目标",
		"asset", "vulnerability goal", "privilege goal", "objective",
	} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func splitProjectBriefItems(line string) []string {
	line = strings.TrimSpace(strings.TrimLeft(line, "-*• "))
	if line == "" {
		return nil
	}
	parts := strings.FieldsFunc(line, func(r rune) bool {
		return r == ';' || r == '；'
	})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := normalizeProjectBriefLine(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func normalizeProjectBriefLine(value string) string {
	value = strings.TrimSpace(strings.TrimLeft(value, "-*• "))
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) > maxGraphNodeTitleRun {
		value = string(runes[:maxGraphNodeTitleRun]) + "…"
	}
	return strings.TrimSpace(value)
}

func (db *DB) backfillProjectBriefGraphs(ctx context.Context) error {
	if value, ok, err := db.getAppMetadata(ctx, projectBriefGraphVersion); err != nil {
		return err
	} else if ok && value == "done" {
		return nil
	}
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, owner_user_id, name, description, goals, scope, status, created_at, updated_at
		 FROM projects ORDER BY created_at ASC`,
	)
	if err != nil {
		return err
	}
	items := make([]Project, 0)
	for rows.Next() {
		var item Project
		var createdAt, updatedAt int64
		if err := rows.Scan(
			&item.ID,
			&item.OwnerUserID,
			&item.Name,
			&item.Description,
			&item.Goals,
			&item.Scope,
			&item.Status,
			&createdAt,
			&updatedAt,
		); err != nil {
			rows.Close()
			return err
		}
		item.CreatedAt = time.Unix(createdAt, 0).UTC()
		item.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, project := range items {
		if strings.TrimSpace(project.Goals) == "" {
			continue
		}
		if _, err := db.SyncProjectGraph(ctx, project); err != nil {
			return err
		}
	}
	return db.setAppMetadata(ctx, projectBriefGraphVersion, "done")
}
