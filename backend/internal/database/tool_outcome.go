package database

import (
	"encoding/json"
	"regexp"
	"strings"

	"sophon/internal/redact"
	"sophon/internal/toolerror"
	"sophon/internal/toolwire"
)

const maxToolOutcomeRefs = 50

type ToolExecutionOutcome struct {
	Status            string   `json:"status"`
	Summary           string   `json:"summary,omitempty"`
	ErrorClass        string   `json:"errorClass,omitempty"`
	Retryable         bool     `json:"retryable"`
	EvidenceRefs      []string `json:"evidenceRefs,omitempty"`
	Artifacts         []string `json:"artifacts,omitempty"`
	NextActions       []string `json:"nextActions,omitempty"`
	StructuredContent any      `json:"structuredContent,omitempty"`
}

func buildToolExecutionOutcome(
	rowStatus string,
	result string,
	invokeErr error,
	structuredValues ...any,
) ToolExecutionOutcome {
	body, embedded := toolwire.SplitStructured(result)
	var structured any
	for _, value := range structuredValues {
		if value != nil {
			structured = normalizeStructuredContent(value)
			break
		}
	}
	if structured == nil && len(embedded) > 0 {
		structured = normalizeStructuredContent(embedded)
	}
	detail := strings.TrimSpace(body)
	if detail == "" && invokeErr != nil {
		detail = strings.TrimSpace(invokeErr.Error())
	}
	errorClass := ""
	if invokeErr != nil || rowStatus == "failed" {
		errorClass = string(toolerror.Classify(detail + "\n" + errorMessage(invokeErr)))
	}
	class := toolerror.Class(errorClass)
	retryable := toolerror.Retryable(class)
	nextActions := toolerror.NextActions(class)
	refs := extractOutcomeEvidenceRefs(detail)
	artifacts := extractOutcomeArtifacts(detail)

	summary := firstOutcomeLine(detail)
	if summary == "" {
		if invokeErr != nil {
			summary = strings.TrimSpace(invokeErr.Error())
		} else {
			summary = "工具执行完成"
		}
	}
	return ToolExecutionOutcome{
		Status:            outcomeStatus(invokeErr, errorClass),
		Summary:           truncateToolExecutionText(summary),
		ErrorClass:        errorClass,
		Retryable:         retryable,
		EvidenceRefs:      normalizeOutcomeStrings(refs),
		Artifacts:         normalizeOutcomeStrings(artifacts),
		NextActions:       normalizeOutcomeStrings(nextActions),
		StructuredContent: redact.Value(structured, ""),
	}
}

func marshalToolExecutionOutcome(outcome ToolExecutionOutcome) string {
	outcome.EvidenceRefs = normalizeOutcomeStrings(outcome.EvidenceRefs)
	outcome.Artifacts = normalizeOutcomeStrings(outcome.Artifacts)
	outcome.NextActions = normalizeOutcomeStrings(outcome.NextActions)
	outcome.Summary = redact.Text(outcome.Summary)
	outcome.StructuredContent = redact.Value(outcome.StructuredContent, "")
	raw, err := json.Marshal(outcome)
	if err != nil {
		return "{}"
	}
	if len(raw) <= maxToolExecutionResultBytes {
		return string(raw)
	}
	outcome.StructuredContent = map[string]any{
		"truncated": true,
		"reason":    "structured content exceeds 64KB",
	}
	raw, err = json.Marshal(outcome)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func decodeToolExecutionOutcome(raw string) ToolExecutionOutcome {
	var outcome ToolExecutionOutcome
	if strings.TrimSpace(raw) == "" || raw == "{}" {
		return outcome
	}
	if err := json.Unmarshal([]byte(raw), &outcome); err != nil {
		return ToolExecutionOutcome{}
	}
	return outcome
}

func normalizeStructuredContent(value any) any {
	if value == nil {
		return nil
	}
	if raw, ok := value.(json.RawMessage); ok {
		value = []byte(raw)
	}
	if raw, ok := value.([]byte); ok {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil
		}
		value = decoded
	}
	if text, ok := value.(string); ok {
		var decoded any
		if err := json.Unmarshal([]byte(strings.TrimSpace(text)), &decoded); err != nil {
			return nil
		}
		value = decoded
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return nil
	}
	if _, ok := normalized.(map[string]any); !ok {
		return nil
	}
	return normalized
}

func outcomeStatus(err error, errorClass string) string {
	if toolerror.Blocked(toolerror.Class(errorClass)) {
		return "blocked"
	}
	if err != nil {
		return "error"
	}
	return "success"
}

func normalizeOutcomeStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = truncateOutcomeField(redact.Text(strings.TrimSpace(value)), 500)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
		if len(result) >= maxToolOutcomeRefs {
			break
		}
	}
	return result
}

func truncateOutcomeField(value string, maxRunes int) string {
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return string(runes)
	}
	return string(runes[:maxRunes]) + "..."
}

func firstOutcomeLine(value string) string {
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
		if line != "" {
			return line
		}
	}
	return ""
}

func errorMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

var (
	outcomeEvidenceRefPattern = regexp.MustCompile(`(?m)(?:\[sophon evidence_ref\]\s*|evidence_ref:\s*)((?:tool|fact|artifact|file|conversation):[^\s<>"']+)`)
	outcomeArtifactPattern    = regexp.MustCompile(`(?m)^\s*artifact:\s*(.+?)\s*$`)
)

func extractOutcomeEvidenceRefs(value string) []string {
	matches := outcomeEvidenceRefPattern.FindAllStringSubmatch(value, -1)
	refs := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			refs = append(refs, match[1])
		}
	}
	return normalizeOutcomeStrings(refs)
}

func extractOutcomeArtifacts(value string) []string {
	items := make([]string, 0)
	for _, match := range outcomeArtifactPattern.FindAllStringSubmatch(value, -1) {
		if len(match) == 2 {
			items = append(items, strings.TrimSpace(match[1]))
		}
	}
	for _, ref := range extractOutcomeEvidenceRefs(value) {
		if strings.HasPrefix(ref, "file:") || strings.HasPrefix(ref, "artifact:") {
			items = append(items, strings.TrimPrefix(strings.TrimPrefix(ref, "file:"), "artifact:"))
		}
	}
	return normalizeOutcomeStrings(items)
}
