package agent

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"sophon/internal/toolerror"
	"sophon/internal/toolwire"
)

const (
	toolResultHeaderPrefix = "sophon_tool_result: "
	toolResultDataPrefix   = "sophon_tool_data:\n"
	toolResultSummaryRunes = 240
	maxToolResultRefs      = 50
)

type toolResultStatus string

const (
	toolResultStatusSuccess toolResultStatus = "success"
	toolResultStatusError   toolResultStatus = "error"
	toolResultStatusBlocked toolResultStatus = "blocked"
)

type toolErrorClass = toolerror.Class

const (
	toolErrorPolicy            = toolerror.Policy
	toolErrorAuthorization     = toolerror.Authorization
	toolErrorAuthentication    = toolerror.Authentication
	toolErrorNetwork           = toolerror.Network
	toolErrorTargetUnreachable = toolerror.TargetUnreachable
	toolErrorTimeout           = toolerror.Timeout
	toolErrorRateLimit         = toolerror.RateLimit
	toolErrorCommandExit       = toolerror.CommandExit
	toolErrorNoMatch           = toolerror.NoMatch
	toolErrorTool              = toolerror.Tool
	toolErrorInvalidArguments  = toolerror.InvalidArguments
	toolErrorCancelled         = toolerror.Cancelled
	toolErrorUnknown           = toolerror.Unknown
)

type toolResultHeader struct {
	Status       toolResultStatus `json:"status"`
	Summary      string           `json:"summary"`
	Data         map[string]any   `json:"data,omitempty"`
	ErrorClass   toolErrorClass   `json:"error_class,omitempty"`
	Retryable    bool             `json:"retryable"`
	EvidenceRefs []string         `json:"evidence_refs,omitempty"`
	Artifacts    []string         `json:"artifacts,omitempty"`
	NextActions  []string         `json:"next_actions,omitempty"`
}

type toolErrorClassification struct {
	Class       toolErrorClass
	Retryable   bool
	NextActions []string
}

type toolResultFailure struct {
	class       toolErrorClass
	message     string
	retryable   bool
	nextActions []string
	cause       error
}

func (e *toolResultFailure) Error() string {
	if e == nil {
		return ""
	}
	return strings.TrimSpace(e.message)
}

func (e *toolResultFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func newToolResultFailure(
	class toolErrorClass,
	message string,
	retryable bool,
	cause error,
	nextActions ...string,
) error {
	return &toolResultFailure{
		class:       normalizeToolErrorClass(class),
		message:     strings.TrimSpace(message),
		retryable:   retryable,
		nextActions: normalizeNextActions(nextActions),
		cause:       cause,
	}
}

// renderToolSuccess 把成功结果转换成机器可读头 + 原始正文。
// 正文不重复做 JSON 编码，避免长命令输出、源码和 Skill 内容被转义放大。
func renderToolSuccess(toolName, output string) string {
	toolName = normalizeToolResultName(toolName)
	rawOutput := output
	body, structured := toolwire.SplitStructured(output)
	header := toolResultHeader{
		Status:       toolResultStatusSuccess,
		Summary:      successSummary(toolName, body),
		Data:         toolResultData(structured),
		Retryable:    false,
		EvidenceRefs: extractToolEvidenceRefs(rawOutput),
		Artifacts:    extractToolArtifacts(rawOutput),
	}
	return renderToolResultHeader(header, body)
}

func renderToolError(
	toolName string,
	class toolErrorClass,
	detail string,
	retryable bool,
	nextActions []string,
) string {
	toolName = normalizeToolResultName(toolName)
	class = normalizeToolErrorClass(class)
	detail = strings.TrimSpace(detail)
	if len(nextActions) == 0 {
		nextActions = defaultToolNextActions(class)
	}
	rawDetail := detail
	body, structured := toolwire.SplitStructured(detail)
	header := toolResultHeader{
		Status:       errorStatus(class),
		Summary:      errorSummary(toolName, body, class),
		Data:         toolResultData(structured),
		ErrorClass:   class,
		Retryable:    retryable,
		EvidenceRefs: extractToolEvidenceRefs(rawDetail),
		Artifacts:    extractToolArtifacts(rawDetail),
		NextActions:  normalizeNextActions(nextActions),
	}
	return renderToolResultHeader(header, body)
}

func renderToolResultHeader(header toolResultHeader, body string) string {
	raw, err := json.Marshal(header)
	if err != nil {
		raw = []byte(`{"status":"error","summary":"工具结果编码失败","error_class":"tool_error","retryable":false}`)
	}
	return toolResultHeaderPrefix + string(raw) + "\n" + toolResultDataPrefix + body
}

func parseToolResult(value string) (toolResultHeader, string, bool) {
	line, body, hasBody := strings.Cut(value, "\n")
	if !strings.HasPrefix(line, toolResultHeaderPrefix) {
		return toolResultHeader{}, "", false
	}
	var header toolResultHeader
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, toolResultHeaderPrefix)), &header); err != nil {
		return toolResultHeader{}, "", false
	}
	switch header.Status {
	case toolResultStatusSuccess, toolResultStatusError, toolResultStatusBlocked:
	default:
		return toolResultHeader{}, "", false
	}
	if hasBody {
		body = strings.TrimPrefix(body, toolResultDataPrefix)
	}
	return header, body, true
}

func unwrapToolResult(value string) (string, error) {
	header, body, ok := parseToolResult(value)
	if !ok {
		return value, nil
	}
	if header.Status == toolResultStatusSuccess {
		return restoreStructuredContent(body, header.Data)
	}
	message := strings.TrimSpace(body)
	if message == "" {
		message = strings.TrimSpace(header.Summary)
	}
	return "", newToolResultFailure(
		header.ErrorClass,
		message,
		header.Retryable,
		nil,
		header.NextActions...,
	)
}

func toolResultData(structured json.RawMessage) map[string]any {
	data := map[string]any{"format": "text"}
	if len(structured) == 0 {
		return data
	}
	var value any
	if err := json.Unmarshal(structured, &value); err == nil && value != nil {
		data["structured"] = value
	}
	return data
}

func restoreStructuredContent(body string, data map[string]any) (string, error) {
	if data == nil || data["structured"] == nil {
		return body, nil
	}
	return toolwire.AppendStructured(body, data["structured"])
}

func addToolResultEventData(data map[string]interface{}, value string) {
	if data == nil {
		return
	}
	header, body, ok := parseToolResult(value)
	if !ok {
		data["result"] = value
		return
	}
	data["result"] = body
	data["toolStatus"] = string(header.Status)
	if header.ErrorClass != "" {
		data["errorClass"] = string(header.ErrorClass)
	}
	data["retryable"] = header.Retryable
	if len(header.EvidenceRefs) > 0 {
		data["evidenceRefs"] = append([]string(nil), header.EvidenceRefs...)
	}
	if len(header.Artifacts) > 0 {
		data["artifacts"] = append([]string(nil), header.Artifacts...)
	}
	if len(header.NextActions) > 0 {
		data["nextActions"] = append([]string(nil), header.NextActions...)
	}
}

func classifyToolResultError(ctx context.Context, err error, detail string) toolErrorClassification {
	var failure *toolResultFailure
	if errors.As(err, &failure) && failure != nil {
		class := normalizeToolErrorClass(failure.class)
		actions := failure.nextActions
		if len(actions) == 0 {
			actions = defaultToolNextActions(class)
		}
		return toolErrorClassification{
			Class:       class,
			Retryable:   failure.retryable,
			NextActions: actions,
		}
	}
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return toolErrorClassification{Class: toolErrorCancelled}
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return classificationForClass(toolErrorTimeout)
	}
	streamError := errors.New(strings.TrimSpace(detail + "\n" + errorText(err)))
	streamMessage := strings.ToLower(streamError.Error())
	if upstreamStreamFailure(streamError) &&
		(strings.Contains(streamMessage, "failed to receive stream chunk") ||
			strings.Contains(streamMessage, "failed to stream tool call") ||
			strings.Contains(streamMessage, "while reading body")) {
		return classificationForClass(toolErrorNetwork)
	}

	return classificationForClass(toolerror.Classify(detail + "\n" + errorText(err)))
}

func classificationForClass(class toolErrorClass) toolErrorClassification {
	class = normalizeToolErrorClass(class)
	return toolErrorClassification{
		Class:       class,
		Retryable:   toolerror.Retryable(class),
		NextActions: toolerror.NextActions(class),
	}
}

func defaultToolNextActions(class toolErrorClass) []string {
	return toolerror.NextActions(class)
}

func errorStatus(class toolErrorClass) toolResultStatus {
	if toolerror.Blocked(class) {
		return toolResultStatusBlocked
	}
	return toolResultStatusError
}

func normalizeToolErrorClass(class toolErrorClass) toolErrorClass {
	return toolerror.Normalize(class)
}

func normalizeToolResultName(toolName string) string {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return "unknown"
	}
	return toolName
}

func successSummary(toolName, output string) string {
	summary := toolName + " 执行成功"
	if line := firstDisplayLine(output); line != "" {
		summary += "：" + line
	}
	return truncateRunes(summary, toolResultSummaryRunes)
}

func errorSummary(toolName, detail string, class toolErrorClass) string {
	summary := toolName + " 执行失败"
	if class != "" {
		summary += " [" + string(normalizeToolErrorClass(class)) + "]"
	}
	if line := firstDisplayLine(detail); line != "" {
		summary += "：" + line
	}
	return truncateRunes(summary, toolResultSummaryRunes)
}

func firstDisplayLine(value string) string {
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(strings.ReplaceAll(line, "\r", ""))
		if line != "" {
			return truncateRunes(line, 160)
		}
	}
	return ""
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func normalizeNextActions(actions []string) []string {
	result := make([]string, 0, len(actions))
	seen := make(map[string]bool, len(actions))
	for _, action := range actions {
		action = strings.TrimSpace(action)
		if action == "" || seen[action] {
			continue
		}
		seen[action] = true
		result = append(result, action)
	}
	return result
}

var (
	toolEvidenceRefPattern = regexp.MustCompile(`(?m)(?:\[sophon evidence_ref\]\s*|evidence_ref:\s*)((?:tool|fact|artifact|file|conversation):[^\s<>"']+)`)
	toolArtifactPattern    = regexp.MustCompile(`(?m)^\s*artifact:\s*(.+?)\s*$`)
)

func extractToolEvidenceRefs(value string) []string {
	matches := toolEvidenceRefPattern.FindAllStringSubmatch(value, -1)
	refs := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) == 2 {
			refs = append(refs, match[1])
		}
	}
	return normalizeToolResultRefs(refs)
}

func extractToolArtifacts(value string) []string {
	items := make([]string, 0)
	for _, match := range toolArtifactPattern.FindAllStringSubmatch(value, -1) {
		if len(match) == 2 {
			items = append(items, strings.TrimSpace(match[1]))
		}
	}
	for _, ref := range extractToolEvidenceRefs(value) {
		if strings.HasPrefix(ref, "file:") || strings.HasPrefix(ref, "artifact:") {
			items = append(items, strings.TrimPrefix(strings.TrimPrefix(ref, "file:"), "artifact:"))
		}
	}
	return normalizeToolResultRefs(items)
}

func normalizeToolResultRefs(items []string) []string {
	result := make([]string, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		result = append(result, item)
		if len(result) >= maxToolResultRefs {
			break
		}
	}
	return result
}
