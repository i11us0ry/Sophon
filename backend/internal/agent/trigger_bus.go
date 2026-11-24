package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

type plannerTriggerSummary struct {
	Kind       string
	IntentID   string
	Detail     string
	Goals      []string
	Hints      []string
	OccurredAt time.Time
}

func (s *Service) emitAgentTrigger(
	ctx context.Context,
	kind string,
	intentID string,
	payload map[string]interface{},
	dedupeKey string,
) {
	if s == nil || s.db == nil {
		return
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	if conversationID == "" {
		return
	}
	_, _ = s.db.EnqueueAgentTrigger(ctx, database.AgentTrigger{
		ConversationID: conversationID,
		ProjectID:      execctx.ProjectID(ctx),
		Kind:           kind,
		IntentID:       intentID,
		Payload:        payload,
		DedupeKey:      dedupeKey,
	})
	if handle := s.orchestrationFor(conversationID); handle != nil {
		handle.signalPlanner()
	}
}

func (s *Service) emitWorkerTerminalTrigger(
	ctx context.Context,
	hypothesis database.ProjectTestResult,
	executionState string,
	reason string,
) {
	kind := database.AgentTriggerDone
	if executionState == database.ProjectExecutionBlocked {
		kind = database.AgentTriggerDone
	}
	payload := map[string]interface{}{
		"executionState": executionState,
		"outcomeState":   hypothesis.OutcomeState,
		"reason":         strings.TrimSpace(reason),
		"summary":        truncateProjectText(hypothesis.Result, 1000),
	}
	dedupe := fmt.Sprintf(
		"done:%s:%s:%d:%s",
		execctx.ConversationID(ctx),
		hypothesis.ID,
		hypothesis.Attempts,
		executionState,
	)
	s.emitAgentTrigger(ctx, kind, hypothesis.ID, payload, dedupe)
}

func plannerTriggerSummaries(items []database.AgentTrigger) []plannerTriggerSummary {
	result := make([]plannerTriggerSummary, 0, len(items))
	for _, item := range items {
		summary := plannerTriggerSummary{
			Kind:       item.Kind,
			IntentID:   item.IntentID,
			OccurredAt: item.CreatedAt,
		}
		if item.Payload != nil {
			summary.Detail = strings.TrimSpace(fmt.Sprint(item.Payload["summary"]))
			summary.Goals = stringSliceValue(item.Payload["goals"])
			summary.Hints = stringSliceValue(item.Payload["hints"])
			if summary.Detail == "" {
				summary.Detail = strings.TrimSpace(fmt.Sprint(item.Payload["reason"]))
			}
		}
		result = append(result, summary)
	}
	return result
}

func renderPlannerTriggers(items []plannerTriggerSummary) string {
	if len(items) == 0 {
		return "本轮由心跳或初始调度唤醒，没有单独的 Worker 完成事件。"
	}
	var builder strings.Builder
	builder.WriteString("本轮实际触发事件：\n")
	for _, item := range items {
		builder.WriteString("- ")
		switch item.Kind {
		case database.AgentTriggerDone:
			builder.WriteString("Worker 结束")
			if item.IntentID != "" {
				builder.WriteString("，意图 " + item.IntentID)
			}
			if item.Detail != "" {
				builder.WriteString("：" + item.Detail)
			}
		case database.AgentTriggerFinding:
			builder.WriteString("Worker 产生 Finding")
			if item.IntentID != "" {
				builder.WriteString("，意图 " + item.IntentID)
			}
			if item.Detail != "" {
				builder.WriteString("：" + item.Detail)
			}
		case database.AgentTriggerHint:
			builder.WriteString("人类新增战略提示")
			if len(item.Hints) > 0 {
				builder.WriteString("：" + strings.Join(item.Hints, "；"))
			}
		case database.AgentTriggerGoal:
			builder.WriteString("人类新增目标")
			if len(item.Goals) > 0 {
				builder.WriteString("：" + strings.Join(item.Goals, "；"))
			}
		case database.AgentTriggerCancelled:
			builder.WriteString("意图被取消")
			if item.IntentID != "" {
				builder.WriteString("：" + item.IntentID)
			}
		default:
			builder.WriteString(item.Kind)
		}
		builder.WriteString("\n")
	}
	return strings.TrimSpace(builder.String())
}

func stringSliceValue(value interface{}) []string {
	switch items := value.(type) {
	case []string:
		return append([]string(nil), items...)
	case []interface{}:
		result := make([]string, 0, len(items))
		for _, item := range items {
			if text := strings.TrimSpace(fmt.Sprint(item)); text != "" {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}
