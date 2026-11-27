package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

type workerControlContextKey struct{}

type workerControl struct {
	cancel      context.CancelFunc
	cancelCause context.CancelCauseFunc

	mu        sync.Mutex
	steer     []string
	stopped   bool
	projectID string
	assetID   string

	stopReason  string
	stopMessage string
}

var errWorkerStopped = fmt.Errorf("Worker 已被停止")

func (c *workerControl) addSteer(message string) {
	if c == nil {
		return
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	c.mu.Lock()
	c.steer = append(c.steer, message)
	c.mu.Unlock()
}

func (c *workerControl) takeSteer() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	items := append([]string(nil), c.steer...)
	c.steer = nil
	return items
}

func (c *workerControl) stop(details ...string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	reason := "user_stopped"
	message := "用户停止 Worker"
	if len(details) > 0 && strings.TrimSpace(details[0]) != "" {
		reason = strings.TrimSpace(details[0])
	}
	if len(details) > 1 && strings.TrimSpace(details[1]) != "" {
		message = strings.TrimSpace(details[1])
	}
	c.stopped = true
	c.stopReason = reason
	c.stopMessage = message
	cancel := c.cancel
	cancelCause := c.cancelCause
	c.mu.Unlock()
	if cancelCause != nil {
		cancelCause(errWorkerStopped)
	} else if cancel != nil {
		cancel()
	}
}

func (c *workerControl) isStopped() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopped
}

func (c *workerControl) stopDetails() (string, string) {
	if c == nil {
		return "", ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopReason, c.stopMessage
}

func (c *workerControl) snapshot() map[string]interface{} {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]interface{}{
		"stopped":      c.stopped,
		"pendingSteer": len(c.steer),
		"stopReason":   c.stopReason,
		"stopMessage":  c.stopMessage,
	}
}

func (c *workerControl) bindAsset(projectID, assetID string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.projectID = strings.TrimSpace(projectID)
	c.assetID = strings.TrimSpace(assetID)
	c.mu.Unlock()
}

func (s *Service) StopAssetWorkers(projectID, assetID, reason string) int {
	if s == nil || strings.TrimSpace(assetID) == "" {
		return 0
	}
	s.workerControlMu.Lock()
	controls := make([]*workerControl, 0)
	for _, control := range s.workerControls {
		if control == nil {
			continue
		}
		control.mu.Lock()
		matches := control.assetID == strings.TrimSpace(assetID) &&
			(control.projectID == "" || control.projectID == strings.TrimSpace(projectID))
		control.mu.Unlock()
		if matches {
			controls = append(controls, control)
		}
	}
	s.workerControlMu.Unlock()
	for _, control := range controls {
		control.stop("asset_access_blocked", reason)
	}
	return len(controls)
}

func withWorkerControl(ctx context.Context, control *workerControl) context.Context {
	if control == nil {
		return ctx
	}
	return context.WithValue(ctx, workerControlContextKey{}, control)
}

func workerControlFromContext(ctx context.Context) *workerControl {
	control, _ := ctx.Value(workerControlContextKey{}).(*workerControl)
	return control
}

func shouldBlockWorkerFailure(ctx context.Context, control *workerControl) bool {
	return ctx == nil || ctx.Err() == nil || control.isStopped()
}

func workerControlKey(conversationID, hypothesisID string) string {
	return strings.TrimSpace(conversationID) + "\x00" + strings.TrimSpace(hypothesisID)
}

func workerStopMetadata(ctx context.Context, details ...string) (reason string, message string) {
	if info, ok := execctx.Subagent(ctx); ok &&
		strings.EqualFold(strings.TrimSpace(info.Kind), "planner") {
		reason = "planner_stopped"
		message = "Planner 停止 Worker 以回收并发槽位或终止重复方向"
	} else {
		reason = "user_stopped"
		message = "用户停止 Worker"
	}
	if len(details) > 0 && strings.TrimSpace(details[0]) != "" {
		message = strings.TrimSpace(details[0])
	}
	return reason, message
}

func (s *Service) resolveWorkerReference(
	ctx context.Context,
	projectID string,
	reference string,
) string {
	reference = strings.TrimSpace(reference)
	if reference == "" || s == nil || s.db == nil {
		return reference
	}
	if s.workerControlFor(execctx.ConversationID(ctx), reference) != nil {
		return reference
	}
	items, err := s.db.ListProjectTestResults(ctx, projectID, 500)
	if err != nil {
		return reference
	}
	for _, item := range items {
		if item.ID == reference || item.IntentID == reference {
			return item.ID
		}
	}
	return reference
}

func (s *Service) registerWorkerControl(
	conversationID string,
	hypothesisID string,
	cancel context.CancelFunc,
	cancelCause ...context.CancelCauseFunc,
) *workerControl {
	control := &workerControl{cancel: cancel}
	if len(cancelCause) > 0 {
		control.cancelCause = cancelCause[0]
	}
	if s == nil || strings.TrimSpace(hypothesisID) == "" {
		return control
	}
	s.workerControlMu.Lock()
	if s.workerControls == nil {
		s.workerControls = map[string]*workerControl{}
	}
	s.workerControls[workerControlKey(conversationID, hypothesisID)] = control
	s.workerControlMu.Unlock()
	return control
}

func (s *Service) unregisterWorkerControl(
	conversationID string,
	hypothesisID string,
	control *workerControl,
) {
	if s == nil || strings.TrimSpace(hypothesisID) == "" {
		return
	}
	key := workerControlKey(conversationID, hypothesisID)
	s.workerControlMu.Lock()
	if s.workerControls[key] == control {
		delete(s.workerControls, key)
	}
	s.workerControlMu.Unlock()
}

func (s *Service) workerControlFor(
	conversationID string,
	hypothesisID string,
) *workerControl {
	if s == nil || strings.TrimSpace(hypothesisID) == "" {
		return nil
	}
	s.workerControlMu.Lock()
	defer s.workerControlMu.Unlock()
	return s.workerControls[workerControlKey(conversationID, hypothesisID)]
}

func (s *Service) steerWorker(
	conversationID string,
	hypothesisID string,
	message string,
) error {
	message = strings.TrimSpace(message)
	if message == "" {
		return fmt.Errorf("steer_worker 需要非空 message")
	}
	control := s.workerControlFor(conversationID, hypothesisID)
	if control == nil {
		return fmt.Errorf("Worker %s 当前未运行", strings.TrimSpace(hypothesisID))
	}
	control.addSteer(message)
	return nil
}

func (s *Service) stopWorker(
	ctx context.Context,
	conversationID string,
	hypothesisID string,
	details ...string,
) error {
	hypothesisID = strings.TrimSpace(hypothesisID)
	if hypothesisID == "" {
		return fmt.Errorf("stop_worker 需要 hypothesisId")
	}
	control := s.workerControlFor(conversationID, hypothesisID)
	if control == nil {
		return fmt.Errorf("Worker %s 当前未运行", hypothesisID)
	}
	projectID := strings.TrimSpace(execctx.ProjectID(ctx))
	stopReason, stopMessage := workerStopMetadata(ctx, details...)
	if s != nil && s.db != nil && projectID != "" {
		if hypothesis, err := s.db.GetProjectTestResultByID(ctx, projectID, hypothesisID); err == nil &&
			hypothesis != nil {
			s.markCoordinatedHypothesisState(
				ctx,
				*hypothesis,
				database.ProjectExecutionStopped,
				database.ProjectOutcomeUnknown,
				stopReason,
				stopMessage,
				"",
			)
		}
	}
	control.stop(stopReason, stopMessage)
	return nil
}

func (s *Service) workerControlsSnapshot(conversationID string) []map[string]interface{} {
	if s == nil {
		return nil
	}
	prefix := workerControlKey(conversationID, "")
	s.workerControlMu.Lock()
	defer s.workerControlMu.Unlock()
	items := make([]map[string]interface{}, 0, len(s.workerControls))
	for key, control := range s.workerControls {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		item := control.snapshot()
		if item == nil {
			continue
		}
		item["hypothesisId"] = strings.TrimPrefix(key, prefix)
		items = append(items, item)
	}
	return items
}

func workerSteerMessage(messages []string) string {
	messages = nonEmptyWorkerMessages(messages)
	if len(messages) == 0 {
		return ""
	}
	var builder strings.Builder
	builder.WriteString("【规划者实时纠偏】\n")
	for _, message := range messages {
		builder.WriteString("- ")
		builder.WriteString(message)
		builder.WriteString("\n")
	}
	builder.WriteString("本次工具调用未执行。请立即按上述纠偏重新规划下一步，不要继续无效方向。")
	return builder.String()
}

func nonEmptyWorkerMessages(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}
