package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
	zhizipkg "sophon/internal/zhizi"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const (
	orchestratorControlToolName = "orchestrator_control"
	projectPauseReasonPrefix    = "[project_pause] "
)

type backgroundOrchestration struct {
	mu          sync.Mutex
	cancel      context.CancelFunc
	status      string
	feedback    []string
	lastError   string
	startedAt   time.Time
	updatedAt   time.Time
	persist     orchestrationPersistFunc
	plannerWake chan struct{}
	workerWake  chan struct{}
	drainWake   chan struct{}
	done        chan struct{}
	doneOnce    sync.Once
	draining    bool
}

type orchestrationPersistFunc func(status string, lastError string, feedback []string)

func newBackgroundOrchestration(
	cancel context.CancelFunc,
	persist ...orchestrationPersistFunc,
) *backgroundOrchestration {
	now := time.Now().UTC()
	handle := &backgroundOrchestration{
		cancel:      cancel,
		status:      database.AgentOrchestrationRunning,
		startedAt:   now,
		updatedAt:   now,
		plannerWake: make(chan struct{}, 1),
		workerWake:  make(chan struct{}, 1),
		drainWake:   make(chan struct{}, 1),
		done:        make(chan struct{}),
	}
	if len(persist) > 0 {
		handle.persist = persist[0]
	}
	return handle
}

func (o *backgroundOrchestration) markDone() {
	if o == nil {
		return
	}
	o.doneOnce.Do(func() {
		o.mu.Lock()
		done := o.done
		o.mu.Unlock()
		if done != nil {
			close(done)
		}
	})
}

func (o *backgroundOrchestration) waitDone(ctx context.Context) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	done := o.done
	o.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *backgroundOrchestration) signalPlanner() {
	if o == nil {
		return
	}
	o.mu.Lock()
	wake := o.plannerWake
	o.mu.Unlock()
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (o *backgroundOrchestration) signalWorkers() {
	if o == nil {
		return
	}
	o.mu.Lock()
	wake := o.workerWake
	o.mu.Unlock()
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (o *backgroundOrchestration) plannerChannel() <-chan struct{} {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.plannerWake
}

func (o *backgroundOrchestration) workerChannel() <-chan struct{} {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.workerWake
}

func (o *backgroundOrchestration) beginDrain() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.draining {
		o.mu.Unlock()
		return
	}
	o.draining = true
	wake := o.drainWake
	o.mu.Unlock()
	if wake == nil {
		return
	}
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (o *backgroundOrchestration) isDraining() bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.draining
}

func (o *backgroundOrchestration) drainChannel() <-chan struct{} {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.drainWake
}

func (o *backgroundOrchestration) setStatus(status string, err error) {
	o.updateStatus(status, err, true)
}

func (o *backgroundOrchestration) setStatusLocal(status string, err error) {
	o.updateStatus(status, err, false)
}

func (o *backgroundOrchestration) updateStatus(status string, err error, persistStatus bool) {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.status = status
	o.updatedAt = time.Now().UTC()
	if err != nil {
		o.lastError = err.Error()
	} else {
		o.lastError = ""
	}
	lastError := o.lastError
	feedback := append([]string(nil), o.feedback...)
	persist := o.persist
	o.mu.Unlock()
	if persistStatus && persist != nil {
		persist(status, lastError, feedback)
	}
}

func (o *backgroundOrchestration) addFeedback(message string) {
	if o == nil {
		return
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	o.mu.Lock()
	o.feedback = append(o.feedback, message)
	o.updatedAt = time.Now().UTC()
	feedback := append([]string(nil), o.feedback...)
	status := o.status
	lastError := o.lastError
	persist := o.persist
	o.mu.Unlock()
	if persist != nil {
		persist(status, lastError, feedback)
	}
}

func (o *backgroundOrchestration) takeFeedback() []string {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	items := append([]string(nil), o.feedback...)
	o.feedback = nil
	status := o.status
	lastError := o.lastError
	persist := o.persist
	o.mu.Unlock()
	if persist != nil {
		persist(status, lastError, nil)
	}
	return items
}

func (o *backgroundOrchestration) snapshot() map[string]interface{} {
	if o == nil {
		return map[string]interface{}{"status": "idle"}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return map[string]interface{}{
		"status":    o.status,
		"lastError": o.lastError,
		"feedback":  len(o.feedback),
		"draining":  o.draining,
		"startedAt": o.startedAt,
		"updatedAt": o.updatedAt,
	}
}

func (s *Service) orchestrationFor(conversationID string) *backgroundOrchestration {
	if s == nil || strings.TrimSpace(conversationID) == "" {
		return nil
	}
	s.orchestrationMu.Lock()
	defer s.orchestrationMu.Unlock()
	return s.orchestrations[conversationID]
}

// StopConversationOrchestration 停止并等待已删除会话的内存编排退出，项目任务由数据库接管。
func (s *Service) StopConversationOrchestration(
	ctx context.Context,
	conversationID string,
) (bool, error) {
	conversationID = strings.TrimSpace(conversationID)
	if s == nil || conversationID == "" {
		return false, nil
	}
	s.orchestrationMu.Lock()
	handle := s.orchestrations[conversationID]
	if handle != nil {
		delete(s.orchestrations, conversationID)
	}
	s.orchestrationMu.Unlock()
	if handle == nil {
		return false, nil
	}
	status, _ := handle.snapshot()["status"].(string)
	handle.setStatusLocal(database.AgentOrchestrationStopped, nil)
	handle.mu.Lock()
	cancel := handle.cancel
	handle.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if status == database.AgentOrchestrationRunning {
		if err := handle.waitDone(ctx); err != nil {
			s.orchestrationMu.Lock()
			if s.orchestrations == nil {
				s.orchestrations = map[string]*backgroundOrchestration{}
			}
			if s.orchestrations[conversationID] == nil {
				s.orchestrations[conversationID] = handle
			}
			s.orchestrationMu.Unlock()
			return true, fmt.Errorf("等待旧后台编排退出失败: %w", err)
		}
	}
	return true, nil
}

func (s *Service) currentOrchestrationFeedback(ctx context.Context) []string {
	return s.orchestrationFor(execctx.ConversationID(ctx)).takeFeedback()
}

func (s *Service) reviveCoordinatedRuntime(ctx context.Context) error {
	if s == nil || s.db == nil {
		return nil
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	projectID := strings.TrimSpace(execctx.ProjectID(ctx))
	if conversationID == "" || projectID == "" {
		return nil
	}
	if handle := s.orchestrationFor(conversationID); handle != nil {
		status, _ := handle.snapshot()["status"].(string)
		if status == database.AgentOrchestrationRunning {
			handle.signalPlanner()
			handle.signalWorkers()
			return nil
		}
	}
	execution, ok := missionExecutionFromContext(ctx)
	if !ok || !execution.Plan.Coordinated {
		return nil
	}
	if err := s.startBackgroundOrchestration(ctx, execution, projectID); err != nil {
		return err
	}
	if handle := s.orchestrationFor(conversationID); handle != nil {
		handle.signalPlanner()
		handle.signalWorkers()
	}
	return nil
}

func (s *Service) startBackgroundOrchestration(
	parent context.Context,
	execution missionExecution,
	projectID string,
) error {
	return s.startBackgroundOrchestrationWithFeedback(parent, execution, projectID, nil)
}

func (s *Service) startBackgroundOrchestrationWithFeedback(
	parent context.Context,
	execution missionExecution,
	projectID string,
	initialFeedback []string,
) error {
	if s == nil || s.db == nil {
		return nil
	}
	s.resetLLMCircuit()
	conversationID := strings.TrimSpace(execctx.ConversationID(parent))
	projectID = strings.TrimSpace(projectID)
	ownerUserID := strings.TrimSpace(execctx.UserID(parent))
	if conversationID == "" || projectID == "" || ownerUserID == "" {
		return fmt.Errorf("后台编排缺少会话、项目或用户上下文")
	}
	s.orchestrationMu.Lock()
	if s.orchestrations == nil {
		s.orchestrations = map[string]*backgroundOrchestration{}
	}
	if existing := s.orchestrations[conversationID]; existing != nil {
		snapshot := existing.snapshot()
		if snapshot["status"] == "running" {
			s.orchestrationMu.Unlock()
			return nil
		}
		initialFeedback = append(initialFeedback, existing.takeFeedback()...)
	}
	ctx, cancel := context.WithCancel(context.Background())
	persist := s.orchestrationStatePersister(conversationID)
	planJSON, err := marshalPersistedMissionPlan(execution.Plan)
	if err != nil {
		s.orchestrationMu.Unlock()
		cancel()
		return fmt.Errorf("编码后台编排计划失败: %w", err)
	}
	now := time.Now().UTC()
	if err := s.db.UpsertAgentOrchestration(ctx, database.AgentOrchestration{
		ConversationID: conversationID,
		ProjectID:      projectID,
		OwnerUserID:    ownerUserID,
		Status:         database.AgentOrchestrationRunning,
		PlanJSON:       planJSON,
		Phase:          execution.Phase,
		AgentMode:      execution.AgentMode,
		RunID:          execctx.RunID(parent),
		MessageID:      execctx.MessageID(parent),
		CampaignID:     execctx.CampaignID(parent),
		CampaignTaskID: execctx.CampaignTaskID(parent),
		Feedback:       initialFeedback,
		StartedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		s.orchestrationMu.Unlock()
		cancel()
		return fmt.Errorf("保存后台编排状态失败: %w", err)
	}
	handle := newBackgroundOrchestration(cancel, persist)
	for _, message := range initialFeedback {
		handle.addFeedback(message)
	}
	s.orchestrations[conversationID] = handle
	s.orchestrationMu.Unlock()

	ctx = execctx.WithConversationID(ctx, conversationID)
	ctx = execctx.WithUserID(ctx, ownerUserID)
	ctx = execctx.WithMessageID(ctx, execctx.MessageID(parent))
	ctx = execctx.WithProjectID(ctx, projectID)
	ctx = execctx.WithRunID(ctx, execctx.RunID(parent))
	ctx = execctx.WithRunMode(ctx, execctx.RunMode(parent))
	ctx = execctx.WithAssetID(ctx, execctx.AssetID(parent))
	ctx = execctx.WithCampaignID(ctx, execctx.CampaignID(parent))
	ctx = execctx.WithCampaignTaskID(ctx, execctx.CampaignTaskID(parent))
	ctx = execctx.WithAuthorizedScopes(ctx, execution.Plan.AuthorizedScopes)
	restriction, err := s.db.GetConversationAssetRestriction(ctx, conversationID)
	if err != nil {
		restriction = true
	}
	ctx = execctx.WithAssetRestriction(ctx, restriction)
	autoContinue, err := s.db.GetConversationAutoContinue(ctx, conversationID)
	if err != nil {
		autoContinue = true
	}
	ctx = execctx.WithAutoContinue(ctx, autoContinue)
	ctx = withMissionExecution(ctx, execution)
	ctx = withMissionObjectiveState(ctx)
	ctx = withCoordinatedRunState(ctx)
	releaseZhiziLease, err := s.acquireBackgroundZhiziLease(ctx, conversationID, ownerUserID)
	if err != nil {
		handle.setStatus(database.AgentOrchestrationFailed, err)
		cancel()
		return err
	}
	batcher := newProcessDetailBatcher(s.db)
	ctx = withProcessDetailBatcher(ctx, batcher)

	go func() {
		defer handle.markDone()
		defer cancel()
		defer releaseZhiziLease()
		defer func() {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), processDetailWriteTimeout)
			defer closeCancel()
			_ = batcher.Close(closeCtx)
		}()
		_, runErr := s.runCoordinatedMissionLoop(ctx, execution, projectID, false, handle)
		status, _ := handle.snapshot()["status"].(string)
		if runErr != nil && isGlobalLLMError(runErr) {
			handle.setStatus(database.AgentOrchestrationPaused, runErr)
			s.enqueueOrchestrationUpdate(ctx, database.AgentOrchestrationPaused, runErr)
			return
		}
		if status != database.AgentOrchestrationPaused &&
			status != database.AgentOrchestrationStopped {
			terminalStatus := database.AgentOrchestrationCompleted
			if runErr != nil {
				terminalStatus = database.AgentOrchestrationFailed
			}
			s.enqueueOrchestrationUpdate(ctx, terminalStatus, runErr)
		}
		if runErr != nil {
			if status == database.AgentOrchestrationPaused ||
				status == database.AgentOrchestrationStopped {
				return
			}
			handle.setStatus(database.AgentOrchestrationFailed, runErr)
			return
		}
		handle.setStatus(database.AgentOrchestrationCompleted, nil)
	}()
	return nil
}

func (s *Service) acquireBackgroundZhiziLease(
	ctx context.Context,
	conversationID string,
	ownerUserID string,
) (func(), error) {
	noop := func() {}
	if s == nil || s.db == nil {
		return noop, nil
	}
	state, err := s.db.GetZhiziConversationState(ctx, conversationID, ownerUserID)
	if err != nil {
		return noop, fmt.Errorf("读取智子分身状态失败: %w", err)
	}
	if !state.Enabled {
		return noop, nil
	}
	lease := state.Lease
	if lease == nil {
		lease, err = s.db.AcquireZhiziLease(
			ctx,
			conversationID,
			ownerUserID,
			zhizipkg.DefaultTTL,
		)
		if err != nil {
			return noop, fmt.Errorf("后台编排获取智子分身失败: %w", err)
		}
	}
	if lease == nil {
		return noop, fmt.Errorf("后台编排没有可用的智子分身租约")
	}
	stopHeartbeat := s.startZhiziLeaseHeartbeat(context.Background(), lease.ID)
	return func() {
		stopHeartbeat()
		releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.db.ReleaseZhiziLeaseByConversation(releaseCtx, conversationID)
	}, nil
}

func marshalPersistedMissionPlan(plan missionPlan) (string, error) {
	plan.AuthorizationQuote = ""
	plan.ProjectScopeQuote = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func (s *Service) orchestrationStatePersister(
	conversationID string,
) orchestrationPersistFunc {
	if s == nil || s.db == nil {
		return nil
	}
	return func(status string, lastError string, feedback []string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = s.db.UpdateAgentOrchestrationState(
			ctx,
			conversationID,
			status,
			lastError,
			feedback,
		)
	}
}

func (s *Service) RecoverBackgroundOrchestrations(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	records, err := s.db.ListRecoverableAgentOrchestrations(ctx)
	if err != nil {
		return 0, fmt.Errorf("读取待恢复后台编排失败: %w", err)
	}
	maxRunning := s.configSnapshot().AgentMaxConcurrentSessions
	if maxRunning <= 0 {
		maxRunning = 5
	}
	recovered := 0
	running := 0
	var firstErr error
	for _, record := range records {
		if strings.EqualFold(record.Status, database.AgentOrchestrationPaused) {
			s.restorePausedOrchestration(record)
			recovered++
			continue
		}
		if running >= maxRunning {
			s.pauseDeferredOrchestration(record)
			recovered++
			continue
		}
		if err := s.recoverRunningOrchestration(ctx, record); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			s.pauseUnrecoverableOrchestration(record, err)
			continue
		}
		running++
		recovered++
	}
	return recovered, firstErr
}

func (s *Service) restorePausedOrchestration(record database.AgentOrchestration) {
	if s == nil {
		return
	}
	handle := &backgroundOrchestration{
		status:      database.AgentOrchestrationPaused,
		feedback:    append([]string(nil), record.Feedback...),
		lastError:   record.LastError,
		startedAt:   record.StartedAt,
		updatedAt:   record.UpdatedAt,
		persist:     s.orchestrationStatePersister(record.ConversationID),
		plannerWake: make(chan struct{}, 1),
		workerWake:  make(chan struct{}, 1),
		drainWake:   make(chan struct{}, 1),
		done:        make(chan struct{}),
	}
	s.orchestrationMu.Lock()
	if s.orchestrations == nil {
		s.orchestrations = map[string]*backgroundOrchestration{}
	}
	s.orchestrations[record.ConversationID] = handle
	s.orchestrationMu.Unlock()
}

func (s *Service) recoverRunningOrchestration(
	ctx context.Context,
	record database.AgentOrchestration,
) error {
	conversation, err := s.db.GetConversation(ctx, record.ConversationID, record.OwnerUserID)
	if err != nil {
		return fmt.Errorf("读取恢复会话失败: %w", err)
	}
	if strings.TrimSpace(conversation.ProjectID) != strings.TrimSpace(record.ProjectID) {
		return fmt.Errorf("编排项目与会话项目不一致")
	}
	project, err := s.db.GetActiveProject(ctx, record.ProjectID, record.OwnerUserID)
	if err != nil {
		return fmt.Errorf("项目不可恢复: %w", err)
	}
	var plan missionPlan
	if err := json.Unmarshal([]byte(record.PlanJSON), &plan); err != nil {
		return fmt.Errorf("解析恢复计划失败: %w", err)
	}
	if !plan.Coordinated {
		return fmt.Errorf("恢复计划不是协调任务")
	}
	runID := strings.TrimSpace(record.RunID)
	messageID := strings.TrimSpace(record.MessageID)
	if runID == "" || messageID == "" {
		latestRun, err := s.db.GetLatestAgentRun(ctx, record.ConversationID)
		if err != nil || latestRun == nil {
			return fmt.Errorf("缺少可恢复的 Agent 运行消息")
		}
		runID = strings.TrimSpace(latestRun.ID)
		messageID = strings.TrimSpace(latestRun.AssistantMessageID)
	}
	if runID == "" || messageID == "" {
		return fmt.Errorf("缺少可恢复的 Agent 运行消息")
	}
	assets, err := s.db.ListProjectAssets(ctx, project.ID, record.OwnerUserID)
	if err != nil {
		return fmt.Errorf("读取恢复项目资产失败: %w", err)
	}
	recoverCtx := context.Background()
	recoverCtx = execctx.WithConversationID(recoverCtx, record.ConversationID)
	recoverCtx = execctx.WithUserID(recoverCtx, record.OwnerUserID)
	recoverCtx = execctx.WithMessageID(recoverCtx, messageID)
	recoverCtx = execctx.WithProjectID(recoverCtx, project.ID)
	recoverCtx = execctx.WithRunID(recoverCtx, runID)
	recoverCtx = execctx.WithRunMode(recoverCtx, record.AgentMode)
	recoverCtx = execctx.WithAssetID(recoverCtx, conversation.AssetID)
	recoverCtx = execctx.WithCampaignID(recoverCtx, record.CampaignID)
	recoverCtx = execctx.WithCampaignTaskID(recoverCtx, record.CampaignTaskID)
	recoverCtx = execctx.WithAuthorizedScopes(recoverCtx, plan.AuthorizedScopes)
	execution := missionExecution{
		Plan:      plan,
		Phase:     record.Phase,
		Scope:     missionScopeFromPlan(recoverCtx, plan, assets),
		AgentMode: record.AgentMode,
	}
	return s.startBackgroundOrchestrationWithFeedback(
		recoverCtx,
		execution,
		project.ID,
		record.Feedback,
	)
}

func (s *Service) pauseUnrecoverableOrchestration(
	record database.AgentOrchestration,
	recoverErr error,
) {
	if s == nil || s.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	message := "服务重启后无法自动恢复：" + recoverErr.Error()
	_ = s.db.UpdateAgentOrchestrationState(
		ctx,
		record.ConversationID,
		database.AgentOrchestrationPaused,
		message,
		record.Feedback,
	)
	record.Status = database.AgentOrchestrationPaused
	record.LastError = message
	s.restorePausedOrchestration(record)
}

func (s *Service) pauseDeferredOrchestration(record database.AgentOrchestration) {
	if s == nil || s.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	message := "服务已重启，当前恢复并发槽位已满；可在主 Agent 中恢复此任务"
	_ = s.db.UpdateAgentOrchestrationState(
		ctx,
		record.ConversationID,
		database.AgentOrchestrationPaused,
		message,
		record.Feedback,
	)
	record.Status = database.AgentOrchestrationPaused
	record.LastError = message
	s.restorePausedOrchestration(record)
}

func (s *Service) controlOrchestration(
	ctx context.Context,
	action string,
	message string,
	hypothesisID ...string,
) (map[string]interface{}, error) {
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	handle := s.orchestrationFor(conversationID)
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "status":
		return s.orchestrationStatus(ctx, handle), nil
	case "steer":
		if handle == nil {
			return nil, fmt.Errorf("当前没有运行中的后台编排")
		}
		handle.addFeedback(message)
		return s.orchestrationStatus(ctx, handle), nil
	case "steer_worker":
		target := ""
		if len(hypothesisID) > 0 {
			target = s.resolveWorkerReference(
				ctx,
				strings.TrimSpace(execctx.ProjectID(ctx)),
				hypothesisID[0],
			)
		}
		if err := s.steerWorker(conversationID, target, message); err != nil {
			return nil, err
		}
		return s.orchestrationStatus(ctx, handle), nil
	case "worker_output", "worker_trace":
		target := ""
		if len(hypothesisID) > 0 {
			target = s.resolveWorkerReference(
				ctx,
				strings.TrimSpace(execctx.ProjectID(ctx)),
				hypothesisID[0],
			)
		}
		if target == "" {
			return nil, fmt.Errorf("%s 需要 hypothesisId", action)
		}
		sessionID := database.AgentSessionID(
			conversationID,
			database.AgentRoleWorker,
			"",
			target,
		)
		limit := 40
		if action == "worker_trace" {
			limit = 200
		}
		details, total, hasMore, err := s.db.ListAgentSessionDetailsPage(
			ctx,
			conversationID,
			sessionID,
			limit,
			0,
		)
		if err != nil {
			return nil, err
		}
		payload := s.orchestrationStatus(ctx, handle)
		payload["hypothesisId"] = target
		payload["sessionId"] = sessionID
		payload["total"] = total
		payload["hasMore"] = hasMore
		if action == "worker_output" {
			payload["output"] = workerOutputDetails(details)
		} else {
			payload["trace"] = details
		}
		return payload, nil
	case "stop_worker":
		target := ""
		if len(hypothesisID) > 0 {
			target = s.resolveWorkerReference(
				ctx,
				strings.TrimSpace(execctx.ProjectID(ctx)),
				hypothesisID[0],
			)
		}
		if err := s.stopWorker(ctx, conversationID, target, message); err != nil {
			return nil, err
		}
		return s.orchestrationStatus(ctx, handle), nil
	case "pause":
		if handle == nil {
			return nil, fmt.Errorf("当前没有运行中的后台编排")
		}
		projectID := strings.TrimSpace(execctx.ProjectID(ctx))
		if projectID != "" {
			_, _ = s.db.PauseRunningProjectHypothesesForConversation(
				ctx,
				projectID,
				conversationID,
				"任务暂停，Worker 已释放为可恢复状态",
			)
		}
		handle.mu.Lock()
		cancel := handle.cancel
		handle.mu.Unlock()
		handle.setStatus(database.AgentOrchestrationPaused, nil)
		if cancel != nil {
			cancel()
		}
		return s.orchestrationStatus(ctx, handle), nil
	case "resume":
		execution, ok := missionExecutionFromContext(ctx)
		if !ok || !execution.Plan.Coordinated {
			return nil, fmt.Errorf("当前会话没有可恢复的协调任务")
		}
		if err := s.startBackgroundOrchestration(
			ctx,
			execution,
			strings.TrimSpace(execctx.ProjectID(ctx)),
		); err != nil {
			return nil, err
		}
		projectID := strings.TrimSpace(execctx.ProjectID(ctx))
		if projectID != "" {
			_, _ = s.db.ResumePausedProjectHypothesesForConversation(
				ctx,
				projectID,
				conversationID,
			)
		}
		if activeHandle := s.orchestrationFor(conversationID); activeHandle != nil {
			activeHandle.signalPlanner()
			activeHandle.signalWorkers()
		}
		return s.orchestrationStatus(ctx, s.orchestrationFor(conversationID)), nil
	case "resume_project":
		execution, ok := missionExecutionFromContext(ctx)
		if !ok || !execution.Plan.Coordinated {
			return nil, fmt.Errorf("当前会话没有可恢复的协调任务")
		}
		if err := s.startBackgroundOrchestration(
			ctx,
			execution,
			strings.TrimSpace(execctx.ProjectID(ctx)),
		); err != nil {
			return nil, err
		}
		projectID := strings.TrimSpace(execctx.ProjectID(ctx))
		reassigned, err := s.db.ReassignActiveProjectHypothesesToConversation(
			ctx,
			projectID,
			conversationID,
			execctx.RunID(ctx),
		)
		if err != nil {
			return nil, err
		}
		if activeHandle := s.orchestrationFor(conversationID); activeHandle != nil {
			activeHandle.signalPlanner()
			activeHandle.signalWorkers()
		}
		payload := s.orchestrationStatus(ctx, s.orchestrationFor(conversationID))
		payload["reassignedHypotheses"] = reassigned
		return payload, nil
	case "stop":
		if handle == nil {
			return nil, fmt.Errorf("当前没有运行中的后台编排")
		}
		handle.mu.Lock()
		cancel := handle.cancel
		handle.mu.Unlock()
		projectID := strings.TrimSpace(execctx.ProjectID(ctx))
		if projectID != "" {
			_, _ = s.db.StopRunningProjectHypothesesForConversation(
				ctx,
				projectID,
				conversationID,
				"用户停止任务",
			)
		}
		handle.setStatus(database.AgentOrchestrationStopped, nil)
		if cancel != nil {
			cancel()
		}
		return s.orchestrationStatus(ctx, handle), nil
	default:
		return nil, fmt.Errorf(
			"action 必须是 status/steer/steer_worker/stop_worker/pause/resume/resume_project/stop",
		)
	}
}

func fastModeOrchestratorActionAllowed(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "status", "worker_output", "worker_trace", "stop_worker", "stop":
		return true
	default:
		return false
	}
}

func (s *Service) pauseOrchestrationForFastMode(ctx context.Context, conversationID string) {
	if s == nil {
		return
	}
	if handle := s.orchestrationFor(conversationID); handle != nil {
		status, _ := handle.snapshot()["status"].(string)
		if status == database.AgentOrchestrationRunning {
			_, _ = s.controlOrchestration(
				ctx,
				"pause",
				"当前为主 Agent Fast 模式，后台编排已暂停",
			)
		}
		return
	}
	if s.db == nil {
		return
	}
	paused, err := s.db.PauseRunningAgentOrchestration(
		ctx,
		conversationID,
		"当前为主 Agent Fast 模式，后台编排已暂停",
	)
	if err != nil || !paused {
		return
	}
	if projectID := strings.TrimSpace(execctx.ProjectID(ctx)); projectID != "" {
		_, _ = s.db.PauseRunningProjectHypothesesForConversation(
			ctx,
			projectID,
			conversationID,
			"当前为主 Agent Fast 模式，Worker 已释放为可恢复状态",
		)
	}
}

func (s *Service) PauseProject(
	ctx context.Context,
	projectID string,
	userID string,
	reason string,
) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	projectID = strings.TrimSpace(projectID)
	userID = strings.TrimSpace(userID)
	reason = strings.TrimSpace(reason)
	if projectID == "" || userID == "" {
		return 0, fmt.Errorf("项目暂停缺少项目或用户")
	}
	if reason == "" {
		reason = "项目已暂停"
	}
	pauseReason := projectPauseReasonPrefix + reason
	records, err := s.db.ListRecoverableAgentOrchestrations(ctx)
	if err != nil {
		return 0, err
	}
	paused := 0
	var pauseErrors []error
	for _, record := range records {
		if record.ProjectID != projectID ||
			record.OwnerUserID != userID ||
			record.Status != database.AgentOrchestrationRunning {
			continue
		}
		handle := s.orchestrationFor(record.ConversationID)
		if handle != nil {
			handle.setStatus(database.AgentOrchestrationPaused, errors.New(pauseReason))
			handle.mu.Lock()
			cancel := handle.cancel
			handle.mu.Unlock()
			if cancel != nil {
				cancel()
			}
		}
		if err := s.db.UpdateAgentOrchestrationState(
			ctx,
			record.ConversationID,
			database.AgentOrchestrationPaused,
			pauseReason,
			record.Feedback,
		); err != nil {
			pauseErrors = append(pauseErrors, err)
			continue
		}
		paused++
	}
	if _, err := s.db.PauseRunningProjectHypotheses(ctx, projectID, pauseReason); err != nil {
		pauseErrors = append(pauseErrors, err)
	}
	if _, err := s.db.PauseProjectAgentSessions(ctx, projectID, userID, pauseReason); err != nil {
		pauseErrors = append(pauseErrors, fmt.Errorf("暂停 Agent 会话状态: %w", err))
	}
	return paused, errors.Join(pauseErrors...)
}

func (s *Service) ResumeProject(
	ctx context.Context,
	projectID string,
	userID string,
) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	projectID = strings.TrimSpace(projectID)
	userID = strings.TrimSpace(userID)
	if projectID == "" || userID == "" {
		return 0, fmt.Errorf("项目恢复缺少项目或用户")
	}
	records, err := s.db.ListRecoverableAgentOrchestrations(ctx)
	if err != nil {
		return 0, err
	}
	maxRunning := s.configSnapshot().AgentMaxConcurrentSessions
	if maxRunning <= 0 {
		maxRunning = 5
	}
	running := 0
	for _, record := range records {
		if record.Status == database.AgentOrchestrationRunning {
			running++
		}
	}
	resumed := 0
	var resumeErrors []error
	for _, record := range records {
		if record.ProjectID != projectID ||
			record.OwnerUserID != userID ||
			record.Status != database.AgentOrchestrationPaused {
			continue
		}
		if running >= maxRunning {
			continue
		}
		record.Feedback = append(
			record.Feedback,
			"【项目恢复】项目已重新启用，请继续未完成的规划、意图和 Worker 工作。",
		)
		if err := s.recoverRunningOrchestration(ctx, record); err != nil {
			resumeErrors = append(resumeErrors, fmt.Errorf("恢复会话 %s: %w", record.ConversationID, err))
			continue
		}
		resumed++
		running++
		if handle := s.orchestrationFor(record.ConversationID); handle != nil {
			handle.signalPlanner()
			handle.signalWorkers()
		}
	}
	if _, err := s.db.ResumePausedProjectHypotheses(
		ctx,
		projectID,
	); err != nil {
		resumeErrors = append(resumeErrors, err)
	}
	return resumed, errors.Join(resumeErrors...)
}

func (s *Service) ResumeConversationOrchestration(
	ctx context.Context,
	conversationID string,
	userID string,
) (bool, error) {
	if s == nil || s.db == nil {
		return false, nil
	}
	conversationID = strings.TrimSpace(conversationID)
	userID = strings.TrimSpace(userID)
	if conversationID == "" || userID == "" {
		return false, fmt.Errorf("恢复编排缺少会话或用户")
	}
	if handle := s.orchestrationFor(conversationID); handle != nil {
		status, _ := handle.snapshot()["status"].(string)
		if status == database.AgentOrchestrationRunning {
			handle.signalPlanner()
			handle.signalWorkers()
			return true, nil
		}
	}
	records, err := s.db.ListRecoverableAgentOrchestrations(ctx)
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if record.ConversationID != conversationID || record.OwnerUserID != userID {
			continue
		}
		record.Feedback = append(record.Feedback, "用户请求继续当前会话的 Planner/Worker 编排。")
		if err := s.db.UpdateAgentOrchestrationState(
			ctx,
			record.ConversationID,
			database.AgentOrchestrationPaused,
			record.LastError,
			record.Feedback,
		); err != nil {
			return false, err
		}
		if err := s.recoverRunningOrchestration(ctx, record); err != nil {
			return false, err
		}
		if _, err := s.db.ResumePausedProjectHypothesesForConversation(
			ctx,
			record.ProjectID,
			record.ConversationID,
		); err != nil {
			return false, err
		}
		if handle := s.orchestrationFor(record.ConversationID); handle != nil {
			handle.signalPlanner()
			handle.signalWorkers()
		}
		return true, nil
	}
	return false, nil
}

func (s *Service) orchestrationStatus(
	ctx context.Context,
	handle *backgroundOrchestration,
) map[string]interface{} {
	payload := map[string]interface{}{
		"orchestration": handle.snapshot(),
	}
	projectID := strings.TrimSpace(execctx.ProjectID(ctx))
	if s != nil && s.db != nil && projectID != "" {
		if active, err := s.db.ListProjectHypotheses(ctx, projectID, "", 200); err == nil {
			payload["activeHypotheses"] = len(active)
			payload["hypotheses"] = activeHypothesisSummary(active)
		}
		if pending, err := s.db.CountPendingAgentTriggers(ctx, execctx.ConversationID(ctx)); err == nil {
			payload["pendingTriggers"] = pending
		}
		if recent, err := s.db.ListProjectTestResults(ctx, projectID, 100); err == nil {
			payload["recentHypotheses"] = activeHypothesisSummary(recent)
		}
		if todos, err := s.db.ListAgentPlannerTodos(ctx, execctx.ConversationID(ctx)); err == nil {
			payload["plannerTodos"] = todos
		}
	}
	if s != nil {
		payload["workers"] = s.workerControlsSnapshot(execctx.ConversationID(ctx))
	}
	return payload
}

func newOrchestratorControlTool(service *Service) tool.BaseTool {
	return &jsonTool{
		name: orchestratorControlToolName,
		desc: "查看或控制当前会话的后台 Planner/Worker 编排。",
		params: map[string]*schema.ParameterInfo{
			"action": stringParam(
				"操作：status | steer | steer_worker | stop_worker | worker_output | worker_trace | resume | resume_project | stop",
				true,
			),
			"message":      stringParam("steer 的纠偏内容，或 stop_worker 的具体停止原因"),
			"hypothesisId": stringParam("steer_worker 或 stop_worker 的目标假设 ID"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Action       string `json:"action"`
				Message      string `json:"message"`
				HypothesisID string `json:"hypothesisId"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			if info, ok := execctx.Subagent(ctx); ok &&
				strings.EqualFold(strings.TrimSpace(info.Kind), "planner") {
				switch strings.ToLower(strings.TrimSpace(request.Action)) {
				case "status", "steer_worker", "stop_worker", "worker_output", "worker_trace":
				default:
					return "", fmt.Errorf("Planner 只能查看 Worker、纠偏或停止单个 Worker")
				}
			}
			if strings.EqualFold(strings.TrimSpace(request.Action), "pause") {
				return "", fmt.Errorf("Agent 不能暂停自身编排；请由用户使用项目或会话暂停操作")
			}
			result, err := service.controlOrchestration(
				ctx,
				request.Action,
				request.Message,
				request.HypothesisID,
			)
			if err != nil {
				return "", err
			}
			encoded, _ := json.Marshal(result)
			return string(encoded), nil
		},
	}
}

func workerOutputDetails(items []database.ProcessDetail) []database.ProcessDetail {
	result := make([]database.ProcessDetail, 0)
	for _, item := range items {
		switch strings.ToLower(strings.TrimSpace(item.EventType)) {
		case "subagent.completed", "subagent.failed", "result", "response":
			result = append(result, item)
		}
	}
	if len(result) == 0 && len(items) > 0 {
		result = append(result, items[len(items)-1])
	}
	return result
}

func activeHypothesisSummary(items []database.ProjectTestResult) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		result = append(result, map[string]interface{}{
			"id":                   item.ID,
			"assetId":              item.AssetID,
			"dimension":            item.Dimension,
			"technique":            item.Technique,
			"status":               item.Status,
			"executionState":       item.ExecutionState,
			"outcomeState":         item.OutcomeState,
			"stateReason":          item.StateReason,
			"lastWorkerSessionId":  item.LastWorkerSessionID,
			"priority":             item.Priority,
			"originConversationId": item.OriginConversationID,
			"originRunId":          item.OriginRunID,
		})
	}
	return result
}
