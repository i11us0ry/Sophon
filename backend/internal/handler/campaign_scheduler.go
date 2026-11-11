package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	agentpkg "sophon/internal/agent"
	"sophon/internal/database"
	"sophon/internal/observability"
	"sophon/internal/task"
)

type CampaignScheduler struct {
	db   *database.DB
	chat *ChatHandler

	mu      sync.Mutex
	running map[string]*campaignRunner

	refreshMu   sync.Mutex
	lastRefresh map[string]time.Time

	assetMu      sync.Mutex
	activeAssets map[string]int

	runSlotsMu sync.Mutex
	runSlots   map[string]chan struct{}
}

type campaignRunner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func NewCampaignScheduler(db *database.DB, chat *ChatHandler) *CampaignScheduler {
	return &CampaignScheduler{
		db:           db,
		chat:         chat,
		running:      map[string]*campaignRunner{},
		lastRefresh:  map[string]time.Time{},
		activeAssets: map[string]int{},
		runSlots:     map[string]chan struct{}{},
	}
}

func (s *CampaignScheduler) Start(campaignID, userID string) error {
	if s == nil || s.db == nil || s.chat == nil {
		return fmt.Errorf("campaign scheduler unavailable")
	}
	campaign, err := s.db.GetCampaign(context.Background(), campaignID, userID)
	if err != nil {
		return err
	}
	if campaign.Status == database.CampaignStatusRunning {
		return nil
	}
	if err := s.db.SetCampaignResumeOnStart(
		context.Background(),
		campaignID,
		userID,
		true,
	); err != nil {
		return err
	}
	_ = s.db.RecomputeCampaignScheduling(context.Background(), campaignID)
	if err := s.db.UpdateCampaignStatus(
		context.Background(),
		campaignID,
		userID,
		database.CampaignStatusRunning,
	); err != nil {
		return err
	}
	s.startRunner(campaignID, userID, campaign)
	return nil
}

func (s *CampaignScheduler) Pause(campaignID, userID string) error {
	if err := s.db.SetCampaignResumeOnStart(
		context.Background(),
		campaignID,
		userID,
		false,
	); err != nil {
		return err
	}
	if err := s.db.UpdateCampaignStatus(
		context.Background(),
		campaignID,
		userID,
		database.CampaignStatusPaused,
	); err != nil {
		return err
	}
	s.cancelRunner(campaignID)
	return nil
}

func (s *CampaignScheduler) Stop(campaignID, userID string) error {
	if err := s.db.SetCampaignResumeOnStart(
		context.Background(),
		campaignID,
		userID,
		false,
	); err != nil {
		return err
	}
	if err := s.db.StopCampaign(context.Background(), campaignID, userID); err != nil {
		return err
	}
	s.cancelRunner(campaignID)
	return nil
}

func (s *CampaignScheduler) Resume(campaignID, userID string) error {
	_, err := s.db.RequeueCampaignFailedTasks(context.Background(), campaignID)
	if err != nil {
		return err
	}
	if err := s.db.SetCampaignResumeOnStart(
		context.Background(),
		campaignID,
		userID,
		true,
	); err != nil {
		return err
	}
	return s.Start(campaignID, userID)
}

func (s *CampaignScheduler) ResumeAutoCampaigns(ctx context.Context) (int, error) {
	items, err := s.db.ListCampaignsForAutoResume(ctx)
	if err != nil {
		return 0, err
	}
	resumed := 0
	for _, item := range items {
		campaign, err := s.db.GetCampaign(ctx, item.ID, item.OwnerUserID)
		if err != nil {
			continue
		}
		if _, err := s.db.GetActiveProject(ctx, campaign.ProjectID, item.OwnerUserID); err != nil {
			continue
		}
		if err := s.Start(item.ID, item.OwnerUserID); err != nil {
			continue
		}
		resumed++
	}
	return resumed, nil
}

func (h *ChatHandler) ResumeAutoCampaigns(ctx context.Context) (int, error) {
	return h.campaignScheduler().ResumeAutoCampaigns(ctx)
}

func (s *CampaignScheduler) startRunner(
	campaignID string,
	userID string,
	campaign *database.ConversationBatch,
) {
	s.mu.Lock()
	if _, exists := s.running[campaignID]; exists {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	runner := &campaignRunner{cancel: cancel, done: make(chan struct{})}
	s.running[campaignID] = runner
	s.mu.Unlock()
	copyCampaign := *campaign
	go func() {
		defer func() {
			close(runner.done)
			s.mu.Lock()
			if s.running[campaignID] == runner {
				delete(s.running, campaignID)
			}
			s.mu.Unlock()
		}()
		s.run(ctx, campaignID, userID, copyCampaign)
	}()
}

func (s *CampaignScheduler) cancelRunner(campaignID string) {
	s.mu.Lock()
	runner := s.running[campaignID]
	s.mu.Unlock()
	if runner == nil {
		return
	}
	runner.cancel()
	select {
	case <-runner.done:
	case <-time.After(5 * time.Second):
	}
}

func (s *CampaignScheduler) refreshIntelligence(campaignID string) {
	const refreshInterval = 5 * time.Second
	s.refreshMu.Lock()
	last := s.lastRefresh[campaignID]
	now := time.Now()
	if !last.IsZero() && now.Sub(last) < refreshInterval {
		s.refreshMu.Unlock()
		return
	}
	s.lastRefresh[campaignID] = now
	s.refreshMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = s.db.GenerateCampaignChains(ctx, campaignID)
	_ = s.db.RefreshCampaignMemory(ctx, campaignID)
	_ = s.db.RecomputeCampaignScheduling(ctx, campaignID)
}

func (s *CampaignScheduler) activeAssetIDs() []string {
	s.assetMu.Lock()
	defer s.assetMu.Unlock()
	items := make([]string, 0, len(s.activeAssets))
	for assetID, count := range s.activeAssets {
		if count > 0 {
			items = append(items, assetID)
		}
	}
	return items
}

func (s *CampaignScheduler) acquireAsset(assetID string) bool {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return true
	}
	s.assetMu.Lock()
	defer s.assetMu.Unlock()
	if s.activeAssets[assetID] > 0 {
		return false
	}
	s.activeAssets[assetID] = 1
	return true
}

func (s *CampaignScheduler) releaseAsset(assetID string) {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return
	}
	s.assetMu.Lock()
	defer s.assetMu.Unlock()
	if s.activeAssets[assetID] <= 1 {
		delete(s.activeAssets, assetID)
		return
	}
	s.activeAssets[assetID]--
}

func (s *CampaignScheduler) userRunSlot(userID string) chan struct{} {
	capacity := 5
	if s.chat != nil && s.chat.manager != nil {
		capacity = s.chat.manager.MaxPerUser()
	}
	if capacity <= 0 {
		capacity = 5
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		userID = "default"
	}

	s.runSlotsMu.Lock()
	defer s.runSlotsMu.Unlock()
	if s.runSlots == nil {
		s.runSlots = map[string]chan struct{}{}
	}
	slot := s.runSlots[userID]
	if slot == nil {
		slot = make(chan struct{}, capacity)
		s.runSlots[userID] = slot
	}
	return slot
}

func (s *CampaignScheduler) acquireUserRunSlot(ctx context.Context, userID string) bool {
	slot := s.userRunSlot(userID)
	select {
	case slot <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *CampaignScheduler) releaseUserRunSlot(userID string) {
	slot := s.userRunSlot(userID)
	<-slot
}

func (s *CampaignScheduler) availableUserRunSlots(userID string) int {
	slot := s.userRunSlot(userID)
	return cap(slot) - len(slot)
}

func (s *CampaignScheduler) run(
	ctx context.Context,
	campaignID string,
	userID string,
	campaign database.ConversationBatch,
) {
	if !s.acquireUserRunSlot(ctx, userID) {
		return
	}
	defer s.releaseUserRunSlot(userID)

	concurrency := campaign.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	sem := make(chan struct{}, concurrency)
	var workers sync.WaitGroup
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		current, err := s.db.GetCampaign(ctx, campaignID, userID)
		if err != nil || current.Status != database.CampaignStatusRunning {
			break
		}
		available := cap(sem) - len(sem)
		if available > 0 {
			_ = s.db.RecomputeCampaignScheduling(ctx, campaignID)
			items, claimErr := s.db.ClaimCampaignTasksExcluding(
				ctx,
				campaignID,
				available,
				s.activeAssetIDs(),
			)
			if claimErr != nil {
				break
			}
			for index := range items {
				item := items[index]
				if !s.acquireAsset(item.AssetID) {
					if err := s.db.DeferCampaignTask(ctx, item.ID); err != nil {
						log.Printf("campaign defer task %s: %v", item.ID, err)
					}
					continue
				}
				sem <- struct{}{}
				workers.Add(1)
				go func() {
					defer func() {
						s.releaseAsset(item.AssetID)
						<-sem
						workers.Done()
					}()
					s.runTask(ctx, userID, item)
				}()
			}
		}
		if len(sem) == 0 {
			pending, pendingErr := s.db.CampaignHasPendingTasks(ctx, campaignID)
			if pendingErr == nil && !pending {
				paused, pausedErr := s.db.CampaignHasPausedTasks(ctx, campaignID)
				if pausedErr == nil && paused {
					_ = s.db.UpdateCampaignStatus(
						context.Background(),
						campaignID,
						userID,
						database.CampaignStatusPaused,
					)
					break
				}
				if current.CampaignMode == database.CampaignModeContinuous &&
					current.StoppedAt.IsZero() &&
					current.CampaignRound < current.MaxRounds &&
					current.CampaignToolCalls < current.CampaignToolCallBudget {
					round, roundErr := s.db.AdvanceCampaignRound(ctx, campaignID)
					if roundErr == nil {
						if _, reviewErr := s.db.CreateCampaignReviewTask(
							ctx,
							campaignID,
							userID,
							round,
						); reviewErr == nil {
							continue
						}
					}
				}
				summary, _ := s.db.CampaignSummary(ctx, campaignID)
				status := database.CampaignStatusCompleted
				if summary != nil && summary.FailedTasks > 0 {
					status = database.CampaignStatusFailed
				}
				_ = s.db.UpdateCampaignStatus(
					context.Background(),
					campaignID,
					userID,
					status,
				)
				break
			}
		}
		select {
		case <-ctx.Done():
			workers.Wait()
			return
		case <-ticker.C:
		}
	}
	workers.Wait()
}

func (s *CampaignScheduler) runTask(
	ctx context.Context,
	userID string,
	item database.CampaignTask,
) {
	startedAt := time.Now().UTC()
	assistantMessageID := randomID()
	if err := s.db.AddMessage(ctx, database.Message{
		ID:             assistantMessageID,
		ConversationID: item.ConversationID,
		Role:           "assistant",
		Content:        "",
		CreatedAt:      startedAt,
	}); err != nil {
		_ = s.db.CompleteCampaignTask(
			context.Background(),
			item.ID,
			database.CampaignTaskStatusFailed,
			"",
			err.Error(),
			0,
		)
		return
	}

	var taskItem *task.Task
	for {
		created, _, err := s.chat.manager.CreateIfIdle(item.ConversationID, userID)
		if err == nil {
			taskItem = created
			break
		}
		if !errors.Is(err, task.ErrUserTaskLimit) {
			_ = s.db.CompleteCampaignTask(
				context.Background(),
				item.ID,
				database.CampaignTaskStatusFailed,
				"",
				err.Error(),
				0,
			)
			return
		}
		select {
		case <-ctx.Done():
			_ = s.db.CompleteCampaignTask(
				context.Background(),
				item.ID,
				database.CampaignTaskStatusPaused,
				"",
				"campaign paused",
				0,
			)
			return
		case <-time.After(500 * time.Millisecond):
		}
	}

	runCtx, cancelRun := context.WithCancel(taskItem.Context())
	stopRunOnCampaignStop := context.AfterFunc(ctx, cancelRun)
	if item.Kind == "chain_test" && strings.TrimSpace(item.SourceRef) != "" {
		_, _ = s.db.UpdateCampaignChainStatus(
			ctx,
			item.CampaignID,
			item.SourceRef,
			database.CampaignChainStatusTesting,
			nil,
		)
	}
	result, runErr := s.chat.agent.RunWithOptions(
		runCtx,
		item.ConversationID,
		userID,
		assistantMessageID,
		nil,
		agentpkg.RunOptions{
			CampaignID:     item.CampaignID,
			CampaignTaskID: item.ID,
			MaxSegments:    item.MaxSegments,
			MaxToolCalls:   item.MaxToolCalls,
		},
	)
	stopRunOnCampaignStop()
	cancelRun()
	taskStatus := taskItem.Snapshot().Status
	taskItem.Complete()
	attemptToolCalls := 0
	if counted, countErr := s.db.CountToolExecutionsSince(
		context.Background(),
		item.ConversationID,
		startedAt,
	); countErr == nil && counted > 0 {
		attemptToolCalls = counted
	}
	status := database.CampaignTaskStatusCompleted
	errorText := ""
	failureKind := ""
	switch {
	case ctx.Err() != nil:
		status = database.CampaignTaskStatusPaused
		errorText = "campaign paused or stopped"
		failureKind = "canceled"
	case errors.Is(runErr, agentpkg.ErrTaskBudgetExhausted):
		status = database.CampaignTaskStatusPaused
		errorText = runErr.Error()
		failureKind = "budget_exhausted"
	case runErr != nil:
		status = database.CampaignTaskStatusFailed
		errorText = runErr.Error()
		failureKind = observability.ErrorCategory(errorText)
	}
	if taskStatus == task.StatusCancelled {
		status = database.CampaignTaskStatusPaused
		errorText = "campaign task cancelled"
		failureKind = "canceled"
	}
	retryScheduled, err := s.db.CompleteCampaignTaskWithRetry(
		context.Background(),
		item.ID,
		status,
		strings.TrimSpace(result),
		errorText,
		attemptToolCalls,
		failureKind,
		campaignRetryableFailure(failureKind),
	)
	if err != nil {
		return
	}
	_ = s.db.SyncCampaignToolCalls(context.Background(), item.CampaignID)
	if item.Kind == "chain_test" && strings.TrimSpace(item.SourceRef) != "" {
		chainStatus := database.CampaignChainStatusTesting
		switch status {
		case database.CampaignTaskStatusCompleted:
			chainStatus = database.CampaignChainStatusVerified
		case database.CampaignTaskStatusFailed:
			chainStatus = database.CampaignChainStatusFailed
		}
		if retryScheduled {
			chainStatus = database.CampaignChainStatusTesting
		}
		_, _ = s.db.UpdateCampaignChainStatus(
			context.Background(),
			item.CampaignID,
			item.SourceRef,
			chainStatus,
			nil,
		)
	}
	s.refreshIntelligence(item.CampaignID)
}

func campaignRetryableFailure(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "timeout", "gateway", "transient_network", "rate_limit":
		return true
	default:
		return false
	}
}
