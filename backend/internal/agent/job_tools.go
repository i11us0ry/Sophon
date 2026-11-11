package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/database"
	"sophon/internal/execctx"
	"sophon/internal/policy"
)

const (
	jobToolName      = "job"
	maxJobTotalRunes = 256000
)

var errToolJobStateChanged = errors.New("Job 状态已变化")

func newJobTools(service *Service) []tool.BaseTool {
	return []tool.BaseTool{service.jobTool()}
}

type jobToolRequest struct {
	Action string   `json:"action"`
	Steps  []string `json:"steps"`
	JobKey string   `json:"job_key"`
	JobID  string   `json:"job_id"`
}

func (s *Service) jobTool() tool.BaseTool {
	return &jsonTool{
		name: jobToolName,
		desc: "管理受控分步后台 Job。action=start 启动，status 查询，resume 恢复，cancel 取消。" +
			"每一步完成后持久化检查点；禁止使用 nohup、setsid、disown 或后台 &。",
		params: map[string]*schema.ParameterInfo{
			"action":  stringEnumParam("操作类型", []string{"start", "status", "resume", "cancel"}, true),
			"steps":   stringArrayParam("action=start 时必填，按顺序执行的 shell 命令数组，每一步都是可恢复检查点"),
			"job_key": stringParam("可选去重键；相同 Worker 和 key 不会重复启动"),
			"job_id":  stringParam("action=status/resume/cancel 时必填的 Job ID"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request jobToolRequest
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			switch strings.ToLower(strings.TrimSpace(request.Action)) {
			case "start":
				return s.runJobStart(ctx, request)
			case "status":
				return s.runJobStatus(ctx, request)
			case "resume":
				return s.runJobResume(ctx, request)
			case "cancel":
				return s.runJobCancel(ctx, request)
			default:
				return "", fmt.Errorf("action 必须是 start、status、resume 或 cancel")
			}
		},
	}
}

func (s *Service) runJobStart(ctx context.Context, request jobToolRequest) (string, error) {
	steps, err := validateJobSteps(request.Steps)
	if err != nil {
		return "", err
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	userID := strings.TrimSpace(execctx.UserID(ctx))
	if conversationID == "" || userID == "" {
		return "", fmt.Errorf("Job 需要在有效会话上下文中启动")
	}
	agentID := "mainagent"
	if info, ok := execctx.Subagent(ctx); ok && strings.TrimSpace(info.ID) != "" {
		agentID = strings.TrimSpace(info.ID)
	}
	dedupKey := jobDedupKey(agentID, request.JobKey, steps)
	active, err := s.db.FindRunningToolJobByAgent(ctx, conversationID, userID, agentID, "")
	if err != nil {
		return "", fmt.Errorf("检查 Worker 活动 Job 失败: %w", err)
	}
	if active != nil {
		if active.DedupKey == dedupKey {
			return renderToolJob(active, "已复用当前运行中的相同 Job"), nil
		}
		return "", fmt.Errorf("当前 Worker 已有运行中的 Job %s，请先查询、取消或等待完成", active.ID)
	}
	job, created, err := s.db.CreateToolJob(ctx, database.ToolJob{
		ConversationID: conversationID,
		UserID:         userID,
		AgentID:        agentID,
		DedupKey:       dedupKey,
		Status:         database.ToolJobStatusRunning,
		Steps:          steps,
		Progress: map[string]interface{}{
			"startedAt": time.Now().UTC().Format(time.RFC3339),
		},
	})
	if err != nil {
		return "", fmt.Errorf("创建 Job 失败: %w", err)
	}
	if !created {
		return renderToolJob(job, "已复用相同去重键的 Job，未重复启动"), nil
	}
	s.startToolJob(ctx, *job, 0)
	return renderToolJob(job, "Job 已启动"), nil
}

func (s *Service) runJobStatus(ctx context.Context, request jobToolRequest) (string, error) {
	jobID := strings.TrimSpace(request.JobID)
	if jobID == "" {
		return "", fmt.Errorf("action=status 需要 job_id")
	}
	job, err := s.currentToolJob(ctx, jobID)
	if err != nil {
		return "", err
	}
	return renderToolJob(job, "Job 状态"), nil
}

func (s *Service) runJobCancel(ctx context.Context, request jobToolRequest) (string, error) {
	jobID := strings.TrimSpace(request.JobID)
	if jobID == "" {
		return "", fmt.Errorf("action=cancel 需要 job_id")
	}
	job, err := s.currentToolJob(ctx, jobID)
	if err != nil {
		return "", err
	}
	if job.Status == database.ToolJobStatusCompleted {
		return renderToolJob(job, "Job 已完成，无需取消"), nil
	}
	s.cancelRunningToolJob(job.ID)
	progress := cloneJobProgress(job.Progress)
	progress["cancelledAt"] = time.Now().UTC().Format(time.RFC3339)
	updatedStatus, err := s.db.UpdateToolJob(
		ctx,
		job.ID,
		job.UserID,
		[]string{job.Status},
		database.ToolJobStatusCancelled,
		job.NextStep,
		progress,
		job.Result,
		"用户或会话取消 Job",
		true,
	)
	if err != nil {
		return "", fmt.Errorf("更新 Job 取消状态失败: %w", err)
	}
	if !updatedStatus {
		latest, getErr := s.currentToolJob(ctx, job.ID)
		if getErr != nil {
			return "", getErr
		}
		return renderToolJob(latest, "Job 状态已变化，请重新确认"), nil
	}
	updated, err := s.currentToolJob(ctx, job.ID)
	if err != nil {
		return "", err
	}
	return renderToolJob(updated, "Job 已取消"), nil
}

func (s *Service) runJobResume(ctx context.Context, request jobToolRequest) (string, error) {
	jobID := strings.TrimSpace(request.JobID)
	if jobID == "" {
		return "", fmt.Errorf("action=resume 需要 job_id")
	}
	job, err := s.currentToolJob(ctx, jobID)
	if err != nil {
		return "", err
	}
	switch job.Status {
	case database.ToolJobStatusRunning:
		return renderToolJob(job, "Job 仍在运行"), nil
	case database.ToolJobStatusCompleted:
		return renderToolJob(job, "Job 已完成"), nil
	}
	if job.NextStep >= len(job.Steps) {
		return renderToolJob(job, "Job 已没有待执行步骤"), nil
	}
	active, err := s.db.FindRunningToolJobByAgent(
		ctx,
		job.ConversationID,
		job.UserID,
		job.AgentID,
		job.ID,
	)
	if err != nil {
		return "", fmt.Errorf("检查 Worker 活动 Job 失败: %w", err)
	}
	if active != nil {
		return "", fmt.Errorf("当前 Worker 已有运行中的 Job %s，不能并行恢复其他 Job", active.ID)
	}
	progress := cloneJobProgress(job.Progress)
	progress["resumedAt"] = time.Now().UTC().Format(time.RFC3339)
	updatedStatus, err := s.db.UpdateToolJob(
		ctx,
		job.ID,
		job.UserID,
		[]string{job.Status},
		database.ToolJobStatusRunning,
		job.NextStep,
		progress,
		job.Result,
		"",
		false,
	)
	if err != nil {
		return "", fmt.Errorf("恢复 Job 失败: %w", err)
	}
	if !updatedStatus {
		latest, getErr := s.currentToolJob(ctx, job.ID)
		if getErr != nil {
			return "", getErr
		}
		return renderToolJob(latest, "Job 状态已变化，未启动重复执行"), nil
	}
	job.Status = database.ToolJobStatusRunning
	job.Progress = progress
	s.startToolJob(ctx, *job, job.NextStep)
	return renderToolJob(job, "Job 已从检查点恢复"), nil
}

func validateJobSteps(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("steps 不能为空")
	}
	if len(values) > 100 {
		return nil, fmt.Errorf("单个 Job 最多允许 100 个步骤")
	}
	steps := make([]string, 0, len(values))
	totalRunes := 0
	for index, value := range values {
		command := strings.TrimSpace(value)
		if command == "" {
			return nil, fmt.Errorf("第 %d 个步骤不能为空", index+1)
		}
		runeLen := len([]rune(command))
		if runeLen > 16000 {
			return nil, fmt.Errorf("第 %d 个步骤超过 16000 字符", index+1)
		}
		totalRunes += runeLen
		if totalRunes > maxJobTotalRunes {
			return nil, fmt.Errorf("单个 Job 的步骤总长度不能超过 %d 字符", maxJobTotalRunes)
		}
		if policy.ContainsDetachedBackground(command) {
			return nil, fmt.Errorf("第 %d 个步骤包含后台启动语法，请改用 Job 分步执行", index+1)
		}
		steps = append(steps, command)
	}
	return steps, nil
}

func jobDedupKey(agentID, jobKey string, steps []string) string {
	jobKey = strings.TrimSpace(jobKey)
	if jobKey != "" {
		sum := sha256.Sum256([]byte(agentID + "\n" + jobKey))
		return agentID + ":" + hex.EncodeToString(sum[:])
	}
	raw, _ := json.Marshal(steps)
	sum := sha256.Sum256(append([]byte(agentID+"\n"), raw...))
	return agentID + ":" + hex.EncodeToString(sum[:])
}

func (s *Service) currentToolJob(ctx context.Context, id string) (*database.ToolJob, error) {
	job, err := s.db.GetToolJob(
		ctx,
		strings.TrimSpace(id),
		strings.TrimSpace(execctx.UserID(ctx)),
	)
	if err != nil {
		return nil, fmt.Errorf("读取 Job 失败: %w", err)
	}
	if job.ConversationID != strings.TrimSpace(execctx.ConversationID(ctx)) {
		return nil, fmt.Errorf("Job 不属于当前会话")
	}
	return job, nil
}

func (s *Service) startToolJob(parent context.Context, job database.ToolJob, startStep int) {
	ctx, cancel := context.WithCancel(parent)
	s.jobMu.Lock()
	if s.jobs == nil {
		s.jobs = map[string]context.CancelFunc{}
	}
	s.jobs[job.ID] = cancel
	s.jobMu.Unlock()
	go s.runToolJob(ctx, job, startStep)
}

func (s *Service) cancelRunningToolJob(id string) {
	s.jobMu.Lock()
	cancel := s.jobs[strings.TrimSpace(id)]
	s.jobMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) runToolJob(ctx context.Context, job database.ToolJob, startStep int) {
	defer func() {
		s.jobMu.Lock()
		delete(s.jobs, job.ID)
		s.jobMu.Unlock()
	}()
	if startStep < 0 {
		startStep = 0
	}
	progress := cloneJobProgress(job.Progress)
	lastResult := job.Result
	for index := startStep; index < len(job.Steps); index++ {
		if err := ctx.Err(); err != nil {
			s.finishToolJob(job, index, progress, lastResult, database.ToolJobStatusCancelled, "Job 已取消")
			return
		}
		if err := workerBudgetFromContext(ctx).reserve(fmt.Sprintf("job_step_%d", index+1)); err != nil {
			s.finishToolJob(job, index, progress, lastResult, database.ToolJobStatusFailed, err.Error())
			return
		}
		progress["currentStep"] = index + 1
		progress["totalSteps"] = len(job.Steps)
		progress["stepStartedAt"] = time.Now().UTC().Format(time.RFC3339)
		if err := s.updateToolJobProgress(ctx, job, index, progress, lastResult, ""); err != nil {
			if errors.Is(err, errToolJobStateChanged) {
				return
			}
			s.finishToolJob(job, index, progress, lastResult, database.ToolJobStatusFailed, err.Error())
			return
		}

		result, err := s.RunTool(
			ctx,
			job.ConversationID,
			job.UserID,
			"exec",
			map[string]interface{}{"command": job.Steps[index]},
			nil,
		)
		workerBudgetFromContext(ctx).recordCPUUsage(result)
		if err != nil {
			if ctx.Err() != nil {
				s.finishToolJob(job, index, progress, lastResult, database.ToolJobStatusCancelled, "Job 已取消")
			} else {
				s.finishToolJob(job, index, progress, lastResult, database.ToolJobStatusFailed, err.Error())
			}
			return
		}
		lastResult = truncateRunes(strings.TrimSpace(result), 4000)
		progress["lastStep"] = index + 1
		progress["lastStepFinishedAt"] = time.Now().UTC().Format(time.RFC3339)
		progress["lastOutput"] = lastResult
		if err := s.updateToolJobProgress(ctx, job, index+1, progress, lastResult, ""); err != nil {
			if errors.Is(err, errToolJobStateChanged) {
				return
			}
			s.finishToolJob(job, index+1, progress, lastResult, database.ToolJobStatusFailed, err.Error())
			return
		}
	}
	s.finishToolJob(job, len(job.Steps), progress, lastResult, database.ToolJobStatusCompleted, "")
}

func (s *Service) updateToolJobProgress(
	ctx context.Context,
	job database.ToolJob,
	nextStep int,
	progress map[string]interface{},
	result string,
	errText string,
) error {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	updated, err := s.db.UpdateToolJob(
		writeCtx,
		job.ID,
		job.UserID,
		[]string{database.ToolJobStatusRunning},
		database.ToolJobStatusRunning,
		nextStep,
		progress,
		result,
		errText,
		false,
	)
	if err != nil {
		return err
	}
	if !updated {
		return errToolJobStateChanged
	}
	return nil
}

func (s *Service) finishToolJob(
	job database.ToolJob,
	nextStep int,
	progress map[string]interface{},
	result string,
	status string,
	errText string,
) {
	switch status {
	case database.ToolJobStatusCompleted, database.ToolJobStatusFailed, database.ToolJobStatusCancelled:
	default:
		status = database.ToolJobStatusFailed
	}
	progress["finishedAt"] = time.Now().UTC().Format(time.RFC3339)
	writeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _ = s.db.UpdateToolJob(
		writeCtx,
		job.ID,
		job.UserID,
		[]string{database.ToolJobStatusRunning},
		status,
		nextStep,
		progress,
		result,
		errText,
		true,
	)
}

func cloneJobProgress(value map[string]interface{}) map[string]interface{} {
	copied := make(map[string]interface{}, len(value)+4)
	for key, item := range value {
		copied[key] = item
	}
	return copied
}

func renderToolJob(job *database.ToolJob, title string) string {
	if job == nil {
		return title + "\nJob 不存在"
	}
	payload := map[string]interface{}{
		"id":         job.ID,
		"dedupKey":   job.DedupKey,
		"status":     job.Status,
		"nextStep":   job.NextStep,
		"totalSteps": len(job.Steps),
		"progress":   job.Progress,
		"result":     job.Result,
		"error":      job.Error,
		"updatedAt":  job.UpdatedAt.Format(time.RFC3339),
	}
	raw, _ := json.MarshalIndent(payload, "", "  ")
	return title + "\n" + string(raw)
}
