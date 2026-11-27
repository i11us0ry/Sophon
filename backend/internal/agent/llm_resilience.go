package agent

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const llmCircuitCooldown = 2 * time.Minute

var errLLMGloballyUnavailable = errors.New("LLM 全局不可用")

type llmGloballyUnavailableError struct {
	Reason string
}

func (e *llmGloballyUnavailableError) Error() string {
	reason := "模型服务全局不可用"
	if e != nil && strings.TrimSpace(e.Reason) != "" {
		reason = strings.TrimSpace(e.Reason)
	}
	return reason
}

func (e *llmGloballyUnavailableError) Unwrap() error {
	return errLLMGloballyUnavailable
}

func isGlobalLLMError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errLLMGloballyUnavailable) {
		return true
	}
	message := strings.ToLower(err.Error())
	for _, marker := range []string{
		"没有可用的 llm api key",
		"no available llm api key",
		"missing llm api key",
		"status code: 401",
		"status code: 402",
		"status code: 403",
		"payment required",
		"not_enough_balance",
		"insufficient_quota",
		"invalid api key",
		"authentication failed",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func (s *Service) checkLLMCircuit() error {
	if s == nil {
		return nil
	}
	s.llmCircuitMu.Lock()
	defer s.llmCircuitMu.Unlock()
	if s.llmCircuitUntil.IsZero() || time.Now().After(s.llmCircuitUntil) {
		s.llmCircuitUntil = time.Time{}
		s.llmCircuitReason = ""
		return nil
	}
	return &llmGloballyUnavailableError{Reason: s.llmCircuitReason}
}

func (s *Service) observeLLMError(err error) error {
	if err == nil || s == nil || !isGlobalLLMError(err) {
		return err
	}
	reason := redactLLMErrorReason(err)
	s.llmCircuitMu.Lock()
	s.llmCircuitUntil = time.Now().Add(llmCircuitCooldown)
	s.llmCircuitReason = reason
	s.llmCircuitMu.Unlock()
	return &llmGloballyUnavailableError{Reason: reason}
}

func (s *Service) markLLMHealthy() {
	if s == nil {
		return
	}
	s.llmCircuitMu.Lock()
	s.llmCircuitUntil = time.Time{}
	s.llmCircuitReason = ""
	s.llmCircuitMu.Unlock()
}

func (s *Service) resetLLMCircuit() {
	s.markLLMHealthy()
}

func (s *Service) streamErrorRetryable(err error) bool {
	if isGlobalLLMError(err) {
		_ = s.observeLLMError(err)
		return false
	}
	return streamErrorRetryable(err)
}

func redactLLMErrorReason(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	for _, suffix := range []string{
		"，已重试 0 次",
		"，已尝试 0 次",
	} {
		message = strings.ReplaceAll(message, suffix, "")
	}
	return fmt.Sprintf("模型服务不可用，已暂停编排：%s", truncateProjectText(message, 800))
}
