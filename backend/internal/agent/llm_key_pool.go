package agent

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

type llmKeyFailure int

const (
	llmKeyFailureNone llmKeyFailure = iota
	llmKeyFailureAuth
	llmKeyFailureQuota
	llmKeyFailureRateLimit
	llmKeyFailureTransient
)

const (
	llmKeyAuthCooldown      = 5 * time.Minute
	llmKeyQuotaCooldown     = 30 * time.Minute
	llmKeyRateLimitCooldown = 30 * time.Second
	llmKeyTransientCooldown = 10 * time.Second
)

type llmKeyState struct {
	value         string
	cooldownUntil time.Time
}

type llmKeyCandidate struct {
	index int
	value string
}

type llmKeyPool struct {
	mu       sync.Mutex
	keys     []llmKeyState
	active   int
	provider string
	now      func() time.Time
}

func newLLMKeyPool(keys []string, provider string) *llmKeyPool {
	states := make([]llmKeyState, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key != "" {
			states = append(states, llmKeyState{value: key})
		}
	}
	if len(states) == 0 {
		return nil
	}
	return &llmKeyPool{
		keys:     states,
		provider: strings.ToLower(strings.TrimSpace(provider)),
		now:      time.Now,
	}
}

func (p *llmKeyPool) size() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.keys)
}

func (p *llmKeyPool) acquire(tried map[int]bool) (llmKeyCandidate, bool) {
	if p == nil {
		return llmKeyCandidate{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.keys) == 0 {
		return llmKeyCandidate{}, false
	}
	now := p.now()
	for offset := 0; offset < len(p.keys); offset++ {
		index := (p.active + offset) % len(p.keys)
		key := p.keys[index]
		if tried[index] || key.value == "" || key.cooldownUntil.After(now) {
			continue
		}
		return llmKeyCandidate{index: index, value: key.value}, true
	}
	return llmKeyCandidate{}, false
}

func (p *llmKeyPool) markSuccess(index int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if index < 0 || index >= len(p.keys) {
		return
	}
	p.keys[index].cooldownUntil = time.Time{}
	p.active = index
}

func (p *llmKeyPool) markFailure(index int, failure llmKeyFailure, retryAfter time.Duration) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if index < 0 || index >= len(p.keys) {
		return
	}
	cooldown := llmKeyFailureCooldown(failure)
	if retryAfter > cooldown {
		cooldown = retryAfter
	}
	if cooldown > 0 {
		p.keys[index].cooldownUntil = p.now().Add(cooldown)
	}
	if len(p.keys) > 0 {
		p.active = (index + 1) % len(p.keys)
	}
}

func (p *llmKeyPool) applyAuthentication(request *http.Request, key string) {
	if request == nil {
		return
	}
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	if p != nil && p.provider == "anthropic" {
		request.Header.Set("x-api-key", key)
		request.Header.Del("Authorization")
		return
	}
	request.Header.Set("Authorization", "Bearer "+key)
}

func llmKeyFailureCooldown(failure llmKeyFailure) time.Duration {
	switch failure {
	case llmKeyFailureAuth:
		return llmKeyAuthCooldown
	case llmKeyFailureQuota:
		return llmKeyQuotaCooldown
	case llmKeyFailureRateLimit:
		return llmKeyRateLimitCooldown
	case llmKeyFailureTransient:
		return llmKeyTransientCooldown
	default:
		return 0
	}
}

func classifyLLMKeyFailure(status int, body string, requestErr error) llmKeyFailure {
	if requestErr != nil {
		return llmKeyFailureTransient
	}
	message := strings.ToLower(body)
	if llmQuotaError(message) {
		return llmKeyFailureQuota
	}
	if status == http.StatusUnauthorized ||
		(status == http.StatusForbidden && llmAuthenticationError(message)) {
		return llmKeyFailureAuth
	}
	switch status {
	case http.StatusPaymentRequired:
		return llmKeyFailureQuota
	case http.StatusRequestTimeout, http.StatusTooEarly:
		return llmKeyFailureTransient
	case http.StatusTooManyRequests:
		return llmKeyFailureRateLimit
	case http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return llmKeyFailureTransient
	default:
		return llmKeyFailureNone
	}
}

func llmAuthenticationError(message string) bool {
	for _, marker := range []string{
		"invalid api key",
		"incorrect api key",
		"invalid_api_key",
		"authentication",
		"unauthorized",
		"invalid token",
		"api key",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func llmQuotaError(message string) bool {
	for _, marker := range []string{
		"insufficient_quota",
		"insufficient quota",
		"quota_exceeded",
		"quota exceeded",
		"billing_hard_limit",
		"billing hard limit",
		"insufficient_balance",
		"insufficient balance",
		"credit balance",
		"余额不足",
		"额度不足",
		"配额不足",
		"欠费",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
