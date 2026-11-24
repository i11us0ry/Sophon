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
	lastFailure   llmKeyFailure
	inFlight      int
	requests      uint64
	successes     uint64
}

type llmKeyCandidate struct {
	index int
	value string
}

type llmKeyPool struct {
	mu          sync.Mutex
	keys        []llmKeyState
	next        int
	provider    string
	now         func() time.Time
	maxInFlight int
	requests    uint64
	success     uint64
	failures    map[string]uint64
}

type llmKeyPoolSnapshot struct {
	Keys        int
	InFlight    int
	Cooling     int
	MaxInFlight int
	Requests    uint64
	Successes   uint64
	Failures    map[string]uint64
}

func newLLMKeyPool(keys []string, provider string, maxInFlight ...int) *llmKeyPool {
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
	pool := &llmKeyPool{
		keys:     states,
		provider: strings.ToLower(strings.TrimSpace(provider)),
		now:      time.Now,
		failures: map[string]uint64{},
	}
	if len(maxInFlight) > 0 && maxInFlight[0] > 0 {
		pool.maxInFlight = maxInFlight[0]
	}
	return pool
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
	selected := -1
	selectedInFlight := int(^uint(0) >> 1)
	for offset := 0; offset < len(p.keys); offset++ {
		index := (p.next + offset) % len(p.keys)
		key := p.keys[index]
		if tried[index] ||
			key.value == "" ||
			key.cooldownUntil.After(now) ||
			(p.maxInFlight > 0 && key.inFlight >= p.maxInFlight) {
			continue
		}
		if key.inFlight < selectedInFlight {
			selected = index
			selectedInFlight = key.inFlight
		}
	}
	if selected < 0 {
		return llmKeyCandidate{}, false
	}
	p.keys[selected].inFlight++
	p.keys[selected].requests++
	p.requests++
	p.next = (selected + 1) % len(p.keys)
	return llmKeyCandidate{index: selected, value: p.keys[selected].value}, true
}

func (p *llmKeyPool) nextRetryDelay() (time.Duration, bool) {
	if p == nil {
		return 0, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	earliest := time.Duration(0)
	retryable := false
	for _, key := range p.keys {
		if strings.TrimSpace(key.value) == "" {
			continue
		}
		switch key.lastFailure {
		case llmKeyFailureAuth, llmKeyFailureQuota:
			continue
		}
		retryable = true
		if key.cooldownUntil.After(now) {
			delay := key.cooldownUntil.Sub(now)
			if earliest <= 0 || delay < earliest {
				earliest = delay
			}
			continue
		}
		return 0, true
	}
	if !retryable {
		return 0, false
	}
	if earliest <= 0 {
		return 100 * time.Millisecond, true
	}
	return earliest, true
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
	p.settle(index)
	p.keys[index].cooldownUntil = time.Time{}
	p.keys[index].lastFailure = llmKeyFailureNone
	p.success++
	p.keys[index].successes++
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
	p.settle(index)
	cooldown := llmKeyFailureCooldown(failure)
	if retryAfter > cooldown {
		cooldown = retryAfter
	}
	if cooldown > 0 {
		p.keys[index].cooldownUntil = p.now().Add(cooldown)
	}
	p.keys[index].lastFailure = failure
	if p.failures == nil {
		p.failures = map[string]uint64{}
	}
	p.failures[llmKeyFailureLabel(failure)]++
	if len(p.keys) > 0 {
		p.next = (index + 1) % len(p.keys)
	}
}

func (p *llmKeyPool) release(index int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.settle(index)
}

func (p *llmKeyPool) settle(index int) {
	if index < 0 || index >= len(p.keys) {
		return
	}
	if p.keys[index].inFlight > 0 {
		p.keys[index].inFlight--
	}
}

func (p *llmKeyPool) snapshot() llmKeyPoolSnapshot {
	if p == nil {
		return llmKeyPoolSnapshot{Failures: map[string]uint64{}}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	inflight := 0
	cooling := 0
	for _, key := range p.keys {
		inflight += key.inFlight
		if key.cooldownUntil.After(now) {
			cooling++
		}
	}
	failures := make(map[string]uint64, len(p.failures))
	for class, count := range p.failures {
		failures[class] = count
	}
	return llmKeyPoolSnapshot{
		Keys:        len(p.keys),
		InFlight:    inflight,
		Cooling:     cooling,
		MaxInFlight: p.maxInFlight,
		Requests:    p.requests,
		Successes:   p.success,
		Failures:    failures,
	}
}

func llmKeyFailureLabel(failure llmKeyFailure) string {
	switch failure {
	case llmKeyFailureAuth:
		return "auth"
	case llmKeyFailureQuota:
		return "quota"
	case llmKeyFailureRateLimit:
		return "rate_limit"
	case llmKeyFailureTransient:
		return "transient"
	default:
		return "none"
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
		"not_enough_balance",
		"not enough balance",
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
