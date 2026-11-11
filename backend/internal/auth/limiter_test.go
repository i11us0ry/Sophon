package auth

import (
	"testing"
	"time"
)

func newTestLimiter(now *time.Time) *LoginLimiter {
	limiter := NewLoginLimiter()
	limiter.now = func() time.Time { return *now }
	return limiter
}

func TestLoginLimiterBlocksAfterMaxFailures(t *testing.T) {
	current := time.Now()
	limiter := newTestLimiter(&current)

	for index := 0; index < loginUserMaxFailures; index++ {
		if remaining := limiter.Blocked("alice", "10.0.0.1"); remaining > 0 {
			t.Fatalf("第 %d 次失败前不应被锁定", index+1)
		}
		limiter.RecordFailure("alice", "10.0.0.1")
	}

	remaining := limiter.Blocked("alice", "10.0.0.1")
	if remaining <= 0 || remaining > loginLockoutDuration {
		t.Fatalf("达到阈值后应被锁定，实际剩余 %v", remaining)
	}

	if other := limiter.Blocked("bob", "10.0.0.1"); other > 0 {
		t.Fatalf("其他用户名不应被同一用户名计数影响：%v", other)
	}
}

func TestLoginLimiterResetClearsFailures(t *testing.T) {
	current := time.Now()
	limiter := newTestLimiter(&current)

	for index := 0; index < loginUserMaxFailures-1; index++ {
		limiter.RecordFailure("alice", "10.0.0.1")
	}
	limiter.Reset("alice", "10.0.0.1")

	for index := 0; index < loginUserMaxFailures-1; index++ {
		limiter.RecordFailure("alice", "10.0.0.1")
	}
	if remaining := limiter.Blocked("alice", "10.0.0.1"); remaining > 0 {
		t.Fatalf("重置后计数应从零开始，实际被锁定 %v", remaining)
	}
}

func TestLoginLimiterWindowExpiryReleases(t *testing.T) {
	current := time.Now()
	limiter := newTestLimiter(&current)

	for index := 0; index < loginUserMaxFailures; index++ {
		limiter.RecordFailure("alice", "10.0.0.1")
	}
	if remaining := limiter.Blocked("alice", "10.0.0.1"); remaining <= 0 {
		t.Fatalf("达到阈值后应被锁定")
	}

	current = current.Add(loginLockoutDuration + time.Second)
	if remaining := limiter.Blocked("alice", "10.0.0.1"); remaining > 0 {
		t.Fatalf("锁定到期后应放行，实际剩余 %v", remaining)
	}
}

func TestLoginLimiterIPThresholdAcrossUsers(t *testing.T) {
	current := time.Now()
	limiter := newTestLimiter(&current)

	for index := 0; index < loginIPMaxFailures; index++ {
		limiter.RecordFailure(string(rune('a'+index%26))+string(rune('0'+index%10)), "10.0.0.9")
	}
	if remaining := limiter.Blocked("someone", "10.0.0.9"); remaining <= 0 {
		t.Fatalf("同一来源 IP 累计失败应触发锁定")
	}
}

func TestLoginLimiterDoesNotLockAccountAcrossDifferentIPs(t *testing.T) {
	current := time.Now()
	limiter := newTestLimiter(&current)

	for index := 0; index < loginUserMaxFailures; index++ {
		limiter.RecordFailure("admin", "10.0.0.1")
	}
	if remaining := limiter.Blocked("admin", "10.0.0.1"); remaining <= 0 {
		t.Fatalf("同一账号与来源组合达到阈值后应被锁定")
	}
	if remaining := limiter.Blocked("admin", "10.0.0.2"); remaining > 0 {
		t.Fatalf("其他来源不应导致账号被全局锁定，实际剩余 %v", remaining)
	}
}
