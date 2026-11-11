package auth

import (
	"strings"
	"sync"
	"time"
)

const (
	loginUserMaxFailures = 5
	loginIPMaxFailures   = 30
	loginFailureWindow   = 15 * time.Minute
	loginLockoutDuration = 15 * time.Minute
	loginLimiterMaxKeys  = 10000
)

type loginAttempt struct {
	failures     int
	firstFailure time.Time
	blockedUntil time.Time
}

// LoginLimiter 是进程内的登录失败限流器：按账号与来源 IP 组合、以及来源 IP 双维度计数。
// 账号组合阈值低（防撞库），IP 阈值高（避免 NAT 环境误伤整片用户）。
type LoginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempt
	userMax int
	ipMax   int
	window  time.Duration
	lockout time.Duration
	now     func() time.Time
}

func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{
		entries: make(map[string]*loginAttempt),
		userMax: loginUserMaxFailures,
		ipMax:   loginIPMaxFailures,
		window:  loginFailureWindow,
		lockout: loginLockoutDuration,
		now:     time.Now,
	}
}

// Blocked 返回剩余锁定时长；未锁定时返回 0。
func (l *LoginLimiter) Blocked(username, ip string) time.Duration {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if remaining := l.remainingLocked(accountKey(username, ip), now); remaining > 0 {
		return remaining
	}
	return l.remainingLocked(ipKey(ip), now)
}

// RecordFailure 记录一次登录失败。
func (l *LoginLimiter) RecordFailure(username, ip string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.record(accountKey(username, ip), l.userMax, now)
	if strings.TrimSpace(ip) != "" {
		l.record(ipKey(ip), l.ipMax, now)
	}
	l.pruneLocked(now)
}

// Reset 在登录成功后清除该用户名与来源 IP 的失败计数。
func (l *LoginLimiter) Reset(username, ip string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	delete(l.entries, accountKey(username, ip))
	if strings.TrimSpace(ip) != "" {
		delete(l.entries, ipKey(ip))
	}
}

func (l *LoginLimiter) record(key string, max int, now time.Time) {
	if key == "" || max <= 0 {
		return
	}
	entry := l.entries[key]
	if entry == nil || now.Sub(entry.firstFailure) > l.window {
		entry = &loginAttempt{firstFailure: now}
		l.entries[key] = entry
	}
	entry.failures++
	if entry.failures >= max {
		entry.blockedUntil = now.Add(l.lockout)
	}
}

func (l *LoginLimiter) remainingLocked(key string, now time.Time) time.Duration {
	entry := l.entries[key]
	if entry == nil {
		return 0
	}
	if entry.blockedUntil.After(now) {
		return entry.blockedUntil.Sub(now)
	}
	if now.Sub(entry.firstFailure) > l.window {
		delete(l.entries, key)
	}
	return 0
}

// pruneLocked 仅在条目过多时回收过期记录，避免内存无上限增长。
func (l *LoginLimiter) pruneLocked(now time.Time) {
	if len(l.entries) <= loginLimiterMaxKeys {
		return
	}
	for key, entry := range l.entries {
		if !entry.blockedUntil.After(now) && now.Sub(entry.firstFailure) > l.window {
			delete(l.entries, key)
		}
	}
}

func accountKey(username, ip string) string {
	username = strings.ToLower(strings.TrimSpace(username))
	ip = strings.TrimSpace(ip)
	if username == "" || ip == "" {
		return ""
	}
	return "account:" + username + "@" + ip
}

func ipKey(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	return "ip:" + ip
}
