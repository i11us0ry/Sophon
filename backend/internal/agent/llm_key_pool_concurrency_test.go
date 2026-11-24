package agent

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLLMKeyPoolDistributesConcurrentRequests(t *testing.T) {
	pool := newLLMKeyPool([]string{"key-a", "key-b"}, "openai_compatible")
	first, ok := pool.acquire(map[int]bool{})
	if !ok || first.index != 0 {
		t.Fatalf("首个请求应使用 key-a: %+v %t", first, ok)
	}
	second, ok := pool.acquire(map[int]bool{})
	if !ok || second.index != 1 {
		t.Fatalf("第二个并发请求应分摊到 key-b: %+v %t", second, ok)
	}
	third, ok := pool.acquire(map[int]bool{})
	if !ok || third.index != 0 {
		t.Fatalf("两个 Key 均有占用时应继续轮询 key-a: %+v %t", third, ok)
	}

	snapshot := pool.snapshot()
	if snapshot.InFlight != 3 || snapshot.Requests != 3 {
		t.Fatalf("并发占用统计异常: %+v", snapshot)
	}
	pool.release(first.index)
	pool.release(second.index)
	pool.release(third.index)
	if snapshot = pool.snapshot(); snapshot.InFlight != 0 {
		t.Fatalf("释放后仍有占用: %+v", snapshot)
	}
}

func TestLLMKeyPoolCooldownAndStats(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	pool := newLLMKeyPool([]string{"key-a", "key-b"}, "openai_compatible")
	pool.now = func() time.Time { return now }

	first, _ := pool.acquire(map[int]bool{})
	second, _ := pool.acquire(map[int]bool{})
	pool.markSuccess(first.index)
	pool.markFailure(second.index, llmKeyFailureRateLimit, 45*time.Second)

	snapshot := pool.snapshot()
	if snapshot.InFlight != 0 ||
		snapshot.Cooling != 1 ||
		snapshot.Successes != 1 ||
		snapshot.Failures["rate_limit"] != 1 {
		t.Fatalf("Key 池统计异常: %+v", snapshot)
	}
	next, ok := pool.acquire(map[int]bool{})
	if !ok || next.index != first.index {
		t.Fatalf("冷却 Key 应被跳过: %+v %t", next, ok)
	}
	pool.release(next.index)
}

func TestLLMKeyPoolHonorsPerKeyConcurrencyLimit(t *testing.T) {
	pool := newLLMKeyPool([]string{"key-a", "key-b"}, "openai_compatible", 1)
	first, ok := pool.acquire(map[int]bool{})
	if !ok {
		t.Fatal("第一个 Key 应可用")
	}
	second, ok := pool.acquire(map[int]bool{})
	if !ok {
		t.Fatal("第二个 Key 应可用")
	}
	if _, ok := pool.acquire(map[int]bool{}); ok {
		t.Fatal("两个 Key 达到并发上限后不应继续分配")
	}
	snapshot := pool.snapshot()
	if snapshot.MaxInFlight != 1 || snapshot.InFlight != 2 {
		t.Fatalf("并发上限统计异常: %+v", snapshot)
	}
	pool.release(first.index)
	if _, ok := pool.acquire(map[int]bool{}); !ok {
		t.Fatal("释放后应恢复可用")
	}
	pool.release(second.index)
}

func TestLLMKeyPoolsAreIsolatedPerGateway(t *testing.T) {
	gatewayA := newLLMKeyPool([]string{"a-1"}, "openai_compatible")
	gatewayB := newLLMKeyPool([]string{"b-1"}, "openai_compatible")
	candidate, _ := gatewayA.acquire(map[int]bool{})
	gatewayA.markFailure(candidate.index, llmKeyFailureAuth, 0)

	if snapshot := gatewayA.snapshot(); snapshot.Cooling != 1 || snapshot.Failures["auth"] != 1 {
		t.Fatalf("网关 A 统计异常: %+v", snapshot)
	}
	if snapshot := gatewayB.snapshot(); snapshot.Cooling != 0 || snapshot.Requests != 0 {
		t.Fatalf("网关 B 不应共享网关 A 的冷却或统计: %+v", snapshot)
	}
	if _, ok := gatewayB.acquire(map[int]bool{}); !ok {
		t.Fatal("网关 A 的冷却不应影响网关 B")
	}
}

type llmRoundTripFunc func(*http.Request) (*http.Response, error)

func (f llmRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestLLMKeyPoolReleasesCancelledRequestWithoutCooldown(t *testing.T) {
	pool := newLLMKeyPool([]string{"key-a"}, "openai_compatible")
	transport := newLLMRetryTransport(llmRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, request.Context().Err()
	}), pool)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/v1/chat", nil)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("取消请求应返回错误")
	}
	snapshot := pool.snapshot()
	if snapshot.InFlight != 0 || snapshot.Cooling != 0 || len(snapshot.Failures) != 0 {
		t.Fatalf("取消请求不应惩罚 Key: %+v", snapshot)
	}
}

func TestLLMKeyPoolReleasesKeyWhenBodyCannotReplay(t *testing.T) {
	pool := newLLMKeyPool([]string{"key-a", "key-b"}, "openai_compatible")
	calls := 0
	transport := newLLMRetryTransport(llmRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"error":{"code":"invalid_api_key"}}`,
			)),
			Request: request,
		}, nil
	}), pool)
	request, err := http.NewRequest(
		http.MethodPost,
		"https://example.com/v1/chat",
		io.NopCloser(strings.NewReader(`{"ping":"pong"}`)),
	)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	request.GetBody = nil
	if _, err := transport.RoundTrip(request); err == nil ||
		!strings.Contains(err.Error(), "请求体无法重放") {
		t.Fatalf("请求体不可重放时应返回明确错误: %v", err)
	}
	snapshot := pool.snapshot()
	if calls != 1 || snapshot.InFlight != 0 || snapshot.Requests != 2 || snapshot.Cooling != 1 {
		t.Fatalf("不可重放请求未正确释放第二个 Key: calls=%d snapshot=%+v", calls, snapshot)
	}
}
