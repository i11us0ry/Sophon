package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const llmRetryMaxAttempts = 4

type llmRetryTransport struct {
	base        http.RoundTripper
	maxAttempts int
	pool        *llmKeyPool
}

func newLLMRetryTransport(base http.RoundTripper, pools ...*llmKeyPool) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	transport := &llmRetryTransport{
		base:        base,
		maxAttempts: llmRetryMaxAttempts,
	}
	if len(pools) > 0 {
		transport.pool = pools[0]
	}
	return transport
}

func (t *llmRetryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, fmt.Errorf("请求不能为空")
	}
	if t.pool != nil {
		return t.roundTripWithKeyPool(request)
	}
	return t.roundTripWithRetry(request)
}

func (t *llmRetryTransport) roundTripWithRetry(request *http.Request) (*http.Response, error) {
	attempts := t.maxAttempts
	if attempts <= 0 {
		attempts = llmRetryMaxAttempts
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		current, err := requestForAttempt(request, attempt)
		if err != nil {
			return nil, err
		}
		response, err := t.base.RoundTrip(current)
		if err == nil && !isRetryableLLMStatus(response.StatusCode) {
			return response, nil
		}
		if err == nil {
			lastErr = fmt.Errorf("模型网关返回 HTTP %d", response.StatusCode)
		} else {
			lastErr = err
		}
		if attempt >= attempts || request.Context().Err() != nil {
			if response != nil {
				return rewriteLLMGatewayError(response, attempts), nil
			}
			return nil, fmt.Errorf("模型网关请求失败，已重试 %d 次: %w", attempts, lastErr)
		}
		delay := llmRetryDelay(attempt, response)
		if response != nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
			_ = response.Body.Close()
		}
		if err := waitForRetry(request.Context(), delay); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

func (t *llmRetryTransport) roundTripWithKeyPool(request *http.Request) (*http.Response, error) {
	attempts := t.pool.size()
	if attempts == 0 {
		return syntheticLLMKeyPoolError(http.StatusServiceUnavailable, 0), nil
	}
	tried := make(map[int]bool, attempts)
	var lastResponse *http.Response
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		candidate, ok := t.pool.acquire(tried)
		if !ok {
			break
		}
		tried[candidate.index] = true
		current, err := requestForAttempt(request, attempt)
		if err != nil {
			if lastResponse != nil {
				_ = lastResponse.Body.Close()
			}
			return nil, err
		}
		current.Header = request.Header.Clone()
		t.pool.applyAuthentication(current, candidate.value)

		response, runErr := t.base.RoundTrip(current)
		if response == nil {
			lastErr = runErr
			t.pool.markFailure(candidate.index, llmKeyFailureTransient, 0)
			continue
		}
		body := peekLLMResponseBody(response)
		failure := classifyLLMKeyFailure(response.StatusCode, body, runErr)
		if failure == llmKeyFailureNone {
			t.pool.markSuccess(candidate.index)
			if lastResponse != nil {
				_ = lastResponse.Body.Close()
			}
			return response, nil
		}
		lastErr = fmt.Errorf("模型网关返回 HTTP %d", response.StatusCode)
		t.pool.markFailure(candidate.index, failure, llmRetryDelay(attempt, response))
		if lastResponse != nil {
			_ = lastResponse.Body.Close()
		}
		lastResponse = response
	}
	if lastResponse != nil {
		return rewriteLLMKeyPoolError(lastResponse, len(tried)), nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("模型网关请求失败，已尝试 %d 个 Key: %w", len(tried), lastErr)
	}
	return syntheticLLMKeyPoolError(http.StatusServiceUnavailable, len(tried)), nil
}

func requestForAttempt(request *http.Request, attempt int) (*http.Request, error) {
	if attempt == 1 {
		return request, nil
	}
	clone := request.Clone(request.Context())
	if request.Body == nil {
		return clone, nil
	}
	if request.GetBody == nil {
		return nil, fmt.Errorf("请求体无法重放，不能自动重试")
	}
	body, err := request.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}

func isRetryableLLMStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func llmRetryDelay(attempt int, response *http.Response) time.Duration {
	if response != nil {
		if value := strings.TrimSpace(response.Header.Get("Retry-After")); value != "" {
			if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
				delay := time.Duration(seconds) * time.Second
				if delay > 10*time.Second {
					delay = 10 * time.Second
				}
				return delay
			}
			if at, err := http.ParseTime(value); err == nil {
				delay := time.Until(at)
				if delay > 0 {
					if delay > 10*time.Second {
						delay = 10 * time.Second
					}
					return delay
				}
			}
		}
	}
	switch attempt {
	case 1:
		return 300 * time.Millisecond
	case 2:
		return time.Second
	default:
		return 3 * time.Second
	}
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func rewriteLLMGatewayError(response *http.Response, attempts int) *http.Response {
	if response == nil {
		return nil
	}
	payload := fmt.Sprintf(
		`{"error":{"code":"llm_gateway_%d","message":"模型网关返回 HTTP %d，已重试 %d 次仍失败，请稍后重试"}}`,
		response.StatusCode,
		response.StatusCode,
		attempts,
	)
	response.Header = make(http.Header)
	response.Header.Set("Content-Type", "application/json; charset=utf-8")
	response.Body = io.NopCloser(bytes.NewBufferString(payload))
	response.ContentLength = int64(len(payload))
	response.TransferEncoding = nil
	response.Header.Del("Content-Encoding")
	return response
}

func peekLLMResponseBody(response *http.Response) string {
	if response == nil || response.Body == nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	response.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), response.Body))
	return string(body)
}

func rewriteLLMKeyPoolError(response *http.Response, attempts int) *http.Response {
	if response == nil {
		return syntheticLLMKeyPoolError(http.StatusServiceUnavailable, attempts)
	}
	_ = response.Body.Close()
	payload := fmt.Sprintf(
		`{"error":{"code":"llm_key_pool_exhausted","message":"所有 LLM API Key 均不可用或正在冷却，已尝试 %d 个"}}`,
		attempts,
	)
	response.StatusCode = http.StatusServiceUnavailable
	response.Status = "503 Service Unavailable"
	response.Header = make(http.Header)
	response.Header.Set("Content-Type", "application/json; charset=utf-8")
	response.Body = io.NopCloser(bytes.NewBufferString(payload))
	response.ContentLength = int64(len(payload))
	response.TransferEncoding = nil
	response.Header.Del("Content-Encoding")
	return response
}

func syntheticLLMKeyPoolError(status int, attempts int) *http.Response {
	if status <= 0 {
		status = http.StatusServiceUnavailable
	}
	payload := fmt.Sprintf(
		`{"error":{"code":"llm_key_pool_exhausted","message":"没有可用的 LLM API Key，已尝试 %d 个"}}`,
		attempts,
	)
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:          io.NopCloser(bytes.NewBufferString(payload)),
		ContentLength: int64(len(payload)),
		Request:       nil,
	}
}

func isLLMGatewayError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "llm_gateway_") ||
		strings.Contains(message, "llm_key_pool_") ||
		strings.Contains(message, "模型网关") ||
		strings.Contains(message, "bad gateway")
}
