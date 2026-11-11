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
}

func newLLMRetryTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &llmRetryTransport{
		base:        base,
		maxAttempts: llmRetryMaxAttempts,
	}
}

func (t *llmRetryTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil {
		return nil, fmt.Errorf("请求不能为空")
	}
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

func isLLMGatewayError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "llm_gateway_") ||
		strings.Contains(message, "模型网关") ||
		strings.Contains(message, "bad gateway")
}
