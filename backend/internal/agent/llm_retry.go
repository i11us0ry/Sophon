package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	llmRetryMaxAttempts           = 4
	llmRetryMaxWait               = 35 * time.Second
	llmRetryMinWait               = 100 * time.Millisecond
	llmContentPolicyToolResultMax = 6000
	llmContentPolicyRetryMarker   = "[上游内容安全策略拒绝后，平台已压缩此工具结果并重试]"
)

var llmRequestIDPattern = regexp.MustCompile(`(?i)"?request_?id"?\s*[:=]\s*"?([a-z0-9][a-z0-9._-]{5,})`)

type llmRetryTransport struct {
	base         http.RoundTripper
	maxAttempts  int
	maxRetryWait time.Duration
	wait         func(context.Context, time.Duration) error
	pool         *llmKeyPool
}

func newLLMRetryTransport(base http.RoundTripper, pools ...*llmKeyPool) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	transport := &llmRetryTransport{
		base:         base,
		maxAttempts:  llmRetryMaxAttempts,
		maxRetryWait: llmRetryMaxWait,
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
		if err == nil {
			response, err = t.retryAfterContentPolicy(current, response, peekLLMResponseBody(response))
			if err == nil {
				response = rewriteLLMQuotaErrorIfNeeded(response)
			}
		}
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
	keyCount := t.pool.size()
	if keyCount == 0 {
		return syntheticLLMKeyPoolError(http.StatusServiceUnavailable, 0), nil
	}
	attemptLimit := t.maxAttempts
	if attemptLimit <= 0 {
		attemptLimit = llmRetryMaxAttempts
	}
	if keyCount > attemptLimit {
		attemptLimit = keyCount
	}
	maxWait := t.maxRetryWait
	if maxWait <= 0 {
		maxWait = llmRetryMaxWait
	}
	tried := make(map[int]bool, keyCount)
	attempts := 0
	waited := time.Duration(0)
	var lastResponse *http.Response
	var lastErr error
	for attempts < attemptLimit {
		candidate, ok := t.pool.acquire(tried)
		if !ok {
			tried = make(map[int]bool, keyCount)
			delay, retryable := t.pool.nextRetryDelay()
			if !retryable || request.Context().Err() != nil {
				break
			}
			if delay < llmRetryMinWait {
				delay = llmRetryMinWait
			}
			if waited+delay > maxWait {
				break
			}
			if err := t.waitForRetry(request.Context(), delay); err != nil {
				if lastResponse != nil {
					_ = lastResponse.Body.Close()
				}
				return nil, err
			}
			waited += delay
			continue
		}
		attempts++
		tried[candidate.index] = true
		current, err := requestForAttempt(request, attempts)
		if err != nil {
			t.pool.release(candidate.index)
			if lastResponse != nil {
				_ = lastResponse.Body.Close()
			}
			return nil, err
		}
		current.Header = request.Header.Clone()
		t.pool.applyAuthentication(current, candidate.value)

		response, runErr := t.base.RoundTrip(current)
		if response == nil {
			if request.Context().Err() != nil {
				t.pool.release(candidate.index)
				return nil, request.Context().Err()
			}
			lastErr = runErr
			t.pool.markFailure(candidate.index, llmKeyFailureTransient, 0)
			continue
		}
		if runErr == nil {
			response, runErr = t.retryAfterContentPolicy(current, response, peekLLMResponseBody(response))
			if runErr != nil {
				t.pool.release(candidate.index)
				lastErr = runErr
				continue
			}
		}
		body := peekLLMResponseBody(response)
		failure := classifyLLMKeyFailure(response.StatusCode, body, runErr)
		if failure == llmKeyFailureNone {
			if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices {
				t.pool.markSuccess(candidate.index)
			} else {
				t.pool.release(candidate.index)
			}
			if lastResponse != nil {
				_ = lastResponse.Body.Close()
			}
			return response, nil
		}
		lastErr = fmt.Errorf("模型网关返回 HTTP %d", response.StatusCode)
		t.pool.markFailure(candidate.index, failure, llmRetryDelay(attempts, response))
		if lastResponse != nil {
			_ = lastResponse.Body.Close()
		}
		lastResponse = response
	}
	if lastResponse != nil {
		return rewriteLLMKeyPoolError(lastResponse, attempts), nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("模型网关请求失败，已尝试 %d 次: %w", attempts, lastErr)
	}
	return syntheticLLMKeyPoolError(http.StatusServiceUnavailable, attempts), nil
}

func (t *llmRetryTransport) waitForRetry(ctx context.Context, delay time.Duration) error {
	if t.wait != nil {
		return t.wait(ctx, delay)
	}
	return waitForRetry(ctx, delay)
}

func (t *llmRetryTransport) retryAfterContentPolicy(
	request *http.Request,
	response *http.Response,
	body string,
) (*http.Response, error) {
	if !isLLMContentPolicyRejection(responseStatusCode(response), body) {
		return response, nil
	}
	retryRequest, changed := compressLLMRequestToolResult(request)
	if !changed {
		return rewriteLLMContentPolicyError(response, false), nil
	}
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	retried, err := t.base.RoundTrip(retryRequest)
	if err != nil {
		return nil, err
	}
	if isLLMContentPolicyRejection(retried.StatusCode, peekLLMResponseBody(retried)) {
		return rewriteLLMContentPolicyError(retried, true), nil
	}
	return retried, nil
}

func responseStatusCode(response *http.Response) int {
	if response == nil {
		return 0
	}
	return response.StatusCode
}

func compressLLMRequestToolResult(request *http.Request) (*http.Request, bool) {
	if request == nil || request.GetBody == nil {
		return nil, false
	}
	body, err := request.GetBody()
	if err != nil {
		return nil, false
	}
	defer body.Close()
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, false
	}

	var payload map[string]json.RawMessage
	if json.Unmarshal(raw, &payload) != nil {
		return nil, false
	}
	var messages []json.RawMessage
	if json.Unmarshal(payload["messages"], &messages) != nil {
		return nil, false
	}
	for index := len(messages) - 1; index >= 0; index-- {
		var message map[string]json.RawMessage
		if json.Unmarshal(messages[index], &message) != nil {
			continue
		}
		var role string
		if json.Unmarshal(message["role"], &role) != nil || role != "tool" {
			continue
		}
		var content string
		if json.Unmarshal(message["content"], &content) != nil {
			continue
		}
		compacted, changed := compactLLMToolResult(content)
		if !changed {
			continue
		}
		message["content"], _ = json.Marshal(compacted)
		messages[index], _ = json.Marshal(message)
		encodedMessages, _ := json.Marshal(messages)
		payload["messages"] = encodedMessages
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, false
		}
		clone := request.Clone(request.Context())
		clone.Body = io.NopCloser(bytes.NewReader(encoded))
		clone.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(encoded)), nil
		}
		clone.ContentLength = int64(len(encoded))
		clone.TransferEncoding = nil
		clone.Header = request.Header.Clone()
		clone.Header.Set("Content-Length", strconv.Itoa(len(encoded)))
		return clone, true
	}
	return nil, false
}

func compactLLMToolResult(content string) (string, bool) {
	runes := []rune(content)
	if len(runes) < 2 {
		return content, false
	}
	target := llmContentPolicyToolResultMax
	if len(runes) <= target {
		target = len(runes) / 2
	}
	if target < 64 {
		target = 64
	}
	if target >= len(runes) {
		target = len(runes) - 1
	}
	head := target / 2
	tail := target - head
	compacted := string(runes[:head]) +
		"\n\n" + llmContentPolicyRetryMarker + "\n\n" +
		string(runes[len(runes)-tail:])
	return compacted, compacted != content
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
	return rewriteLLMErrorResponse(
		response,
		response.StatusCode,
		fmt.Sprintf("llm_gateway_%d", response.StatusCode),
		fmt.Sprintf("模型网关返回 HTTP %d，已重试 %d 次仍失败，请稍后重试", response.StatusCode, attempts),
		"",
	)
}

func rewriteLLMErrorResponse(
	response *http.Response,
	status int,
	code string,
	message string,
	requestID string,
) *http.Response {
	if response == nil {
		return nil
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	errorPayload := map[string]interface{}{
		"code":    code,
		"message": message,
	}
	if requestID != "" {
		errorPayload["request_id"] = requestID
	}
	encoded, _ := json.Marshal(map[string]interface{}{"error": errorPayload})
	if status <= 0 {
		status = http.StatusBadGateway
	}
	response.StatusCode = status
	response.Status = fmt.Sprintf("%d %s", status, http.StatusText(status))
	response.Header = make(http.Header)
	response.Header.Set("Content-Type", "application/json; charset=utf-8")
	response.Body = io.NopCloser(bytes.NewReader(encoded))
	response.ContentLength = int64(len(encoded))
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
	body := peekLLMResponseBody(response)
	if llmQuotaError(strings.ToLower(body)) {
		return rewriteLLMQuotaError(response)
	}
	return rewriteLLMErrorResponse(
		response,
		http.StatusServiceUnavailable,
		"llm_key_pool_exhausted",
		fmt.Sprintf("模型网关暂时不可用，已尝试 %d 次并等待冷却，仍未恢复", attempts),
		"",
	)
}

func rewriteLLMQuotaErrorIfNeeded(response *http.Response) *http.Response {
	if response == nil || response.StatusCode != http.StatusBadRequest {
		return response
	}
	if !llmQuotaError(strings.ToLower(peekLLMResponseBody(response))) {
		return response
	}
	return rewriteLLMQuotaError(response)
}

func rewriteLLMQuotaError(response *http.Response) *http.Response {
	requestID := extractLLMRequestID(peekLLMResponseBody(response))
	message := "模型网关提示余额不足（NOT_ENOUGH_BALANCE），请检查 Key 余额或切换可用 Key"
	if requestID != "" {
		message += "（request_id: " + requestID + "）"
	}
	return rewriteLLMErrorResponse(
		response,
		http.StatusPaymentRequired,
		"llm_balance_insufficient",
		message,
		requestID,
	)
}

func rewriteLLMContentPolicyError(response *http.Response, retried bool) *http.Response {
	requestID := extractLLMRequestID(peekLLMResponseBody(response))
	message := "上游模型网关拒绝了请求内容（内容安全策略）"
	if retried {
		message += "，已自动压缩最后一次工具结果并重试一次仍失败"
	} else {
		message += "，但请求中没有可压缩的 tool 结果，未自动重试"
	}
	message += "。请更换模型提供方，或进一步压缩上下文后继续"
	if requestID != "" {
		message += "（request_id: " + requestID + "）"
	}
	return rewriteLLMErrorResponse(
		response,
		http.StatusBadRequest,
		"llm_content_policy_rejected",
		message,
		requestID,
	)
}

func extractLLMRequestID(body string) string {
	match := llmRequestIDPattern.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func isLLMContentPolicyRejection(status int, body string) bool {
	if status != http.StatusBadRequest {
		return false
	}
	message := strings.ToLower(body)
	for _, marker := range []string{
		"安全策略",
		"内容安全",
		"内容审核",
		"content policy",
		"safety policy",
		"moderation",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func syntheticLLMKeyPoolError(status int, attempts int) *http.Response {
	if status <= 0 {
		status = http.StatusServiceUnavailable
	}
	payload := fmt.Sprintf(
		`{"error":{"code":"llm_key_pool_exhausted","message":"没有可用的 LLM API Key，已尝试 %d 次"}}`,
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

func isLLMContentPolicyError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "llm_content_policy_rejected") ||
		strings.Contains(message, "内容安全策略") ||
		strings.Contains(message, "上游内容拒绝")
}

func isLLMQuotaError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "llm_balance_insufficient") || llmQuotaError(message)
}

// IsLLMContentPolicyError 判断错误是否来自上游内容安全拒绝。
func IsLLMContentPolicyError(err error) bool {
	return isLLMContentPolicyError(err)
}

// IsLLMQuotaError 判断错误是否表示 API Key 余额或额度不足。
func IsLLMQuotaError(err error) bool {
	return isLLMQuotaError(err)
}

// IsLLMGatewayError 判断错误是否来自模型网关。
func IsLLMGatewayError(err error) bool {
	return isLLMGatewayError(err)
}
