package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLLMRetryTransportRetriesGatewayErrorsAndReplaysBody(t *testing.T) {
	attempts := 0
	bodies := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		body, _ := io.ReadAll(request.Body)
		bodies <- string(body)
		if attempts < 3 {
			http.Error(writer, "bad gateway", http.StatusBadGateway)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := &http.Client{Transport: newLLMRetryTransport(http.DefaultTransport)}
	request, err := http.NewRequest(
		http.MethodPost,
		server.URL,
		bytes.NewBufferString(`{"ping":"pong"}`),
	)
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if attempts != 3 {
		t.Fatalf("应重试到第 3 次成功，实际 %d", attempts)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("状态码应为 200，实际 %d", response.StatusCode)
	}
	for index := 0; index < 3; index++ {
		if body := <-bodies; body != `{"ping":"pong"}` {
			t.Fatalf("第 %d 次请求体重放错误: %q", index+1, body)
		}
	}
}

func TestLLMRetryTransportReturnsStructuredErrorAfterRetries(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		writer.Header().Set("Content-Type", "text/html")
		writer.WriteHeader(http.StatusBadGateway)
		_, _ = writer.Write([]byte(`<html>502 Bad Gateway</html>`))
	}))
	defer server.Close()

	transport := &llmRetryTransport{
		base:        http.DefaultTransport,
		maxAttempts: 2,
	}
	client := &http.Client{Transport: transport}
	request, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if attempts != 2 {
		t.Fatalf("应尝试 2 次，实际 %d", attempts)
	}
	var payload map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("错误响应应为 JSON: %v", err)
	}
	if !bytes.Contains([]byte(payload["error"].(map[string]interface{})["code"].(string)), []byte("llm_gateway_502")) {
		t.Fatalf("错误代码错误: %+v", payload)
	}
}

func TestLLMRetryTransportWaitsForKeyCooldownAndRetries(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if attempts.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte(`{"error":{"message":"upstream unavailable"}}`))
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	pool := newLLMKeyPool([]string{"key-a"}, "openai_compatible")
	now := time.Now()
	pool.now = func() time.Time { return now }
	waits := 0
	transport := &llmRetryTransport{
		base:         http.DefaultTransport,
		maxAttempts:  2,
		maxRetryWait: 20 * time.Second,
		pool:         pool,
		wait: func(_ context.Context, delay time.Duration) error {
			waits++
			now = now.Add(delay)
			return nil
		},
	}
	client := &http.Client{Transport: transport}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || attempts.Load() != 2 {
		t.Fatalf("应在冷却后重试成功，status=%d attempts=%d", response.StatusCode, attempts.Load())
	}
	if waits != 1 {
		t.Fatalf("应等待一次冷却，实际 %d", waits)
	}
}

func TestLLMRetryTransportDoesNotWaitForAuthenticationFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	defer server.Close()

	pool := newLLMKeyPool([]string{"bad-key"}, "openai_compatible")
	waits := 0
	transport := &llmRetryTransport{
		base:         http.DefaultTransport,
		maxAttempts:  4,
		maxRetryWait: 20 * time.Second,
		pool:         pool,
		wait: func(_ context.Context, _ time.Duration) error {
			waits++
			return nil
		},
	}
	client := &http.Client{Transport: transport}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || attempts.Load() != 1 {
		t.Fatalf("鉴权失败不应等待重试，status=%d attempts=%d", response.StatusCode, attempts.Load())
	}
	if waits != 0 {
		t.Fatalf("鉴权失败不应进入等待，实际等待 %d 次", waits)
	}
}

func TestLLMRetryTransportCompressesLastToolResultOnContentPolicy(t *testing.T) {
	attempts := 0
	var retriedMessages []map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		var payload struct {
			Messages []map[string]interface{} `json:"messages"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("解析请求失败: %v", err)
		}
		if attempts == 1 {
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte(`{"error":{"message":"请求内容未通过安全策略检查","request_id":"req-policy-1"}}`))
			return
		}
		retriedMessages = payload.Messages
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	toolContent := strings.Repeat("开头内容", 1200) + "中间证据" + strings.Repeat("结尾内容", 1200)
	payload, _ := json.Marshal(map[string]interface{}{
		"model": "test-model",
		"messages": []map[string]interface{}{
			{"role": "system", "content": "保持不变"},
			{"role": "tool", "tool_call_id": "call-1", "content": toolContent},
		},
	})
	request, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Transport: newLLMRetryTransport(http.DefaultTransport)}).Do(request)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || attempts != 2 {
		t.Fatalf("应压缩后重试一次成功，status=%d attempts=%d", response.StatusCode, attempts)
	}
	if len(retriedMessages) != 2 ||
		retriedMessages[0]["content"] != "保持不变" ||
		retriedMessages[1]["role"] != "tool" {
		t.Fatalf("重试请求消息结构错误: %+v", retriedMessages)
	}
	retriedContent, _ := retriedMessages[1]["content"].(string)
	if !strings.Contains(retriedContent, llmContentPolicyRetryMarker) ||
		len([]rune(retriedContent)) >= len([]rune(toolContent)) {
		t.Fatalf("最后一次工具结果未被有效压缩: %d -> %d", len([]rune(toolContent)), len([]rune(retriedContent)))
	}
}

func TestLLMRetryTransportReportsContentPolicyAfterCompressedRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":{"code":"content_policy","message":"上游安全策略拒绝","request_id":"req-policy-2"}}`))
	}))
	defer server.Close()

	payload, _ := json.Marshal(map[string]interface{}{
		"messages": []map[string]interface{}{
			{"role": "tool", "content": strings.Repeat("工具输出", 2000)},
		},
	})
	request, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	response, err := (&http.Client{Transport: newLLMRetryTransport(http.DefaultTransport)}).Do(request)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest || attempts != 2 {
		t.Fatalf("压缩后仍拒绝应返回 400 且只重试一次，status=%d attempts=%d", response.StatusCode, attempts)
	}
	var result struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatalf("错误响应 JSON 无效: %v", err)
	}
	if result.Error.Code != "llm_content_policy_rejected" ||
		result.Error.RequestID != "req-policy-2" ||
		!strings.Contains(result.Error.Message, "更换模型提供方") {
		t.Fatalf("内容拒绝错误信息错误: %+v", result.Error)
	}
}

func TestLLMRetryTransportReportsNotEnoughBalance(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts++
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":{"code":"NOT_ENOUGH_BALANCE","message":"余额不足","request_id":"req-balance-1"}}`))
	}))
	defer server.Close()

	response, err := (&http.Client{Transport: newLLMRetryTransport(http.DefaultTransport)}).Get(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusPaymentRequired || attempts != 1 {
		t.Fatalf("余额不足应返回 402 且不重试，status=%d attempts=%d", response.StatusCode, attempts)
	}
	body, _ := io.ReadAll(response.Body)
	if !bytes.Contains(body, []byte(`"code":"llm_balance_insufficient"`)) ||
		!bytes.Contains(body, []byte(`"request_id":"req-balance-1"`)) ||
		bytes.Contains(body, []byte("请求参数不正确")) {
		t.Fatalf("余额不足错误信息错误: %s", body)
	}
}
