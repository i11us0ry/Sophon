package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLLMKeyPoolFailsOverAfterUnauthorized(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		body, _ := io.ReadAll(request.Body)
		if string(body) != `{"ping":"pong"}` {
			t.Errorf("请求体未正确重放: %q", body)
		}
		switch request.Header.Get("Authorization") {
		case "Bearer key-a":
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":{"code":"invalid_api_key"}}`))
		case "Bearer key-b":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"ok":true}`))
		default:
			t.Errorf("未设置预期的 Authorization: %q", request.Header.Get("Authorization"))
		}
	}))
	defer server.Close()

	client := &http.Client{Transport: newLLMRetryTransport(
		http.DefaultTransport,
		newLLMKeyPool([]string{"key-a", "key-b"}, "openai_compatible"),
	)}
	request, err := http.NewRequest(http.MethodPost, server.URL, bytes.NewBufferString(`{"ping":"pong"}`))
	if err != nil {
		t.Fatalf("创建请求失败: %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("应切换到第二个 Key 成功，实际 HTTP %d", response.StatusCode)
	}
	if attempts.Load() != 2 {
		t.Fatalf("应尝试 2 个 Key，实际 %d", attempts.Load())
	}
}

func TestLLMKeyPoolFailsOverOnInsufficientQuota(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		if request.Header.Get("Authorization") == "Bearer key-a" {
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = writer.Write([]byte(`{"error":{"code":"insufficient_quota","message":"余额不足"}}`))
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := &http.Client{Transport: newLLMRetryTransport(
		http.DefaultTransport,
		newLLMKeyPool([]string{"key-a", "key-b"}, "openai_compatible"),
	)}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("余额不足时应切换 Key，实际 HTTP %d", response.StatusCode)
	}
	if attempts.Load() != 2 {
		t.Fatalf("应尝试 2 个 Key，实际 %d", attempts.Load())
	}
}

func TestLLMKeyPoolDoesNotFailOverOnRequestError(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts.Add(1)
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":{"message":"invalid parameter"}}`))
	}))
	defer server.Close()

	client := &http.Client{Transport: newLLMRetryTransport(
		http.DefaultTransport,
		newLLMKeyPool([]string{"key-a", "key-b"}, "openai_compatible"),
	)}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("普通请求错误应直接返回，实际 HTTP %d", response.StatusCode)
	}
	if attempts.Load() != 1 {
		t.Fatalf("普通请求错误不应切换 Key，实际尝试 %d 次", attempts.Load())
	}
}

func TestLLMKeyPoolExhaustedErrorDoesNotLeakKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	defer server.Close()

	client := &http.Client{Transport: newLLMRetryTransport(
		http.DefaultTransport,
		newLLMKeyPool([]string{"secret-key-a", "secret-key-b"}, "openai_compatible"),
	)}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Key 池耗尽应返回 503，实际 %d", response.StatusCode)
	}
	if strings.Contains(string(body), "secret-key") {
		t.Fatalf("错误响应泄露 Key: %s", body)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("错误响应不是 JSON: %v", err)
	}
	errorPayload, _ := payload["error"].(map[string]interface{})
	if errorPayload["code"] != "llm_key_pool_exhausted" {
		t.Fatalf("错误码不正确: %+v", payload)
	}
}

func TestLLMKeyPoolUsesAnthropicHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("x-api-key") != "anthropic-key" {
			t.Errorf("Anthropic Key 头错误: %q", request.Header.Get("x-api-key"))
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{Transport: newLLMRetryTransport(
		http.DefaultTransport,
		newLLMKeyPool([]string{"anthropic-key", "backup-key"}, "anthropic"),
	)}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	_ = response.Body.Close()
}
