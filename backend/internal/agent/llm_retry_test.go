package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
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
