package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/config"

	"github.com/gin-gonic/gin"
)

func TestSettingsUpdateSavesMultipleLLMKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("agent:\n  llm:\n    api_key: legacy\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}
	handler := &SettingsHandler{
		cfg: config.Config{
			ConfigPath:  path,
			LLMProvider: "openai_compatible",
			LLMBaseURL:  "https://api.example.com/v1",
			LLMAPIKey:   "legacy",
			LLMModel:    "test-model",
		},
		configPath: path,
	}
	payload, err := json.Marshal(map[string]interface{}{
		"llm": map[string]string{"apiKeys": " key-a\nkey-b\n\nkey-a "},
	})
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	recorder := performSettingsUpdate(t, handler, string(payload))
	if recorder.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	text := string(raw)
	for _, want := range []string{"api_keys:", "- key-a", "- key-b", "api_key: \"\""} {
		if !strings.Contains(text, want) {
			t.Fatalf("配置缺少 %q: %s", want, text)
		}
	}
	if strings.Count(text, "- key-a") != 1 {
		t.Fatalf("重复 Key 应去重: %s", text)
	}
}

func TestSettingsUpdateRejectsTooManyLLMKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("agent:\n  llm:\n    api_key: legacy\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}
	handler := &SettingsHandler{
		cfg:        config.Config{ConfigPath: path, LLMAPIKey: "legacy"},
		configPath: path,
	}
	keys := ""
	for index := 0; index < 21; index++ {
		keys += fmt.Sprintf("key-%d\n", index)
	}
	payload, err := json.Marshal(map[string]interface{}{
		"llm": map[string]string{"apiKeys": keys},
	})
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	recorder := performSettingsUpdate(t, handler, string(payload))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("超过 20 个 Key 应拒绝，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	if code := responseCode(t, recorder); code != "invalid_settings" {
		t.Fatalf("错误码错误: %s", code)
	}
}

func TestMaskedLLMAPIKeysDoesNotExposeSecrets(t *testing.T) {
	keys := effectiveLLMAPIKeys(config.Config{LLMAPIKeys: []string{"secret-key-a", "secret-key-b"}})
	masked := maskedLLMAPIKeys(keys)
	if len(masked) != 2 {
		t.Fatalf("掩码数量错误: %v", masked)
	}
	for _, value := range masked {
		if strings.Contains(value, "secret") {
			t.Fatalf("掩码泄露 Key: %q", value)
		}
	}
}

func TestLLMKeyMaskAndFingerprintAreStable(t *testing.T) {
	key := "sk-1234567890ea0b"
	if got := maskLLMKey(key); got != "sk-12****ea0b" {
		t.Fatalf("Key 脱敏格式错误: %q", got)
	}
	first := llmKeyID(key)
	second := llmKeyID(key)
	if first == "" || first != second {
		t.Fatalf("Key 指纹应稳定: %q %q", first, second)
	}
	if strings.Contains(first, key) {
		t.Fatalf("Key 指纹不能包含明文: %q", first)
	}
}

func TestMergeLLMKeysRejectsMoreThanTwenty(t *testing.T) {
	keys := make([]string, 0, 21)
	for index := 0; index < 21; index++ {
		keys = append(keys, fmt.Sprintf("key-%d", index))
	}
	if _, err := mergeLLMKeys(nil, keys); err == nil {
		t.Fatal("超过 20 个 Key 应被拒绝")
	}
	merged, err := mergeLLMKeys([]string{"key-a", "key-b"}, []string{"key-b", "key-c"})
	if err != nil {
		t.Fatalf("合并 Key 失败: %v", err)
	}
	if strings.Join(merged, ",") != "key-a,key-b,key-c" {
		t.Fatalf("合并结果错误: %v", merged)
	}
}

func TestProbeLLMKeyStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.Header.Get("Authorization") {
		case "Bearer healthy":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"ok":true}`))
		case "Bearer auth-error":
			writer.WriteHeader(http.StatusUnauthorized)
			_, _ = writer.Write([]byte(`{"error":{"message":"invalid api key"}}`))
		case "Bearer quota-error":
			writer.WriteHeader(http.StatusPaymentRequired)
			_, _ = writer.Write([]byte(`{"error":{"message":"insufficient balance"}}`))
		default:
			writer.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	cfg := config.Config{
		LLMProvider: "openai_compatible",
		LLMBaseURL:  server.URL,
		LLMModel:    "test-model",
	}
	cases := []struct {
		key        string
		wantStatus string
		wantText   string
	}{
		{key: "healthy", wantStatus: llmKeyStatusHealthy, wantText: "正常"},
		{key: "auth-error", wantStatus: llmKeyStatusError, wantText: "认证失败"},
		{key: "quota-error", wantStatus: llmKeyStatusError, wantText: "额度不足"},
	}
	for _, item := range cases {
		got := probeLLMKey(context.Background(), server.Client(), cfg, item.key)
		if got.Status != item.wantStatus || !strings.Contains(got.Message, item.wantText) {
			t.Fatalf("Key %s 检测结果错误: %+v", item.key, got)
		}
	}
}

func TestAddAndDeleteLLMKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("agent:\n  llm:\n    api_key: key-a\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}
	handler := &SettingsHandler{
		cfg: config.Config{
			ConfigPath:  path,
			LLMProvider: "openai_compatible",
			LLMBaseURL:  "https://api.example.com/v1",
			LLMAPIKeys:  []string{"key-a"},
			LLMAPIKey:   "key-a",
			LLMModel:    "test-model",
		},
		configPath: path,
	}

	addBody, _ := json.Marshal(map[string]string{"apiKeys": "key-b\nkey-c\nkey-b"})
	addResponse := performKeyRequest(t, http.MethodPost, "/settings/llm/keys", addBody,
		func(router *gin.Engine) {
			router.POST("/settings/llm/keys", handler.AddLLMKeys)
		})
	if addResponse.Code != http.StatusOK {
		t.Fatalf("添加 Key 失败: %d %s", addResponse.Code, addResponse.Body.String())
	}
	var added struct {
		Items []llmKeyView `json:"items"`
	}
	if err := json.Unmarshal(addResponse.Body.Bytes(), &added); err != nil {
		t.Fatalf("解析添加响应失败: %v", err)
	}
	if len(added.Items) != 3 {
		t.Fatalf("添加后应有 3 个 Key，实际 %d", len(added.Items))
	}
	for range added.Items {
		if strings.Contains(addResponse.Body.String(), "key-a") ||
			strings.Contains(addResponse.Body.String(), "key-b") ||
			strings.Contains(addResponse.Body.String(), "key-c") {
			t.Fatalf("响应泄露明文 Key: %s", addResponse.Body.String())
		}
	}

	removeID := llmKeyID("key-a")
	removeResponse := performKeyRequest(t, http.MethodDelete, "/settings/llm/keys/"+removeID, nil,
		func(router *gin.Engine) {
			router.DELETE("/settings/llm/keys/:id", handler.DeleteLLMKey)
		})
	if removeResponse.Code != http.StatusNoContent {
		t.Fatalf("删除 Key 失败: %d %s", removeResponse.Code, removeResponse.Body.String())
	}
	if keys := effectiveLLMAPIKeys(handler.currentConfig()); strings.Join(keys, ",") != "key-b,key-c" {
		t.Fatalf("删除后 Key 列表错误: %v", keys)
	}
}

func TestDeleteLastLLMKeyRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("agent:\n  llm:\n    api_key: key-a\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}
	handler := &SettingsHandler{
		cfg:        config.Config{ConfigPath: path, LLMAPIKeys: []string{"key-a"}, LLMAPIKey: "key-a"},
		configPath: path,
	}
	response := performKeyRequest(t, http.MethodDelete, "/settings/llm/keys/"+llmKeyID("key-a"), nil,
		func(router *gin.Engine) {
			router.DELETE("/settings/llm/keys/:id", handler.DeleteLLMKey)
		})
	if response.Code != http.StatusConflict {
		t.Fatalf("最后一个 Key 应拒绝删除，实际 %d %s", response.Code, response.Body.String())
	}
}

func TestLLMKeyProbeCooldownIsPerUser(t *testing.T) {
	handler := &SettingsHandler{}
	if _, ok := handler.beginLLMKeyProbe("user-1"); !ok {
		t.Fatal("首次检测应允许")
	}
	handler.endLLMKeyProbe("user-1")

	if retryAfter, ok := handler.beginLLMKeyProbe("user-1"); ok || retryAfter <= 0 {
		t.Fatalf("冷却期内应拒绝并返回等待时间: retry=%v ok=%v", retryAfter, ok)
	}
	if _, ok := handler.beginLLMKeyProbe("user-2"); !ok {
		t.Fatal("其他用户不应受冷却影响")
	}

	handler.llmKeyProbeMu.Lock()
	handler.llmKeyProbeLast["user-1"] = time.Now().Add(-llmKeyProbeCooldown - time.Second)
	handler.llmKeyProbeMu.Unlock()
	if _, ok := handler.beginLLMKeyProbe("user-1"); !ok {
		t.Fatal("冷却结束后应允许再次检测")
	}
}

func performKeyRequest(
	t *testing.T,
	method string,
	path string,
	body []byte,
	register func(*gin.Engine),
) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	register(router)
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}
