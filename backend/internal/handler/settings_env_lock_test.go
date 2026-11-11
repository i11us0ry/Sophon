package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sophon/internal/config"
	"sophon/internal/storage"

	"github.com/gin-gonic/gin"
)

func writeEnvLockTestConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}
	return path
}

func performSettingsUpdate(t *testing.T, handler *SettingsHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/settings/ai", handler.Update)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/settings/ai", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	return recorder
}

func performStorageUpdate(t *testing.T, handler *StorageHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/settings/storage", handler.Update)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/settings/storage", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	return recorder
}

func responseCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析响应失败: %v, body=%s", err, recorder.Body.String())
	}
	return payload.Code
}

func TestSettingsUpdateAllowsPartialSaveWithEnvLockedField(t *testing.T) {
	t.Setenv("SOPHON_LLM_MODEL", "env-model")
	path := writeEnvLockTestConfig(t, "agent:\n  llm:\n    model: file-model\n    timeout_seconds: 120\n  context_max_chars: 24000\n")
	handler := &SettingsHandler{
		cfg: config.Config{
			ConfigPath:           path,
			LLMProvider:          "openai_compatible",
			LLMModel:             "env-model",
			LLMTimeoutSeconds:    120,
			AgentContextMaxChars: 24000,
		},
		configPath: path,
	}

	recorder := performSettingsUpdate(t, handler, `{"llm":{"model":"env-model"},"agent":{"contextMaxChars":30000}}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if !strings.Contains(string(raw), "context_max_chars: 30000") {
		t.Fatalf("未锁定的字段应保存成功: %s", raw)
	}
	if !strings.Contains(string(raw), "model: file-model") {
		t.Fatalf("环境变量锁定的字段不应写入配置文件: %s", raw)
	}
}

func TestSettingsUpdateRejectsChangedEnvLockedField(t *testing.T) {
	t.Setenv("SOPHON_LLM_MODEL", "env-model")
	path := writeEnvLockTestConfig(t, "agent:\n  llm:\n    model: file-model\n    timeout_seconds: 120\n  context_max_chars: 24000\n")
	handler := &SettingsHandler{
		cfg: config.Config{
			ConfigPath:           path,
			LLMProvider:          "openai_compatible",
			LLMModel:             "env-model",
			LLMTimeoutSeconds:    120,
			AgentContextMaxChars: 24000,
		},
		configPath: path,
	}

	recorder := performSettingsUpdate(t, handler, `{"llm":{"model":"other-model"},"agent":{"contextMaxChars":30000}}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	if code := responseCode(t, recorder); code != "settings_env_locked" {
		t.Fatalf("期望错误码 settings_env_locked，实际 %s", code)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if !strings.Contains(string(raw), "context_max_chars: 24000") || !strings.Contains(string(raw), "model: file-model") {
		t.Fatalf("被拒绝的请求不应写入任何字段: %s", raw)
	}
}

func TestSettingsUpdateSavesMaxHypotheses(t *testing.T) {
	path := writeEnvLockTestConfig(t, "agent:\n  max_iterations: 40\n")
	handler := &SettingsHandler{
		cfg: config.Config{
			ConfigPath:         path,
			AgentMaxIterations: 40,
			AgentMaxHypotheses: 200,
		},
		configPath: path,
	}
	recorder := performSettingsUpdate(t, handler, `{"agent":{"maxHypotheses":300}}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if !strings.Contains(string(raw), "max_hypotheses: 300") {
		t.Fatalf("活跃假设上限未写入配置: %s", raw)
	}
}

func newEnvLockStorageHandler(t *testing.T, configPath string, effectiveAutoClean bool) *StorageHandler {
	t.Helper()
	service := storage.NewService(nil, config.StorageConfig{
		AutoClean:        effectiveAutoClean,
		IntervalMinutes:  60,
		ArtifactRoot:     t.TempDir(),
		ActiveGraceHours: 24,
		Categories: map[string]config.StorageCategoryConfig{
			"audit_logs": {Enabled: true, RetentionDays: 30},
		},
	}, filepath.Join(t.TempDir(), "data"))
	return &StorageHandler{service: service, configPath: configPath}
}

func TestStorageUpdateAllowsPartialSaveWithEnvLockedField(t *testing.T) {
	t.Setenv("SOPHON_STORAGE_AUTO_CLEAN", "true")
	path := writeEnvLockTestConfig(t, "storage:\n  auto_clean: false\n  categories:\n    audit_logs:\n      enabled: true\n      retention_days: 30\n")
	handler := newEnvLockStorageHandler(t, path, true)

	recorder := performStorageUpdate(t, handler, `{"autoClean":true,"categories":[{"name":"audit_logs","retentionDays":45}]}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if !strings.Contains(string(raw), "retention_days: 45") {
		t.Fatalf("未锁定的类别设置应保存成功: %s", raw)
	}
	if !strings.Contains(string(raw), "auto_clean: false") {
		t.Fatalf("环境变量锁定的字段不应写入配置文件: %s", raw)
	}
}

func TestStorageUpdateRejectsChangedEnvLockedField(t *testing.T) {
	t.Setenv("SOPHON_STORAGE_AUTO_CLEAN", "true")
	path := writeEnvLockTestConfig(t, "storage:\n  auto_clean: false\n  categories:\n    audit_logs:\n      enabled: true\n      retention_days: 30\n")
	handler := newEnvLockStorageHandler(t, path, true)

	recorder := performStorageUpdate(t, handler, `{"autoClean":false,"categories":[{"name":"audit_logs","retentionDays":45}]}`)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	if code := responseCode(t, recorder); code != "settings_env_locked" {
		t.Fatalf("期望错误码 settings_env_locked，实际 %s", code)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if !strings.Contains(string(raw), "retention_days: 30") {
		t.Fatalf("被拒绝的请求不应写入任何字段: %s", raw)
	}
}
