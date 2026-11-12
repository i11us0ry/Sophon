package handler

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"sophon/internal/config"
)

func TestSettingsUpdateAcceptsHundredMillionTurnTokens(t *testing.T) {
	path := writeEnvLockTestConfig(t, "agent:\n  context_max_chars: 24000\n")
	handler := &SettingsHandler{
		cfg:        config.Config{ConfigPath: path, AgentContextMaxChars: 24000},
		configPath: path,
	}
	recorder := performSettingsUpdate(
		t,
		handler,
		`{"agent":{"maxTurnTokens":100000000}}`,
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("100,000,000 应允许保存，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	if !strings.Contains(string(raw), "max_turn_tokens: 100000000") {
		t.Fatalf("配置未保存新上限: %s", raw)
	}
}

func TestSettingsUpdateRejectsOverHundredMillionTurnTokens(t *testing.T) {
	path := writeEnvLockTestConfig(t, "agent:\n  context_max_chars: 24000\n")
	handler := &SettingsHandler{
		cfg:        config.Config{ConfigPath: path, AgentContextMaxChars: 24000},
		configPath: path,
	}
	recorder := performSettingsUpdate(
		t,
		handler,
		`{"agent":{"maxTurnTokens":100000001}}`,
	)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("超过 100,000,000 应拒绝，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	if code := responseCode(t, recorder); code != "invalid_settings" {
		t.Fatalf("错误码错误: %s", code)
	}
}

func TestSettingsUpdateAcceptsZeroAsUnlimitedForAgentLimits(t *testing.T) {
	path := writeEnvLockTestConfig(t, "agent:\n  context_max_chars: 24000\n")
	handler := &SettingsHandler{
		cfg:        config.Config{ConfigPath: path, AgentContextMaxChars: 24000},
		configPath: path,
	}
	recorder := performSettingsUpdate(
		t,
		handler,
		`{"agent":{"maxIterations":0,"maxTurnTokens":0,"maxHypotheses":0}}`,
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("三项设置填 0 应允许保存，实际 %d: %s", recorder.Code, recorder.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取配置失败: %v", err)
	}
	text := string(raw)
	for _, want := range []string{
		"max_iterations: 0",
		"max_turn_tokens: 0",
		"max_hypotheses: 0",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("配置缺少 %q: %s", want, text)
		}
	}
}
