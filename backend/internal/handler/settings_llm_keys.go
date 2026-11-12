package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"sophon/internal/config"
	"sophon/internal/middleware"
	"sophon/internal/outbound"

	"github.com/gin-gonic/gin"
)

const (
	llmKeyProbeTimeout         = 20 * time.Second
	llmKeyProbeMaxConcurrent   = 4
	llmKeyProbeResponseMaxSize = 64 * 1024
	llmKeyProbeCooldown        = 30 * time.Second

	llmKeyStatusUnknown = "unknown"
	llmKeyStatusHealthy = "healthy"
	llmKeyStatusError   = "error"
)

var (
	errLLMKeyConfigReadOnly = errors.New("未找到可写的 config.yml")
	errLLMKeyEnvLocked      = errors.New("llm.apiKeys 由环境变量锁定")
)

type llmKeyStatus struct {
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	CheckedAt string `json:"checkedAt,omitempty"`
}

type llmKeyView struct {
	ID        string `json:"id"`
	Masked    string `json:"masked"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	CheckedAt string `json:"checkedAt,omitempty"`
}

type llmKeyTestResult struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	CheckedAt string `json:"checkedAt,omitempty"`
}

func (h *SettingsHandler) ListLLMKeys(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"items": h.llmKeyViews(h.currentConfig())})
}

func (h *SettingsHandler) AddLLMKeys(c *gin.Context) {
	var request struct {
		APIKeys string `json:"apiKeys"`
		Keys    string `json:"keys"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_llm_keys", "请求格式错误")
		return
	}
	rawKeys := request.APIKeys
	if strings.TrimSpace(rawKeys) == "" {
		rawKeys = request.Keys
	}
	added, changed, errText := parseSettingsLLMAPIKeys(rawKeys)
	if errText != "" {
		badRequest(c, "invalid_llm_keys", errText)
		return
	}
	if !changed {
		badRequest(c, "invalid_llm_keys", "至少输入一个 API Key")
		return
	}
	configMutationMu.Lock()
	defer configMutationMu.Unlock()
	current := effectiveLLMAPIKeys(h.currentConfig())
	keys, err := mergeLLMKeys(current, added)
	if err != nil {
		badRequest(c, "invalid_llm_keys", err.Error())
		return
	}
	if len(keys) == len(current) {
		badRequest(c, "invalid_llm_keys", "输入的 API Key 已存在")
		return
	}
	if err := h.saveLLMKeys(c.Request.Context(), keys); err != nil {
		h.respondLLMKeyMutationError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": h.llmKeyViews(h.currentConfig())})
}

func (h *SettingsHandler) DeleteLLMKey(c *gin.Context) {
	targetID := strings.TrimSpace(c.Param("id"))
	if targetID == "" {
		badRequest(c, "invalid_llm_key", "API Key id 不能为空")
		return
	}
	configMutationMu.Lock()
	defer configMutationMu.Unlock()
	current := effectiveLLMAPIKeys(h.currentConfig())
	found := false
	keys := make([]string, 0, len(current))
	for _, key := range current {
		if llmKeyID(key) == targetID {
			found = true
			continue
		}
		keys = append(keys, key)
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"code": "llm_key_not_found", "message": "API Key 不存在"})
		return
	}
	if len(keys) == 0 {
		c.JSON(http.StatusConflict, gin.H{"code": "last_llm_key", "message": "不能删除最后一个 API Key"})
		return
	}
	if err := h.saveLLMKeys(c.Request.Context(), keys); err != nil {
		h.respondLLMKeyMutationError(c, err)
		return
	}
	h.deleteLLMKeyStatus(targetID)
	c.Status(http.StatusNoContent)
}

func (h *SettingsHandler) TestLLMKeys(c *gin.Context) {
	cfg := h.currentConfig()
	keys := effectiveLLMAPIKeys(cfg)
	if len(keys) == 0 {
		badRequest(c, "missing_llm_api_key", "没有可检测的 API Key")
		return
	}
	user := middleware.UserFromContext(c)
	userID := "unknown"
	if user != nil && strings.TrimSpace(user.ID) != "" {
		userID = user.ID
	}
	retryAfter, acquired := h.beginLLMKeyProbe(userID)
	if !acquired {
		seconds := int(retryAfter / time.Second)
		if retryAfter%time.Second != 0 {
			seconds++
		}
		if seconds < 1 {
			seconds = 1
		}
		c.Header("Retry-After", fmt.Sprintf("%d", seconds))
		c.JSON(http.StatusTooManyRequests, gin.H{
			"code":              "llm_key_probe_cooldown",
			"message":           "API Key 检测过于频繁，请稍后再试",
			"retryAfterSeconds": seconds,
		})
		return
	}
	defer h.endLLMKeyProbe(userID)
	ctx, cancel := context.WithTimeout(c.Request.Context(), llmKeyProbeTimeout+5*time.Second)
	defer cancel()
	client, err := llmProbeHTTPClient(ctx, cfg)
	if err != nil {
		internalError(c, "llm_key_probe_client_failed", err.Error())
		return
	}

	results := make([]llmKeyTestResult, len(keys))
	sem := make(chan struct{}, llmKeyProbeMaxConcurrent)
	var wait sync.WaitGroup
	for index, key := range keys {
		index, key := index, key
		wait.Add(1)
		go func() {
			defer wait.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				status := llmKeyStatus{
					Status:    llmKeyStatusError,
					Message:   "检测超时",
					CheckedAt: time.Now().UTC().Format(time.RFC3339),
				}
				h.setLLMKeyStatus(llmKeyID(key), status)
				results[index] = llmKeyTestResult{
					ID:        llmKeyID(key),
					Status:    status.Status,
					Message:   status.Message,
					CheckedAt: status.CheckedAt,
				}
				return
			}
			status := probeLLMKey(ctx, client, cfg, key)
			h.setLLMKeyStatus(llmKeyID(key), status)
			results[index] = llmKeyTestResult{
				ID:        llmKeyID(key),
				Status:    status.Status,
				Message:   status.Message,
				CheckedAt: status.CheckedAt,
			}
		}()
	}
	wait.Wait()
	c.JSON(http.StatusOK, gin.H{"items": results})
}

func (h *SettingsHandler) llmKeyViews(cfg config.Config) []llmKeyView {
	keys := effectiveLLMAPIKeys(cfg)
	result := make([]llmKeyView, 0, len(keys))
	for _, key := range keys {
		id := llmKeyID(key)
		status := h.llmKeyStatus(id)
		view := llmKeyView{
			ID:        id,
			Masked:    maskLLMKey(key),
			Status:    status.Status,
			Message:   status.Message,
			CheckedAt: status.CheckedAt,
		}
		if view.Status == "" {
			view.Status = llmKeyStatusUnknown
		}
		result = append(result, view)
	}
	return result
}

func (h *SettingsHandler) saveLLMKeys(ctx context.Context, keys []string) error {
	if h.configPath == "" {
		return errLLMKeyConfigReadOnly
	}
	if config.EnvLocked("SOPHON_LLM_API_KEYS") || config.EnvLocked("SOPHON_LLM_API_KEY") {
		return errLLMKeyEnvLocked
	}
	keys = config.NormalizeLLMAPIKeys(keys)
	if len(keys) == 0 {
		return fmt.Errorf("至少保留一个 API Key")
	}
	next := h.currentConfig()
	next.LLMAPIKeys = append([]string(nil), keys...)
	next.LLMAPIKey = keys[0]
	if err := config.UpdateFileWithOptions(h.configPath, []config.FieldUpdate{
		{Path: []string{"agent", "llm", "api_keys"}, Value: keys},
		{Path: []string{"agent", "llm", "api_key"}, Value: ""},
	}, config.UpdateOptions{SkipBackup: true}); err != nil {
		return err
	}
	if h.agent != nil {
		if err := h.agent.Reload(next); err != nil {
			return fmt.Errorf("配置已保存，但热更新失败: %w", err)
		}
	}
	h.mu.Lock()
	h.cfg = next
	h.mu.Unlock()
	return nil
}

func (h *SettingsHandler) respondLLMKeyMutationError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, errLLMKeyConfigReadOnly):
		badRequest(c, "config_not_writable", err.Error())
	case errors.Is(err, errLLMKeyEnvLocked):
		badRequest(c, "settings_env_locked", err.Error())
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    "save_llm_keys_failed",
			"message": err.Error(),
		})
	}
}

func (h *SettingsHandler) llmKeyStatus(id string) llmKeyStatus {
	h.llmKeyStatusMu.Lock()
	defer h.llmKeyStatusMu.Unlock()
	status, ok := h.llmKeyStatuses[id]
	if !ok {
		return llmKeyStatus{Status: llmKeyStatusUnknown}
	}
	return status
}

func (h *SettingsHandler) setLLMKeyStatus(id string, status llmKeyStatus) {
	h.llmKeyStatusMu.Lock()
	defer h.llmKeyStatusMu.Unlock()
	if h.llmKeyStatuses == nil {
		h.llmKeyStatuses = map[string]llmKeyStatus{}
	}
	h.llmKeyStatuses[id] = status
}

func (h *SettingsHandler) deleteLLMKeyStatus(id string) {
	h.llmKeyStatusMu.Lock()
	defer h.llmKeyStatusMu.Unlock()
	delete(h.llmKeyStatuses, id)
}

func (h *SettingsHandler) beginLLMKeyProbe(userID string) (time.Duration, bool) {
	h.llmKeyProbeMu.Lock()
	defer h.llmKeyProbeMu.Unlock()
	if h.llmKeyProbeRunning == nil {
		h.llmKeyProbeRunning = map[string]bool{}
	}
	if h.llmKeyProbeLast == nil {
		h.llmKeyProbeLast = map[string]time.Time{}
	}
	if h.llmKeyProbeRunning[userID] {
		return time.Second, false
	}
	now := time.Now()
	if last := h.llmKeyProbeLast[userID]; !last.IsZero() {
		if remaining := llmKeyProbeCooldown - now.Sub(last); remaining > 0 {
			return remaining, false
		}
	}
	h.llmKeyProbeRunning[userID] = true
	h.llmKeyProbeLast[userID] = now
	return 0, true
}

func (h *SettingsHandler) endLLMKeyProbe(userID string) {
	h.llmKeyProbeMu.Lock()
	defer h.llmKeyProbeMu.Unlock()
	delete(h.llmKeyProbeRunning, userID)
}

func llmKeyID(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:12])
}

func mergeLLMKeys(existing, added []string) ([]string, error) {
	result := make([]string, 0, len(existing)+len(added))
	seen := map[string]bool{}
	for _, key := range append(append([]string(nil), existing...), added...) {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, key)
		if len(result) > 20 {
			return nil, fmt.Errorf("最多配置 20 个 API Key")
		}
	}
	return result, nil
}

func maskLLMKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return "****"
	}
	prefix := 3
	if len(key) > 12 {
		prefix = 5
	}
	return key[:prefix] + "****" + key[len(key)-4:]
}

func llmProbeHTTPClient(ctx context.Context, cfg config.Config) (*http.Client, error) {
	base, err := cfg.Proxy.HTTPClient(llmKeyProbeTimeout)
	if err != nil {
		return nil, fmt.Errorf("代理配置无效: %w", err)
	}
	client, err := outbound.NewHTTPClient(base, outbound.Policy{
		AllowPrivate: cfg.LLMAllowPrivateNetwork,
		ProxyHost:    cfg.Proxy.Host,
		ProxyPort:    cfg.Proxy.Port,
	})
	if err != nil {
		return nil, fmt.Errorf("出站策略配置无效: %w", err)
	}
	if _, err := outbound.ValidateURL(ctx, cfg.LLMBaseURL, outbound.Policy{
		AllowPrivate: cfg.LLMAllowPrivateNetwork,
		ProxyHost:    cfg.Proxy.Host,
		ProxyPort:    cfg.Proxy.Port,
	}); err != nil {
		return nil, fmt.Errorf("LLM API 地址不合法: %w", err)
	}
	return client, nil
}

func probeLLMKey(ctx context.Context, client *http.Client, cfg config.Config, key string) llmKeyStatus {
	checkedAt := time.Now().UTC().Format(time.RFC3339)
	request, err := newLLMKeyProbeRequest(ctx, cfg, key)
	if err != nil {
		return llmKeyStatus{Status: llmKeyStatusError, Message: "请求构造失败", CheckedAt: checkedAt}
	}
	response, err := client.Do(request)
	if err != nil {
		return llmKeyStatus{Status: llmKeyStatusError, Message: "连接失败", CheckedAt: checkedAt}
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, llmKeyProbeResponseMaxSize))
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return llmKeyStatus{Status: llmKeyStatusHealthy, Message: "正常", CheckedAt: checkedAt}
	}
	return llmKeyStatus{
		Status:    llmKeyStatusError,
		Message:   llmKeyProbeErrorLabel(response.StatusCode, string(body)),
		CheckedAt: checkedAt,
	}
}

func newLLMKeyProbeRequest(ctx context.Context, cfg config.Config, key string) (*http.Request, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.LLMBaseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("API 地址为空")
	}
	var endpoint string
	var payload []byte
	if strings.EqualFold(strings.TrimSpace(cfg.LLMProvider), "anthropic") {
		if strings.HasSuffix(baseURL, "/v1") {
			endpoint = baseURL + "/messages"
		} else {
			endpoint = baseURL + "/v1/messages"
		}
		payload, _ = json.Marshal(map[string]interface{}{
			"model":      cfg.LLMModel,
			"max_tokens": 1,
			"messages": []map[string]string{
				{"role": "user", "content": "ping"},
			},
		})
	} else {
		endpoint = baseURL + "/chat/completions"
		payload, _ = json.Marshal(map[string]interface{}{
			"model":      cfg.LLMModel,
			"max_tokens": 1,
			"stream":     false,
			"messages": []map[string]string{
				{"role": "user", "content": "ping"},
			},
		})
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if strings.EqualFold(strings.TrimSpace(cfg.LLMProvider), "anthropic") {
		request.Header.Set("x-api-key", key)
		request.Header.Set("anthropic-version", "2023-06-01")
	} else {
		request.Header.Set("Authorization", "Bearer "+key)
	}
	return request, nil
}

func llmKeyProbeErrorLabel(status int, body string) string {
	message := strings.ToLower(body)
	switch {
	case llmProbeQuotaError(message):
		return "额度不足"
	case llmProbeAuthError(message):
		return "认证失败"
	case status == http.StatusUnauthorized:
		return "认证失败"
	case status == http.StatusForbidden:
		return "权限或认证失败"
	case status == http.StatusPaymentRequired:
		return "额度不足"
	case status == http.StatusTooManyRequests:
		return "请求限流"
	default:
		if status <= 0 {
			return "请求失败"
		}
		return fmt.Sprintf("请求失败（HTTP %d）", status)
	}
}

func llmProbeAuthError(message string) bool {
	for _, marker := range []string{
		"invalid api key",
		"incorrect api key",
		"invalid_api_key",
		"authentication",
		"unauthorized",
		"api key",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func llmProbeQuotaError(message string) bool {
	for _, marker := range []string{
		"insufficient_quota",
		"insufficient quota",
		"quota_exceeded",
		"quota exceeded",
		"insufficient_balance",
		"insufficient balance",
		"credit balance",
		"余额不足",
		"额度不足",
		"配额不足",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}
