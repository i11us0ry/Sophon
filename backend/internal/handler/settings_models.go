package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sophon/internal/config"
	"sophon/internal/outbound"

	"github.com/gin-gonic/gin"
)

const (
	modelsResponseLimit  = 1 << 20
	modelsRequestTimeout = 20 * time.Second
)

type listModelsRequest struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"baseUrl"`
	APIKey   string `json:"apiKey"`
}

type modelEntry struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// ListModels 代理上游模型列表接口：OpenAI 兼容 GET {base}/models；
// Anthropic 兼容 GET {base}/v1/models（x-api-key + anthropic-version）。
func (h *SettingsHandler) ListModels(c *gin.Context) {
	var request listModelsRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_models_request", "请求格式错误")
		return
	}

	provider := strings.ToLower(strings.TrimSpace(request.Provider))
	switch provider {
	case "", "openai", "openai_compatible":
		provider = "openai_compatible"
	case "anthropic", "claude":
		provider = "anthropic"
	default:
		badRequest(c, "invalid_llm_provider", "接口格式需为 openai_compatible 或 anthropic")
		return
	}

	baseURL := strings.TrimRight(strings.TrimSpace(request.BaseURL), "/")
	if baseURL == "" {
		badRequest(c, "invalid_llm_base_url", "API 地址不能为空")
		return
	}
	current := h.currentConfig()
	policy := outbound.Policy{
		AllowPrivate: current.LLMAllowPrivateNetwork,
		ProxyHost:    current.Proxy.Host,
		ProxyPort:    current.Proxy.Port,
	}
	if _, err := outbound.ValidateURL(c.Request.Context(), baseURL, policy); err != nil {
		badRequest(c, "invalid_llm_base_url", "API 地址不合法")
		return
	}

	apiKey := strings.TrimSpace(request.APIKey)
	explicitKey := apiKey != "" && !strings.Contains(apiKey, "****")
	if explicitKey {
		if keys := config.ParseLLMAPIKeys(apiKey); len(keys) > 0 {
			apiKey = keys[0]
		} else {
			explicitKey = false
			apiKey = ""
		}
	}
	if !explicitKey {
		if strings.TrimRight(baseURL, "/") != strings.TrimRight(current.LLMBaseURL, "/") {
			badRequest(c, "api_key_required_for_new_base_url", "切换 API 地址时必须填写对应的 API Key")
			return
		}
		if keys := effectiveLLMAPIKeys(current); len(keys) > 0 {
			apiKey = keys[0]
		}
	}
	if apiKey == "" {
		badRequest(c, "missing_llm_api_key", "API Key 不能为空")
		return
	}

	endpoint := baseURL + "/models"
	if provider == "anthropic" && !strings.HasSuffix(baseURL, "/v1") {
		endpoint = baseURL + "/v1/models"
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), modelsRequestTimeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		badRequest(c, "invalid_llm_base_url", "API 地址不合法")
		return
	}
	httpRequest.Header.Set("Accept", "application/json")
	if provider == "anthropic" {
		httpRequest.Header.Set("x-api-key", apiKey)
		httpRequest.Header.Set("anthropic-version", "2023-06-01")
	} else {
		httpRequest.Header.Set("Authorization", "Bearer "+apiKey)
	}

	baseClient, err := current.Proxy.HTTPClient(modelsRequestTimeout)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"supported": true,
			"models":    []modelEntry{},
			"error":     "代理配置无效: " + err.Error(),
		})
		return
	}
	client, err := outbound.NewHTTPClient(baseClient, policy)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"supported": true,
			"models":    []modelEntry{},
			"error":     "出站策略配置无效: " + err.Error(),
		})
		return
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"supported": true,
			"models":    []modelEntry{},
			"error":     "请求上游失败: " + err.Error(),
		})
		return
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, modelsResponseLimit))
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"supported": true,
			"models":    []modelEntry{},
			"error":     "读取上游响应失败: " + err.Error(),
		})
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		c.JSON(http.StatusOK, gin.H{
			"success":   false,
			"supported": true,
			"models":    []modelEntry{},
			"error": fmt.Sprintf(
				"上游返回 HTTP %d: %s",
				response.StatusCode,
				truncateForMessage(string(body)),
			),
		})
		return
	}

	models := parseModelList(body)
	c.JSON(http.StatusOK, gin.H{
		"success":   true,
		"supported": true,
		"models":    models,
		"count":     len(models),
	})
}

func parseModelList(body []byte) []modelEntry {
	var payload struct {
		Data []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
		} `json:"data"`
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return []modelEntry{}
	}

	seen := make(map[string]bool, len(payload.Data)+len(payload.Models))
	items := make([]modelEntry, 0, len(payload.Data)+len(payload.Models))
	for _, item := range payload.Data {
		id := strings.TrimSpace(item.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		name := strings.TrimSpace(item.DisplayName)
		if name == "" {
			name = strings.TrimSpace(item.Name)
		}
		items = append(items, modelEntry{ID: id, Name: name})
	}
	for _, item := range payload.Models {
		id := strings.TrimSpace(item.ID)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		items = append(items, modelEntry{ID: id})
	}
	return items
}

func truncateForMessage(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 300 {
		return value[:300] + "..."
	}
	return value
}
