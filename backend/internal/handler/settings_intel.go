package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/intel"

	"github.com/gin-gonic/gin"
)

const intelProbeTimeout = 20 * time.Second

type intelProbeStatus struct {
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	CheckedAt string `json:"checkedAt,omitempty"`
}

func (h *SettingsHandler) IntelSettings(c *gin.Context) {
	settings, err := h.loadIntelSettings(c.Request.Context())
	if err != nil {
		internalError(c, "load_intel_settings_failed", "读取信息设置失败")
		return
	}
	c.JSON(http.StatusOK, h.intelSettingsResponse(settings))
}

func (h *SettingsHandler) UpdateIntelSettings(c *gin.Context) {
	if h.db == nil {
		internalError(c, "database_unavailable", "数据库不可用")
		return
	}
	var request struct {
		Enabled      *bool   `json:"enabled"`
		FOFAEmail    *string `json:"fofaEmail"`
		FOFAKey      *string `json:"fofaKey"`
		HunterKey    *string `json:"hunterKey"`
		ClearFOFAKey bool    `json:"clearFofaKey"`
		ClearHunter  bool    `json:"clearHunterKey"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_intel_settings", "信息设置请求格式错误")
		return
	}
	current, err := h.loadIntelSettings(c.Request.Context())
	if err != nil {
		internalError(c, "load_intel_settings_failed", "读取信息设置失败")
		return
	}
	if request.Enabled != nil {
		current.Enabled = *request.Enabled
	}
	if request.FOFAEmail != nil {
		value := strings.ToLower(strings.TrimSpace(*request.FOFAEmail))
		if len([]rune(value)) > 254 || (value != "" && !validIntelEmail(value)) {
			badRequest(c, "invalid_intel_settings", "FOFA Email 格式不合法")
			return
		}
		current.FOFAEmail = value
	}
	if request.FOFAKey != nil {
		value := strings.TrimSpace(*request.FOFAKey)
		if len(value) > 4096 {
			badRequest(c, "invalid_intel_settings", "FOFA Key 不能超过 4096 个字符")
			return
		}
		if value != "" {
			current.FOFAKey = value
		}
	}
	if request.HunterKey != nil {
		value := strings.TrimSpace(*request.HunterKey)
		if len(value) > 4096 {
			badRequest(c, "invalid_intel_settings", "Hunter Key 不能超过 4096 个字符")
			return
		}
		if value != "" {
			current.HunterKey = value
		}
	}
	if request.ClearFOFAKey {
		current.FOFAKey = ""
	}
	if request.ClearHunter {
		current.HunterKey = ""
	}
	if current.FOFAKey != "" && current.FOFAEmail == "" {
		badRequest(c, "invalid_intel_settings", "配置 FOFA Key 时必须填写 FOFA Email")
		return
	}
	if err := h.db.SaveIntelSettings(c.Request.Context(), current); err != nil {
		internalError(c, "save_intel_settings_failed", "保存信息设置失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": true})
}

func (h *SettingsHandler) TestIntelSettings(c *gin.Context) {
	var request struct {
		Provider string `json:"provider"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_intel_test", "测试请求格式错误")
		return
	}
	provider := strings.ToLower(strings.TrimSpace(request.Provider))
	if provider != "fofa" && provider != "hunter" {
		badRequest(c, "invalid_intel_test", "provider 只能是 fofa 或 hunter")
		return
	}
	settings, err := h.loadIntelSettings(c.Request.Context())
	if err != nil {
		internalError(c, "load_intel_settings_failed", "读取信息设置失败")
		return
	}
	client, err := intel.NewHTTPClient(h.currentConfig().Proxy, intelProbeTimeout)
	if err != nil {
		internalError(c, "create_intel_client_failed", "创建情报测试客户端失败")
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), intelProbeTimeout)
	defer cancel()
	intelClient := intel.NewClient(client)
	status := intelProbeStatus{Status: "healthy", CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	switch provider {
	case "fofa":
		err = intelClient.TestFOFA(ctx, intel.Settings{
			FOFAEmail: settings.FOFAEmail,
			FOFAKey:   settings.FOFAKey,
		})
	case "hunter":
		err = intelClient.TestHunter(ctx, intel.Settings{
			HunterKey: settings.HunterKey,
		})
	}
	if err != nil {
		status.Status = "error"
		status.Message = truncateIntelStatus(err.Error())
	}
	h.setIntelStatus(provider, status)
	respondIntelProbe(c, provider, status)
}

func (h *SettingsHandler) loadIntelSettings(ctx context.Context) (database.IntelSettings, error) {
	if h == nil || h.db == nil {
		return database.IntelSettings{}, fmt.Errorf("数据库不可用")
	}
	return h.db.GetIntelSettings(ctx)
}

func (h *SettingsHandler) intelSettingsResponse(settings database.IntelSettings) gin.H {
	return gin.H{
		"enabled":          settings.Enabled,
		"fofaEmail":        settings.FOFAEmail,
		"fofaKeyMasked":    config.MaskSecret(settings.FOFAKey),
		"hunterKeyMasked":  config.MaskSecret(settings.HunterKey),
		"fofaConfigured":   settings.FOFAEmail != "" && settings.FOFAKey != "",
		"hunterConfigured": settings.HunterKey != "",
		"updatedAt":        settings.UpdatedAt,
		"statuses": gin.H{
			"fofa":   h.intelStatus("fofa"),
			"hunter": h.intelStatus("hunter"),
		},
	}
}

func (h *SettingsHandler) intelStatus(provider string) intelProbeStatus {
	h.intelStatusMu.Lock()
	defer h.intelStatusMu.Unlock()
	if h.intelStatuses == nil {
		return intelProbeStatus{Status: "unknown"}
	}
	status, ok := h.intelStatuses[provider]
	if !ok {
		return intelProbeStatus{Status: "unknown"}
	}
	return status
}

func (h *SettingsHandler) setIntelStatus(provider string, status intelProbeStatus) {
	h.intelStatusMu.Lock()
	defer h.intelStatusMu.Unlock()
	if h.intelStatuses == nil {
		h.intelStatuses = map[string]intelProbeStatus{}
	}
	h.intelStatuses[provider] = status
}

func validIntelEmail(value string) bool {
	at := strings.LastIndex(value, "@")
	return at > 0 && at < len(value)-1 &&
		strings.Contains(value[at+1:], ".") &&
		!strings.ContainsAny(value, " \t\r\n")
}

func truncateIntelStatus(value string) string {
	value = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value))
	runes := []rune(value)
	if len(runes) > 300 {
		value = string(runes[:300]) + "..."
	}
	return value
}

func respondIntelProbe(c *gin.Context, provider string, status intelProbeStatus) {
	response := gin.H{
		"success":   status.Status != "error",
		"provider":  provider,
		"status":    status.Status,
		"message":   status.Message,
		"checkedAt": status.CheckedAt,
	}
	if status.Status == "error" {
		response["code"] = "intel_test_failed"
		c.JSON(http.StatusBadGateway, response)
		return
	}
	c.JSON(http.StatusOK, response)
}
