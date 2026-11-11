package handler

import (
	"net/http"
	"strings"

	"sophon/internal/config"
	storagepkg "sophon/internal/storage"

	"github.com/gin-gonic/gin"
)

type StorageHandler struct {
	service    *storagepkg.Service
	configPath string
}

func NewStorageHandler(service *storagepkg.Service, configPath string) *StorageHandler {
	return &StorageHandler{service: service, configPath: strings.TrimSpace(configPath)}
}

func (h *StorageHandler) Status(c *gin.Context) {
	items, err := h.service.Preview(c.Request.Context())
	if err != nil {
		internalError(c, "storage_preview_failed", "读取存储清理预览失败")
		return
	}
	cfg := h.service.Config()
	envLocked := make([]string, 0, 2)
	for _, item := range []struct {
		field  string
		envKey string
	}{
		{field: "autoClean", envKey: "SOPHON_STORAGE_AUTO_CLEAN"},
		{field: "intervalMinutes", envKey: "SOPHON_STORAGE_INTERVAL_MINUTES"},
		{field: "artifactRoot", envKey: "SOPHON_STORAGE_ARTIFACT_ROOT"},
	} {
		if config.EnvLocked(item.envKey) {
			envLocked = append(envLocked, item.field)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"configPath":       h.configPath,
		"editable":         h.configPath != "",
		"autoClean":        cfg.AutoClean,
		"intervalMinutes":  cfg.IntervalMinutes,
		"artifactRoot":     h.service.ArtifactRoot(),
		"activeGraceHours": h.service.ActiveGraceHours(),
		"categories":       items,
		"envLocked":        envLocked,
		"note":             "自动清理的开关与间隔修改后需重启生效；手动清理立即执行。",
	})
}

func (h *StorageHandler) Update(c *gin.Context) {
	configMutationMu.Lock()
	defer configMutationMu.Unlock()
	if h.configPath == "" {
		badRequest(c, "config_not_writable", "未找到 config.yml，无法保存在线修改")
		return
	}
	var request struct {
		AutoClean       *bool   `json:"autoClean"`
		IntervalMinutes *int    `json:"intervalMinutes"`
		ArtifactRoot    *string `json:"artifactRoot"`
		Categories      []struct {
			Name          string  `json:"name"`
			Enabled       *bool   `json:"enabled"`
			RetentionDays *int    `json:"retentionDays"`
			Path          *string `json:"path"`
		} `json:"categories"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_storage_settings", "存储设置请求格式错误")
		return
	}

	next := h.service.Config()
	updates := make([]config.FieldUpdate, 0, 8)
	if request.ArtifactRoot != nil {
		badRequest(c, "invalid_storage_path", "artifact_root 只允许通过 config.yml 修改")
		return
	}
	if request.AutoClean != nil {
		if config.EnvLocked("SOPHON_STORAGE_AUTO_CLEAN") {
			// 被环境变量锁定且值未变化的字段直接跳过，避免阻断其他设置保存。
			if *request.AutoClean != next.AutoClean {
				badRequest(c, "settings_env_locked", "自动清理开关由环境变量锁定")
				return
			}
		} else {
			next.AutoClean = *request.AutoClean
			updates = append(updates, config.FieldUpdate{Path: []string{"storage", "auto_clean"}, Value: *request.AutoClean})
		}
	}
	if request.IntervalMinutes != nil {
		if config.EnvLocked("SOPHON_STORAGE_INTERVAL_MINUTES") {
			if *request.IntervalMinutes != next.IntervalMinutes {
				badRequest(c, "settings_env_locked", "自动清理间隔由环境变量锁定")
				return
			}
		} else {
			value := *request.IntervalMinutes
			if value < 5 || value > 10080 {
				badRequest(c, "invalid_storage_settings", "自动清理间隔需在 5-10080 分钟之间")
				return
			}
			next.IntervalMinutes = value
			updates = append(updates, config.FieldUpdate{Path: []string{"storage", "interval_minutes"}, Value: value})
		}
	}
	for _, item := range request.Categories {
		name := strings.TrimSpace(item.Name)
		_, ok := storagepkg.CategoryByName(name)
		if !ok {
			badRequest(c, "invalid_storage_settings", "未知的清理类别: "+name)
			return
		}
		category := next.Categories[name]
		if item.Enabled != nil {
			category.Enabled = *item.Enabled
			updates = append(updates, config.FieldUpdate{
				Path:  []string{"storage", "categories", name, "enabled"},
				Value: *item.Enabled,
			})
		}
		if item.RetentionDays != nil {
			value := *item.RetentionDays
			if value < 0 || value > 3650 {
				badRequest(c, "invalid_storage_settings", "保留天数需在 0-3650 之间")
				return
			}
			category.RetentionDays = value
			updates = append(updates, config.FieldUpdate{
				Path:  []string{"storage", "categories", name, "retention_days"},
				Value: value,
			})
		}
		if item.Path != nil {
			badRequest(c, "invalid_storage_path", "存储类别路径只允许通过 config.yml 修改")
			return
		}
		next.Categories[name] = category
	}

	if len(updates) == 0 {
		badRequest(c, "invalid_storage_settings", "没有需要保存的修改")
		return
	}
	if err := config.UpdateFile(h.configPath, updates); err != nil {
		internalError(c, "save_storage_settings_failed", err.Error())
		return
	}
	if err := h.service.UpdateConfig(next); err != nil {
		internalError(c, "save_storage_settings_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": true, "requiresRestart": []string{"autoClean", "intervalMinutes"}})
}

func (h *StorageHandler) Cleanup(c *gin.Context) {
	var request struct {
		Categories []string `json:"categories"`
	}
	if err := c.ShouldBindJSON(&request); err != nil && err.Error() != "EOF" {
		badRequest(c, "invalid_cleanup_request", "清理请求格式错误")
		return
	}
	// 手动清理忽略保留期，自动清理才按保留期执行。
	result, err := h.service.Clean(c.Request.Context(), request.Categories, true)
	if err != nil {
		internalError(c, "cleanup_failed", "存储清理失败")
		return
	}
	total := 0
	var totalBytes int64
	for _, count := range result.Deleted {
		total += count
	}
	for _, bytes := range result.Bytes {
		totalBytes += bytes
	}
	c.JSON(http.StatusOK, gin.H{
		"deleted":    result.Deleted,
		"bytes":      result.Bytes,
		"total":      total,
		"totalBytes": totalBytes,
	})
}
