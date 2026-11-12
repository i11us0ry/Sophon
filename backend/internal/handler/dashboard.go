package handler

import (
	"net/http"
	"strconv"
	"strings"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

type DashboardHandler struct {
	db *database.DB
}

func NewDashboardHandler(db *database.DB) *DashboardHandler {
	return &DashboardHandler{db: db}
}

func (h *DashboardHandler) Tokens(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	days, _ := strconv.Atoi(c.Query("days"))
	version := strings.ToLower(strings.TrimSpace(c.DefaultQuery("version", "new")))
	legacy := version == "old"
	stats, err := h.db.DashboardTokenStats(
		c.Request.Context(),
		user.ID,
		days,
		strings.TrimSpace(c.Query("model")),
		legacy,
	)
	if err != nil {
		internalError(c, "dashboard_tokens_failed", "读取 Token 统计失败")
		return
	}
	source := "token_usage"
	if legacy {
		source = "activity"
	}
	c.JSON(http.StatusOK, gin.H{
		"version": version,
		"source":  source,
		"stats":   stats,
	})
}

func (h *DashboardHandler) Summary(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	summary, err := h.db.DashboardSummary(c.Request.Context(), user.ID)
	if err != nil {
		internalError(c, "dashboard_summary_failed", "读取仪表盘数据失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"conversations":   summary.Conversations,
		"vulnerabilities": summary.Vulnerabilities,
		"toolCalls":       summary.ToolCalls,
		"assets": gin.H{
			"total":       summary.AssetTotal,
			"criticality": summary.AssetCriticality,
			"status":      summary.AssetStatus,
		},
		"tokens": gin.H{
			"prompt":     summary.PromptTokens,
			"cacheRead":  summary.CacheReadTokens,
			"completion": summary.CompletionTokens,
			"total":      summary.TotalTokens,
			"estimated":  summary.EstimatedTokens,
		},
		"vulnerabilityStatus":   summary.VulnerabilityStatus,
		"vulnerabilitySeverity": summary.VulnerabilitySeverity,
	})
}
