package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

// ContextHandler 暴露上下文压缩与记忆写入的只读指标。
type ContextHandler struct {
	db *database.DB
}

func NewContextHandler(db *database.DB) *ContextHandler {
	return &ContextHandler{db: db}
}

func (h *ContextHandler) Metrics(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	all := wantsGlobalContextScope(c, user)
	metrics, err := h.db.ContextMetrics(c.Request.Context(), user.ID, all)
	if err != nil {
		internalError(c, "context_metrics_failed", "读取上下文指标失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"compactions": gin.H{
			"total":        metrics.Compactions,
			"minor":        metrics.CompactionsMinor,
			"major":        metrics.CompactionsMajor,
			"avgRatio":     metrics.AvgRatio,
			"avgLatencyMs": metrics.AvgLatencyMs,
			"lastAt":       lastAtOrNil(metrics.LastAt),
		},
		"memoryWrites": gin.H{
			"ADD":       metrics.MemoryAdd,
			"UPDATE":    metrics.MemoryUpdate,
			"NONE":      metrics.MemoryNone,
			"SUPERSEDE": metrics.MemorySupersede,
			"total":     metrics.MemoryTotal,
		},
		"injections": gin.H{
			"total": metrics.Injections,
		},
	})
}

// lastAtOrNil 把零值时间序列化为 null，避免返回 0001-01-01。
func lastAtOrNil(value time.Time) interface{} {
	if value.IsZero() {
		return nil
	}
	return value
}

func (h *ContextHandler) Compactions(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(c.Query("limit")))
	conversationID := strings.TrimSpace(c.Query("conversationId"))
	all := wantsGlobalContextScope(c, user)
	// 会话维度查询校验归属；管理员全局范围内不额外限制。
	if conversationID != "" && !all {
		if _, err := h.db.GetConversation(c.Request.Context(), conversationID, user.ID); err != nil {
			badRequest(c, "conversation_not_found", "会话不存在或无权访问")
			return
		}
	}
	items, err := h.db.ListContextCompactionsForUser(
		c.Request.Context(),
		user.ID,
		conversationID,
		limit,
		all,
	)
	if err != nil {
		internalError(c, "context_compactions_failed", "读取压缩记录失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// wantsGlobalContextScope 只有管理员显式请求 scope=all 时才返回全局数据。
func wantsGlobalContextScope(c *gin.Context, user *database.User) bool {
	if user == nil || user.Role != "admin" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(c.Query("scope")), "all")
}
