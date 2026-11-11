package handler

import (
	"net/http"
	"strconv"
	"strings"

	"sophon/internal/middleware"
	"sophon/internal/observability"

	"github.com/gin-gonic/gin"
)

// ObservabilityHandler 暴露进程内事件与聚合指标，供审计页面或外部采集系统读取。
type ObservabilityHandler struct {
	emitter *observability.Emitter
}

func NewObservabilityHandler(emitter *observability.Emitter) *ObservabilityHandler {
	return &ObservabilityHandler{emitter: emitter}
}

func (h *ObservabilityHandler) Metrics(c *gin.Context) {
	if middleware.UserFromContext(c) == nil {
		unauthorized(c)
		return
	}
	metrics := observability.Metrics{
		ByType: map[string]int64{},
		Tools:  map[string]int64{},
	}
	if h != nil && h.emitter != nil {
		metrics = h.emitter.Metrics()
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled":        metrics.Enabled,
		"eventsTotal":    metrics.EventsTotal,
		"failuresTotal":  metrics.FailuresTotal,
		"deniedTotal":    metrics.DeniedTotal,
		"approvalsTotal": metrics.ApprovalsTotal,
		"byType":         metrics.ByType,
		"tools":          metrics.Tools,
		"bufferSize":     metrics.BufferSize,
		"fileBytes":      metrics.FileBytes,
		"eventTypes":     observability.EventTypes(),
	})
}

// Events 返回最近事件（内存环形缓冲，默认 500 条）。
func (h *ObservabilityHandler) Events(c *gin.Context) {
	if middleware.UserFromContext(c) == nil {
		unauthorized(c)
		return
	}
	limit := 100
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if limit > 500 {
		limit = 500
	}
	var events []observability.Event
	if h != nil && h.emitter != nil {
		events = h.emitter.Recent(limit)
	}
	c.JSON(http.StatusOK, gin.H{
		"items": events,
		"count": len(events),
	})
}
