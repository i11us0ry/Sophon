package handler

import (
	"net/http"
	"time"

	"sophon/internal/system"

	"github.com/gin-gonic/gin"
)

type HealthHandler struct {
	version   string
	started   time.Time
	collector *system.Collector
}

func NewHealthHandler(version string) *HealthHandler {
	return &HealthHandler{
		version:   version,
		started:   time.Now(),
		collector: system.NewCollector(),
	}
}

// System 返回主机名与主机/容器资源使用率。
func (h *HealthHandler) System(c *gin.Context) {
	if h.collector == nil {
		internalError(c, "system_stats_unavailable", "当前平台不支持系统指标采集")
		return
	}
	c.JSON(http.StatusOK, h.collector.Collect())
}

func (h *HealthHandler) Live(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "sophon-backend",
	})
}

func (h *HealthHandler) Ready(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ready",
	})
}

func (h *HealthHandler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":         "ok",
		"service":        "sophon-backend",
		"version":        h.version,
		"uptime_seconds": int(time.Since(h.started).Seconds()),
		"time":           time.Now().UTC(),
	})
}

func (h *HealthHandler) Version(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"service":    "sophon-backend",
		"version":    h.version,
		"apiVersion": "v1",
		"capabilities": []string{
			"health",
			"version",
			"chat",
			"conversations",
			"sse",
			"agent",
			"mcp",
			"tasks",
			"hitl",
			"audit",
			"monitor",
			"context-summary",
			"projects",
			"assets",
			"vulnerabilities",
			"vulnerability-retest",
			"knowledge",
			"skills",
			"webshell-registry",
			"project-context",
			"embedding",
			"semantic-search",
			"settings",
		},
	})
}
