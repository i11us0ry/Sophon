package handler

import (
	"net/http"
	"strconv"
	"strings"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

type GovernanceHandler struct {
	db *database.DB
}

func NewGovernanceHandler(db *database.DB) *GovernanceHandler {
	return &GovernanceHandler{db: db}
}

func (h *GovernanceHandler) ListAuditLogs(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	limit := 50
	if parsed, err := strconv.Atoi(strings.TrimSpace(c.Query("limit"))); err == nil && auditPageSizes[parsed] {
		limit = parsed
	}
	offset := 0
	if parsed, err := strconv.Atoi(strings.TrimSpace(c.Query("offset"))); err == nil && parsed > 0 {
		offset = parsed
	}
	allUsers := false
	if strings.EqualFold(strings.TrimSpace(c.Query("scope")), "all") {
		if !strings.EqualFold(strings.TrimSpace(user.Role), "admin") {
			c.JSON(http.StatusForbidden, gin.H{
				"code":    "permission_denied",
				"message": "仅管理员可查看全部审计日志",
			})
			return
		}
		allUsers = true
	}
	items, total, err := h.db.ListAuditLogsFiltered(c.Request.Context(), database.AuditLogFilter{
		UserID:   user.ID,
		AllUsers: allUsers,
		Result:   strings.TrimSpace(c.Query("result")),
		Search:   strings.TrimSpace(c.Query("search")),
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		internalError(c, "list_audit_failed", "读取审计日志失败")
		return
	}
	totalPages := (total + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      items,
		"total":      total,
		"page":       offset/limit + 1,
		"pageSize":   limit,
		"totalPages": totalPages,
	})
}

var auditPageSizes = map[int]bool{50: true, 100: true, 500: true, 1000: true}

func (h *GovernanceHandler) ListToolExecutions(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	items, err := h.db.ListToolExecutions(c.Request.Context(), user.ID, 200)
	if err != nil {
		internalError(c, "list_monitor_failed", "读取工具执行记录失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *GovernanceHandler) ListPendingHITL(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	items, err := h.db.ListPendingHITLRequests(c.Request.Context(), user.ID)
	if err != nil {
		internalError(c, "list_hitl_failed", "读取待审批请求失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *GovernanceHandler) DecideHITL(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		Approved *bool  `json:"approved"`
		Comment  string `json:"comment"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.Approved == nil {
		badRequest(c, "invalid_request", "审批请求格式错误")
		return
	}
	requestID := strings.TrimSpace(c.Param("id"))
	if requestID == "" || len(requestID) > 128 {
		badRequest(c, "invalid_request_id", "审批请求 ID 不合法")
		return
	}
	if err := h.db.DecideHITLRequest(
		c.Request.Context(),
		requestID,
		user.ID,
		*request.Approved,
		truncateRunes(request.Comment, 2000),
		user.Username,
	); err != nil {
		if database.NoRows(err) {
			c.JSON(http.StatusNotFound, gin.H{
				"code":    "hitl_request_not_found",
				"message": "审批请求不存在、已处理或无权操作",
			})
			return
		}
		internalError(c, "hitl_decision_failed", "提交审批结果失败")
		return
	}
	c.Status(http.StatusNoContent)
}
