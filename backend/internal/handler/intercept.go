package handler

import (
	"net/http"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/intercept"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

type InterceptHandler struct {
	db *database.DB
}

func NewInterceptHandler(db *database.DB) *InterceptHandler {
	return &InterceptHandler{db: db}
}

func (h *InterceptHandler) List(c *gin.Context) {
	if middleware.UserFromContext(c) == nil {
		unauthorized(c)
		return
	}
	rules, err := h.db.ListInterceptRules(c.Request.Context())
	if err != nil {
		internalError(c, "list_intercept_rules_failed", "读取拦截规则失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": rules})
}

func (h *InterceptHandler) Create(c *gin.Context) {
	var rule database.InterceptRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		badRequest(c, "invalid_intercept_rule", "拦截规则请求格式错误")
		return
	}
	if err := intercept.ValidateRule(&rule); err != nil {
		badRequest(c, "invalid_intercept_rule", err.Error())
		return
	}
	now := time.Now().UTC()
	rule.ID = randomID()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	if err := h.db.CreateInterceptRule(c.Request.Context(), rule); err != nil {
		internalError(c, "create_intercept_rule_failed", "创建拦截规则失败")
		return
	}
	c.JSON(http.StatusCreated, rule)
}

func (h *InterceptHandler) Update(c *gin.Context) {
	var rule database.InterceptRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		badRequest(c, "invalid_intercept_rule", "拦截规则请求格式错误")
		return
	}
	rule.ID = strings.TrimSpace(c.Param("id"))
	if rule.ID == "" {
		badRequest(c, "invalid_intercept_rule", "规则 ID 不能为空")
		return
	}
	if err := intercept.ValidateRule(&rule); err != nil {
		badRequest(c, "invalid_intercept_rule", err.Error())
		return
	}
	rule.UpdatedAt = time.Now().UTC()
	if err := h.db.UpdateInterceptRule(c.Request.Context(), rule); err != nil {
		respondMutationError(c, err, "intercept_rule_not_found", "拦截规则不存在", "update_intercept_rule_failed", "更新拦截规则失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *InterceptHandler) Delete(c *gin.Context) {
	if err := h.db.DeleteInterceptRule(c.Request.Context(), strings.TrimSpace(c.Param("id"))); err != nil {
		respondMutationError(c, err, "intercept_rule_not_found", "拦截规则不存在", "delete_intercept_rule_failed", "删除拦截规则失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *InterceptHandler) Toggle(c *gin.Context) {
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.Enabled == nil {
		badRequest(c, "invalid_intercept_rule", "缺少 enabled 字段")
		return
	}
	if err := h.db.SetInterceptRuleEnabled(c.Request.Context(), strings.TrimSpace(c.Param("id")), *request.Enabled); err != nil {
		respondMutationError(c, err, "intercept_rule_not_found", "拦截规则不存在", "toggle_intercept_rule_failed", "更新拦截规则状态失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *InterceptHandler) Test(c *gin.Context) {
	var request struct {
		Rule      database.InterceptRule `json:"rule"`
		ToolName  string                 `json:"toolName"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_intercept_rule", "测试请求格式错误")
		return
	}
	matched, err := intercept.TestRule(request.Rule, request.ToolName, request.Arguments)
	if err != nil {
		badRequest(c, "invalid_intercept_rule", err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"matched": matched})
}
