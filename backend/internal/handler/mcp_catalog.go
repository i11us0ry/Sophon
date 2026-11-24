package handler

import (
	"net/http"
	"strings"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

func (h *MCPHandler) CatalogStatus(c *gin.Context) {
	if h.catalog == nil {
		internalError(c, "tool_catalog_unavailable", "Tool Catalog 未配置")
		return
	}
	name := strings.TrimSpace(c.Query("name"))
	if name != "" {
		status, err := h.catalog.Status(c.Request.Context(), name)
		if err != nil {
			badRequest(c, "tool_catalog_status_failed", err.Error())
			return
		}
		c.JSON(http.StatusOK, status)
		return
	}
	items, err := h.catalog.List(c.Request.Context())
	if err != nil {
		internalError(c, "tool_catalog_list_failed", "读取 Tool Catalog 失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *MCPHandler) CatalogInstall(c *gin.Context) {
	if h.catalog == nil {
		internalError(c, "tool_catalog_unavailable", "Tool Catalog 未配置")
		return
	}
	var request struct {
		Name  string `json:"name"`
		Force bool   `json:"force"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_tool_catalog_install", "安装请求格式错误")
		return
	}
	status, err := h.catalog.Install(c.Request.Context(), request.Name, request.Force)
	if err != nil {
		badRequest(c, "tool_catalog_install_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, status)
}

func (h *MCPHandler) CatalogVerify(c *gin.Context) {
	if h.catalog == nil {
		internalError(c, "tool_catalog_unavailable", "Tool Catalog 未配置")
		return
	}
	var request struct {
		Name string `json:"name"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_tool_catalog_verify", "验证请求格式错误")
		return
	}
	status, err := h.catalog.Verify(c.Request.Context(), request.Name)
	if err != nil {
		badRequest(c, "tool_catalog_verify_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, status)
}

func (h *MCPHandler) ToolRegistry(c *gin.Context) {
	if h.db == nil {
		internalError(c, "tool_registry_unavailable", "工具注册表不可用")
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	tools, err := h.db.ListAllRegisteredTools(c.Request.Context(), user.ID)
	if err != nil {
		internalError(c, "tool_registry_list_failed", "读取工具注册表失败")
		return
	}
	for index := range tools {
		redacted := make(map[string]string, len(tools[index].Env))
		for key := range tools[index].Env {
			redacted[key] = "***"
		}
		tools[index].Env = redacted
	}
	projectID := strings.TrimSpace(c.Query("projectId"))
	conversationID := strings.TrimSpace(c.Query("conversationId"))
	var paths []database.ToolRuntimePath
	if projectID == "" && conversationID == "" {
		paths, err = h.db.ListAllToolRuntimePaths(c.Request.Context(), user.ID)
	} else {
		paths, err = h.db.ListToolRuntimePaths(
			c.Request.Context(),
			user.ID,
			projectID,
			conversationID,
		)
	}
	if err != nil {
		internalError(c, "tool_paths_list_failed", "读取工具 PATH 失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"tools": tools, "paths": paths})
}

func (h *MCPHandler) DeleteToolRegistry(c *gin.Context) {
	if h.db == nil {
		internalError(c, "tool_registry_unavailable", "工具注册表不可用")
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		badRequest(c, "invalid_tool_registry_id", "工具注册 id 不能为空")
		return
	}
	var deleted bool
	var err error
	if strings.EqualFold(strings.TrimSpace(c.Query("kind")), "path") {
		deleted, err = h.db.DeleteToolRuntimePath(c.Request.Context(), id, user.ID)
	} else {
		deleted, err = h.db.DeleteRegisteredTool(c.Request.Context(), id, user.ID)
	}
	if err != nil {
		internalError(c, "tool_registry_delete_failed", "删除工具注册失败")
		return
	}
	if !deleted {
		c.JSON(http.StatusNotFound, gin.H{"error": "工具注册不存在或无权删除"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}
