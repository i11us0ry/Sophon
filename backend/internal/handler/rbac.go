package handler

import (
	"net/http"
	"strings"

	"sophon/internal/database"
	"sophon/internal/middleware"
	rbacpkg "sophon/internal/rbac"

	"github.com/gin-gonic/gin"
)

type RBACHandler struct {
	service *rbacpkg.Service
}

func NewRBACHandler(service *rbacpkg.Service) *RBACHandler {
	return &RBACHandler{service: service}
}

func (h *RBACHandler) Me(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	role, _ := h.service.ListRoles(c.Request.Context())
	var permissions []string
	for _, item := range role {
		if item.Name == user.Role {
			permissions = item.Permissions
			break
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"user":        rbacUserResponse(user),
		"permissions": permissions,
	})
}

func (h *RBACHandler) Metadata(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"permissions": rbacpkg.PermissionCatalog(),
	})
}

func (h *RBACHandler) ListRoles(c *gin.Context) {
	roles, err := h.service.ListRoles(c.Request.Context())
	if err != nil {
		internalError(c, "list_roles_failed", "读取角色失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": roles})
}

func (h *RBACHandler) CreateRole(c *gin.Context) {
	var input rbacpkg.RoleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		badRequest(c, "invalid_role", "角色请求格式错误")
		return
	}
	if err := h.service.CreateRole(c.Request.Context(), input); err != nil {
		badRequest(c, "create_role_failed", err.Error())
		return
	}
	c.Status(http.StatusCreated)
}

func (h *RBACHandler) UpdateRole(c *gin.Context) {
	var input rbacpkg.RoleInput
	if err := c.ShouldBindJSON(&input); err != nil {
		badRequest(c, "invalid_role", "角色请求格式错误")
		return
	}
	if err := h.service.UpdateRole(c.Request.Context(), c.Param("name"), input); err != nil {
		badRequest(c, "update_role_failed", err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *RBACHandler) DeleteRole(c *gin.Context) {
	if err := h.service.DeleteRole(c.Request.Context(), c.Param("name")); err != nil {
		badRequest(c, "delete_role_failed", err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *RBACHandler) ListUsers(c *gin.Context) {
	users, err := h.service.ListUsers(c.Request.Context())
	if err != nil {
		internalError(c, "list_users_failed", "读取用户失败")
		return
	}
	result := make([]gin.H, 0, len(users))
	for index := range users {
		result = append(result, rbacUserResponse(&users[index]))
	}
	c.JSON(http.StatusOK, gin.H{"items": result})
}

func (h *RBACHandler) CreateUser(c *gin.Context) {
	var input rbacpkg.UserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		badRequest(c, "invalid_user", "用户请求格式错误")
		return
	}
	if !input.Enabled {
		input.Enabled = true
	}
	user, err := h.service.CreateUser(c.Request.Context(), input)
	if err != nil {
		badRequest(c, "create_user_failed", err.Error())
		return
	}
	c.JSON(http.StatusCreated, rbacUserResponse(user))
}

func (h *RBACHandler) UpdateUser(c *gin.Context) {
	actor := middleware.UserFromContext(c)
	if actor == nil {
		unauthorized(c)
		return
	}
	var input rbacpkg.UserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		badRequest(c, "invalid_user", "用户请求格式错误")
		return
	}
	if err := h.service.UpdateUser(c.Request.Context(), actor.ID, c.Param("id"), input); err != nil {
		badRequest(c, "update_user_failed", err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *RBACHandler) DeleteUser(c *gin.Context) {
	actor := middleware.UserFromContext(c)
	if actor == nil {
		unauthorized(c)
		return
	}
	if err := h.service.DeleteUser(c.Request.Context(), actor.ID, c.Param("id")); err != nil {
		badRequest(c, "delete_user_failed", err.Error())
		return
	}
	c.Status(http.StatusNoContent)
}

func rbacUserResponse(user *database.User) gin.H {
	return gin.H{
		"id":          user.ID,
		"username":    user.Username,
		"displayName": user.DisplayName,
		"role":        user.Role,
		"enabled":     user.Enabled,
		"createdAt":   user.CreatedAt,
	}
}

func normalizedRoleName(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
