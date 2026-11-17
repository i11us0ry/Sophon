package handler

import (
	"net/http"
	"sort"
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
	stats := map[string]int{"total": len(users)}
	for index := range users {
		if users[index].Enabled {
			stats["enabled"]++
		}
	}
	if strings.TrimSpace(c.Query("offset")) == "" {
		result := make([]gin.H, 0, len(users))
		for index := range users {
			result = append(result, rbacUserResponse(&users[index]))
		}
		c.JSON(http.StatusOK, gin.H{"items": result, "stats": stats})
		return
	}
	search := strings.ToLower(strings.TrimSpace(c.Query("search")))
	status := strings.ToLower(strings.TrimSpace(c.Query("status")))
	filtered := make([]database.User, 0, len(users))
	for _, user := range users {
		if status == "enabled" && !user.Enabled {
			continue
		}
		if status == "disabled" && user.Enabled {
			continue
		}
		if search != "" {
			haystack := strings.ToLower(strings.Join([]string{
				user.Username,
				user.DisplayName,
				user.Role,
			}, " "))
			if !strings.Contains(haystack, search) {
				continue
			}
		}
		filtered = append(filtered, user)
	}
	sortUsers(filtered, c.Query("sort"))
	total := len(filtered)
	limit := clampQueryInt(c.Query("limit"), 20, 1, 100)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 1000000)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	result := make([]gin.H, 0, end-offset)
	for index := offset; index < end; index++ {
		result = append(result, rbacUserResponse(&filtered[index]))
	}
	totalPages := (total + limit - 1) / limit
	if totalPages == 0 {
		totalPages = 1
	}
	c.JSON(http.StatusOK, gin.H{
		"items":      result,
		"stats":      stats,
		"total":      total,
		"page":       offset/limit + 1,
		"pageSize":   limit,
		"totalPages": totalPages,
	})
}

func sortUsers(users []database.User, sortValue string) {
	switch strings.ToLower(strings.TrimSpace(sortValue)) {
	case "username_desc":
		sort.SliceStable(users, func(i, j int) bool {
			return strings.ToLower(users[i].Username) > strings.ToLower(users[j].Username)
		})
	case "created_desc":
		sort.SliceStable(users, func(i, j int) bool {
			return users[i].CreatedAt.After(users[j].CreatedAt)
		})
	case "created_asc":
		sort.SliceStable(users, func(i, j int) bool {
			return users[i].CreatedAt.Before(users[j].CreatedAt)
		})
	case "role_asc":
		sort.SliceStable(users, func(i, j int) bool {
			if users[i].Role == users[j].Role {
				return strings.ToLower(users[i].Username) < strings.ToLower(users[j].Username)
			}
			return users[i].Role < users[j].Role
		})
	default:
		sort.SliceStable(users, func(i, j int) bool {
			return strings.ToLower(users[i].Username) < strings.ToLower(users[j].Username)
		})
	}
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
