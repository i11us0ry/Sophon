package middleware

import (
	"net/http"
	"strings"

	"sophon/internal/rbac"

	"github.com/gin-gonic/gin"
)

// PermissionExempt marks routes that every authenticated account may call.
const PermissionExempt = "-"

func RequirePermission(service *rbac.Service, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := UserFromContext(c)
		if user == nil {
			abortUnauthorized(c)
			return
		}
		if !service.HasPermission(c.Request.Context(), user, permission) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":       "permission_denied",
				"message":    "权限不足",
				"permission": permission,
			})
			return
		}
		c.Next()
	}
}

func RequireRoutePermission(service *rbac.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		permission := RoutePermission(c.Request.Method, c.FullPath())
		if permission == PermissionExempt {
			c.Next()
			return
		}
		if permission == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    "permission_not_configured",
				"message": "接口未配置访问权限",
			})
			return
		}
		user := UserFromContext(c)
		if user == nil || !service.HasPermission(c.Request.Context(), user, permission) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":       "permission_denied",
				"message":    "权限不足",
				"permission": permission,
			})
			return
		}
		c.Next()
	}
}

func RoutePermission(method, path string) string {
	path = strings.TrimSpace(path)
	switch path {
	case "/api/auth/me", "/api/auth/profile", "/api/auth/logout", "/api/auth/password", "/api/rbac/me":
		return PermissionExempt
	}
	switch {
	case strings.HasPrefix(path, "/api/rbac"):
		return crudPermission(method, "rbac")
	case strings.HasPrefix(path, "/api/dashboard"):
		return crudPermission(method, "dashboard")
	case strings.HasPrefix(path, "/api/system"):
		return crudPermission(method, "dashboard")
	case strings.HasPrefix(path, "/api/context"):
		return crudPermission(method, "dashboard")
	case strings.HasPrefix(path, "/api/agent-roles"):
		if method == http.MethodGet || method == http.MethodHead {
			return "agentRole:read"
		}
		return "agentRole:admin"
	case strings.HasPrefix(path, "/api/mcp"):
		return crudPermission(method, "mcp")
	case strings.HasPrefix(path, "/api/admin"):
		return crudPermission(method, "rbac")
	case strings.HasPrefix(path, "/api/settings"):
		if method == http.MethodGet || method == http.MethodHead {
			return "settings:read"
		}
		return "settings:write"
	case strings.HasPrefix(path, "/api/intercept"):
		if method == http.MethodGet || method == http.MethodHead {
			return "settings:read"
		}
		return "settings:write"
	case strings.HasPrefix(path, "/api/workspace"):
		if method == http.MethodGet || method == http.MethodHead {
			return "settings:read"
		}
		return "settings:write"
	case strings.HasPrefix(path, "/api/projects/") &&
		strings.HasSuffix(path, "/vulnerabilities"):
		return crudPermission(method, "vulnerability")
	case strings.HasPrefix(path, "/api/projects/") &&
		strings.HasSuffix(path, "/assets"):
		return crudPermission(method, "asset")
	case strings.HasPrefix(path, "/api/projects/") &&
		strings.Contains(path, "/graph"):
		return crudPermission(method, "vulnerability")
	case strings.HasPrefix(path, "/api/projects"):
		if strings.HasPrefix(path, "/api/projects/batch-delete") {
			return "project:delete"
		}
		return crudPermission(method, "project")
	case strings.HasPrefix(path, "/api/assets"):
		return crudPermission(method, "asset")
	case strings.HasPrefix(path, "/api/vulnerabilities/batch-delete"):
		return "vulnerability:delete"
	case strings.HasPrefix(path, "/api/vulnerabilities"):
		return crudPermission(method, "vulnerability")
	case strings.HasPrefix(path, "/api/knowledge"):
		return crudPermission(method, "knowledge")
	case strings.HasPrefix(path, "/api/skills"):
		return crudPermission(method, "skills")
	case strings.HasPrefix(path, "/api/webshell"):
		return crudPermission(method, "webshell")
	case strings.HasPrefix(path, "/api/hitl"):
		return crudPermission(method, "hitl")
	case strings.HasPrefix(path, "/api/audit"):
		return crudPermission(method, "audit")
	case strings.HasPrefix(path, "/api/monitor"):
		return crudPermission(method, "monitor")
	case strings.HasPrefix(path, "/api/observability"):
		return crudPermission(method, "monitor")
	case strings.HasPrefix(path, "/api/conversations"), strings.HasPrefix(path, "/api/messages"), strings.HasPrefix(path, "/api/process-details"):
		if strings.HasPrefix(path, "/api/conversations/batch-delete") {
			return "chat:delete"
		}
		return crudPermission(method, "chat")
	case strings.HasPrefix(path, "/api/conversation-batches"):
		return crudPermission(method, "chat")
	case strings.HasPrefix(path, "/api/attachments"):
		return crudPermission(method, "chat")
	case strings.HasPrefix(path, "/api/chat"), strings.HasPrefix(path, "/api/eino-agent"), strings.HasPrefix(path, "/api/multi-agent"):
		return "agent:execute"
	case strings.HasPrefix(path, "/api/tasks"):
		return crudPermission(method, "tasks")
	default:
		return ""
	}
}

func crudPermission(method, module string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return module + ":read"
	case http.MethodDelete:
		return module + ":delete"
	default:
		return module + ":write"
	}
}
