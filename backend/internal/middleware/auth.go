package middleware

import (
	"net/http"
	"strings"

	"sophon/internal/auth"
	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

const (
	contextUserKey    = "sophon.user"
	contextSessionKey = "sophon.session"
	contextTokenKey   = "sophon.raw_token"
)

func RequireAuth(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawToken, err := c.Cookie(auth.SessionCookieName)
		if err != nil || strings.TrimSpace(rawToken) == "" {
			abortUnauthorized(c)
			return
		}

		session, err := authService.Authenticate(c.Request.Context(), rawToken)
		if err != nil {
			abortUnauthorized(c)
			return
		}

		c.Set(contextUserKey, session.User)
		c.Set(contextSessionKey, session)
		c.Set(contextTokenKey, rawToken)
		c.Next()
	}
}

func RequireCSRF(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}

		session := AuthSessionFromContext(c)
		headerToken := c.GetHeader(auth.CSRFHeaderName)
		if session == nil || !authService.ValidateCSRF(session, headerToken) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    "csrf_failed",
				"message": "CSRF 校验失败",
			})
			return
		}
		c.Next()
	}
}

func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		allowed[strings.TrimSpace(strings.ToLower(role))] = struct{}{}
	}

	return func(c *gin.Context) {
		user := UserFromContext(c)
		if user == nil {
			abortUnauthorized(c)
			return
		}
		if _, ok := allowed[strings.ToLower(user.Role)]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"code":    "permission_denied",
				"message": "权限不足",
			})
			return
		}
		c.Next()
	}
}

func UserFromContext(c *gin.Context) *database.User {
	value, ok := c.Get(contextUserKey)
	if !ok {
		return nil
	}
	user, _ := value.(*database.User)
	return user
}

func AuthSessionFromContext(c *gin.Context) *auth.AuthenticatedSession {
	value, ok := c.Get(contextSessionKey)
	if !ok {
		return nil
	}
	session, _ := value.(*auth.AuthenticatedSession)
	return session
}

func RawTokenFromContext(c *gin.Context) string {
	value, ok := c.Get(contextTokenKey)
	if !ok {
		return ""
	}
	token, _ := value.(string)
	return token
}

func abortUnauthorized(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"code":    "unauthorized",
		"message": "未登录或会话已失效",
	})
}

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
