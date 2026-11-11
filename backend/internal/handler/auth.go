package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"sophon/internal/auth"
	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	service         *auth.Service
	db              *database.DB
	limiter         *auth.LoginLimiter
	passwordLimiter *auth.LoginLimiter
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const maxLoginRequestBytes = 4 * 1024

type userResponse struct {
	ID              string `json:"id"`
	Username        string `json:"username"`
	DisplayName     string `json:"displayName"`
	Role            string `json:"role"`
	AssistantName   string `json:"assistantName"`
	AssistantAvatar string `json:"assistantAvatar"`
	UserAvatar      string `json:"userAvatar"`
}

func NewAuthHandler(service *auth.Service, db *database.DB) *AuthHandler {
	return &AuthHandler{
		service:         service,
		db:              db,
		limiter:         auth.NewLoginLimiter(),
		passwordLimiter: auth.NewLoginLimiter(),
	}
}

func (h *AuthHandler) Login(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxLoginRequestBytes)

	var request loginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    "invalid_request",
			"message": "请求格式错误",
		})
		return
	}

	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" || len(request.Username) > 64 || request.Password == "" || len(request.Password) > 256 {
		c.JSON(http.StatusBadRequest, gin.H{
			"code":    "invalid_credentials",
			"message": "用户名或密码错误",
		})
		return
	}

	clientIP := c.ClientIP()
	if remaining := h.limiter.Blocked(request.Username, clientIP); remaining > 0 {
		retryAfter := int(remaining.Seconds()) + 1
		c.Header("Retry-After", strconv.Itoa(retryAfter))
		if h.db != nil {
			_ = h.db.AddAuditLog(c.Request.Context(), database.AuditLog{
				Username:     strings.ToLower(strings.TrimSpace(request.Username)),
				Action:       "auth.login.blocked",
				ResourceType: "session",
				Result:       "failure",
				Detail:       fmt.Sprintf("ip=%s retry_after=%ds", clientIP, retryAfter),
			})
		}
		c.JSON(http.StatusTooManyRequests, gin.H{
			"code":              "too_many_attempts",
			"message":           "登录尝试过于频繁，请稍后再试",
			"retryAfterSeconds": retryAfter,
		})
		return
	}

	result, err := h.service.Login(c.Request.Context(), request.Username, request.Password)
	if err != nil {
		h.limiter.RecordFailure(request.Username, clientIP)
		if h.db != nil {
			_ = h.db.AddAuditLog(c.Request.Context(), database.AuditLog{
				Username:     request.Username,
				Action:       "auth.login",
				ResourceType: "session",
				Result:       "failure",
				Detail:       fmt.Sprintf("invalid credentials ip=%s", clientIP),
			})
		}
		if err == auth.ErrInvalidCredentials {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code":    "invalid_credentials",
				"message": "用户名或密码错误",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    "internal_error",
			"message": "登录失败",
		})
		return
	}

	h.limiter.Reset(request.Username, clientIP)
	if h.db != nil {
		_ = h.db.AddAuditLog(c.Request.Context(), database.AuditLog{
			UserID:       result.User.ID,
			Username:     result.User.Username,
			Action:       "auth.login",
			ResourceType: "session",
			ResourceID:   result.User.ID,
			Result:       "success",
			Detail:       fmt.Sprintf("ip=%s", clientIP),
		})
	}
	h.setCookies(c, result)
	c.JSON(http.StatusOK, gin.H{
		"user":      h.toUserResponse(c.Request.Context(), result.User),
		"csrfToken": result.CSRFToken,
		"expiresAt": result.ExpiresAt,
	})
}

func (h *AuthHandler) Me(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"code":    "unauthorized",
			"message": "未登录",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user": h.toUserResponse(c.Request.Context(), user),
	})
}

type updateProfileRequest struct {
	DisplayName     string `json:"displayName"`
	AssistantName   string `json:"assistantName"`
	AssistantAvatar string `json:"assistantAvatar"`
	UserAvatar      string `json:"userAvatar"`
}

func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request updateProfileRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_request", "资料格式错误")
		return
	}
	displayName := strings.TrimSpace(request.DisplayName)
	if displayName == "" {
		displayName = user.Username
	}
	assistantName := strings.TrimSpace(request.AssistantName)
	if assistantName == "" {
		assistantName = "Sophon"
	}
	if len([]rune(displayName)) > 40 || len([]rune(assistantName)) > 40 {
		badRequest(c, "profile_name_too_long", "称呼不能超过 40 个字符")
		return
	}
	assistantAvatar := strings.TrimSpace(request.AssistantAvatar)
	userAvatar := strings.TrimSpace(request.UserAvatar)
	if !validProfileAvatar(assistantAvatar) || !validProfileAvatar(userAvatar) {
		badRequest(c, "invalid_avatar", "头像必须是 HTTP(S)、站内路径或 data:image 地址")
		return
	}
	if err := h.db.UpdateUserProfile(
		c.Request.Context(),
		user.ID,
		displayName,
		assistantName,
		assistantAvatar,
		userAvatar,
	); err != nil {
		internalError(c, "update_profile_failed", "保存个人资料失败")
		return
	}
	user.DisplayName = displayName
	c.JSON(http.StatusOK, gin.H{
		"user": h.toUserResponse(c.Request.Context(), user),
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	rawToken := middleware.RawTokenFromContext(c)
	if err := h.service.Logout(c.Request.Context(), rawToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code":    "internal_error",
			"message": "登出失败",
		})
		return
	}
	h.clearCookies(c)
	c.Status(http.StatusNoContent)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	ConfirmPassword string `json:"confirmPassword"`
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	clientIP := c.ClientIP()
	if remaining := h.passwordLimiter.Blocked(user.Username, clientIP); remaining > 0 {
		retryAfter := int(remaining.Seconds()) + 1
		c.Header("Retry-After", strconv.Itoa(retryAfter))
		c.JSON(http.StatusTooManyRequests, gin.H{
			"code":              "too_many_attempts",
			"message":           "密码修改尝试过于频繁，请稍后再试",
			"retryAfterSeconds": retryAfter,
		})
		return
	}
	var request changePasswordRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_request", "请求格式错误")
		return
	}
	if strings.TrimSpace(request.CurrentPassword) == "" || strings.TrimSpace(request.NewPassword) == "" {
		badRequest(c, "invalid_request", "当前密码与新密码不能为空")
		return
	}
	if request.NewPassword != request.ConfirmPassword {
		badRequest(c, "password_mismatch", "两次输入的新密码不一致")
		return
	}
	err := h.service.ChangePassword(
		c.Request.Context(),
		user.ID,
		middleware.RawTokenFromContext(c),
		request.CurrentPassword,
		request.NewPassword,
	)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		h.passwordLimiter.RecordFailure(user.Username, clientIP)
		if h.db != nil {
			_ = h.db.AddAuditLog(c.Request.Context(), database.AuditLog{
				UserID:       user.ID,
				Username:     user.Username,
				Action:       "auth.change_password",
				ResourceType: "user",
				ResourceID:   user.ID,
				Result:       "failure",
				Detail:       "invalid current password",
			})
		}
		badRequest(c, "invalid_current_password", "当前密码不正确")
		return
	case err != nil:
		badRequest(c, "invalid_new_password", err.Error())
		return
	}
	h.passwordLimiter.Reset(user.Username, clientIP)
	if h.db != nil {
		_ = h.db.AddAuditLog(c.Request.Context(), database.AuditLog{
			UserID:       user.ID,
			Username:     user.Username,
			Action:       "auth.change_password",
			ResourceType: "user",
			ResourceID:   user.ID,
			Result:       "success",
		})
	}
	c.Status(http.StatusNoContent)
}

func (h *AuthHandler) setCookies(c *gin.Context, result *auth.LoginResult) {
	maxAge := int(time.Until(result.ExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    result.Token,
		Path:     "/",
		MaxAge:   maxAge,
		Expires:  result.ExpiresAt,
		HttpOnly: true,
		Secure:   h.service.CookieSecure(),
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     auth.CSRFCookieName,
		Value:    result.CSRFToken,
		Path:     "/",
		MaxAge:   maxAge,
		Expires:  result.ExpiresAt,
		HttpOnly: false,
		Secure:   h.service.CookieSecure(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *AuthHandler) clearCookies(c *gin.Context) {
	expiresAt := time.Unix(1, 0)
	for _, cookie := range []*http.Cookie{
		{
			Name:     auth.SessionCookieName,
			Path:     "/",
			MaxAge:   -1,
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   h.service.CookieSecure(),
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     auth.CSRFCookieName,
			Path:     "/",
			MaxAge:   -1,
			Expires:  expiresAt,
			HttpOnly: false,
			Secure:   h.service.CookieSecure(),
			SameSite: http.SameSiteLaxMode,
		},
	} {
		http.SetCookie(c.Writer, cookie)
	}
}

func validProfileAvatar(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 500*1024 {
		return false
	}
	if strings.HasPrefix(value, "data:image/") {
		return true
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return false
	}
	if parsed.Scheme == "" {
		return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//")
	}
	return parsed.Scheme == "http" || parsed.Scheme == "https"
}

func (h *AuthHandler) toUserResponse(ctx context.Context, user *database.User) userResponse {
	displayName := strings.TrimSpace(user.DisplayName)
	if displayName == "" {
		displayName = user.Username
	}
	assistantName := "Sophon"
	assistantAvatar := ""
	userAvatar := ""
	if h.db != nil {
		if profile, err := h.db.GetUserProfile(ctx, user.ID); err == nil {
			if strings.TrimSpace(profile.AssistantName) != "" {
				assistantName = strings.TrimSpace(profile.AssistantName)
			}
			assistantAvatar = profile.AssistantAvatar
			userAvatar = profile.UserAvatar
		}
	}
	return userResponse{
		ID:              user.ID,
		Username:        user.Username,
		DisplayName:     displayName,
		Role:            user.Role,
		AssistantName:   assistantName,
		AssistantAvatar: assistantAvatar,
		UserAvatar:      userAvatar,
	}
}
