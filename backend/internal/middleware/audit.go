package middleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/redact"

	"github.com/gin-gonic/gin"
)

const (
	auditBodyLimit    = 16 << 10
	auditDetailLimit  = 600
	auditWriteTimeout = 3 * time.Second
)

// AuditMutations 记录所有写操作的审计日志：真实对象 ID + 脱敏后的请求摘要。
func AuditMutations(db *database.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body []byte
		if db != nil && isMutation(c.Request.Method) {
			body = captureAuditBody(c)
		}

		c.Next()

		if db == nil || !isMutation(c.Request.Method) {
			return
		}

		user := UserFromContext(c)
		var userID string
		var username string
		if user != nil {
			userID = user.ID
			username = user.Username
		}
		result := "success"
		if c.Writer.Status() >= 400 {
			result = "failure"
		}
		resourceType, resourceID := auditResource(c)
		detail := auditDetail(c, body, c.Writer.Status())
		if resourceType == "workspace_file" {
			detail = workspaceFileAuditDetail(c, c.Writer.Status())
		}

		entry := database.AuditLog{
			UserID:       userID,
			Username:     username,
			Action:       fmt.Sprintf("%s %s", c.Request.Method, c.FullPath()),
			ResourceType: resourceType,
			ResourceID:   resourceID,
			Result:       result,
			Detail:       detail,
		}

		// 客户端断开或超时不应丢失审计：脱离请求取消信号，并限制写入耗时。
		ctx, cancel := context.WithTimeout(
			context.WithoutCancel(c.Request.Context()),
			auditWriteTimeout,
		)
		defer cancel()
		if err := db.AddAuditLog(ctx, entry); err != nil {
			log.Printf("audit: 写入审计日志失败 action=%s err=%v", entry.Action, err)
		}
	}
}

func isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// captureAuditBody 读取并还原请求体；仅处理 JSON 且不超过上限的请求。
func captureAuditBody(c *gin.Context) []byte {
	if c.Request == nil || c.Request.Body == nil {
		return nil
	}
	if !strings.Contains(strings.ToLower(c.GetHeader("Content-Type")), "application/json") {
		return nil
	}
	original := c.Request.Body
	raw, err := io.ReadAll(io.LimitReader(original, auditBodyLimit+1))
	if err != nil {
		c.Request.Body = &auditReadCloser{
			Reader: io.MultiReader(bytes.NewReader(raw), original),
			Closer: original,
		}
		return nil
	}
	if len(raw) > auditBodyLimit {
		c.Request.Body = &auditReadCloser{
			Reader: io.MultiReader(bytes.NewReader(raw), original),
			Closer: original,
		}
		return nil
	}
	_ = original.Close()
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	return raw
}

type auditReadCloser struct {
	io.Reader
	io.Closer
}

// auditResourceID 返回路径参数里最后一个真实对象 ID（没有路径参数时为空）。
func auditResourceID(c *gin.Context) string {
	resourceID := ""
	for _, param := range c.Params {
		if value := strings.TrimSpace(param.Value); value != "" {
			resourceID = value
		}
	}
	return resourceID
}

func auditResource(c *gin.Context) (string, string) {
	if c.Request.Method == http.MethodPut && c.FullPath() == "/api/workspace/content" {
		path := strings.TrimSpace(c.Query("path"))
		if runes := []rune(path); len(runes) > 512 {
			path = string(runes[:512]) + "..."
		}
		return "workspace_file", path
	}
	return "http_route", auditResourceID(c)
}

func workspaceFileAuditDetail(c *gin.Context, status int) string {
	parts := []string{fmt.Sprintf("status=%d", status)}
	if ip := strings.TrimSpace(c.ClientIP()); ip != "" {
		parts = append(parts, "ip="+ip)
	}
	if category := strings.TrimSpace(c.Query("category")); category != "" {
		parts = append(parts, "category="+category)
	}
	return strings.Join(parts, " ")
}

func auditDetail(c *gin.Context, body []byte, status int) string {
	parts := []string{fmt.Sprintf("status=%d", status)}
	if ip := strings.TrimSpace(c.ClientIP()); ip != "" {
		parts = append(parts, "ip="+ip)
	}
	if summary := summarizeAuditBody(c.FullPath(), body); summary != "" {
		parts = append(parts, "body="+summary)
	}
	detail := strings.Join(parts, " ")
	if runes := []rune(detail); len(runes) > auditDetailLimit {
		detail = string(runes[:auditDetailLimit]) + "..."
	}
	return detail
}

// summarizeAuditBody 生成脱敏、截断的请求体摘要；对话流不记录正文。
func summarizeAuditBody(route string, body []byte) string {
	if len(body) == 0 || route == "/api/chat/stream" {
		return ""
	}
	summary, ok := redact.JSON(body)
	if !ok {
		return ""
	}
	return summary
}
