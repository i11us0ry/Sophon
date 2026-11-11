package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// LimitJSONBody 限制 JSON 请求体大小，避免认证用户提交超大对象耗尽内存或数据库空间。
func LimitJSONBody(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request == nil || c.Request.Body == nil || maxBytes <= 0 {
			c.Next()
			return
		}
		if !strings.Contains(strings.ToLower(c.GetHeader("Content-Type")), "application/json") {
			c.Next()
			return
		}
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"code":    "request_too_large",
				"message": "请求内容过大",
			})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
