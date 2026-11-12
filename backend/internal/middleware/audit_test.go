package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCaptureAuditBodyPreservesLargeJSONBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	payload := []byte(`{"message":"` + strings.Repeat("A", 20_000) + `"}`)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")

	if captured := captureAuditBody(ctx); captured != nil {
		t.Fatalf("超过审计上限的请求不应返回审计正文")
	}
	restored, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		t.Fatalf("读取还原请求体失败: %v", err)
	}
	if !bytes.Equal(restored, payload) {
		t.Fatalf("请求体被截断：got=%d want=%d", len(restored), len(payload))
	}
	var parsed map[string]string
	if err := json.Unmarshal(restored, &parsed); err != nil {
		t.Fatalf("还原请求体不是完整 JSON: %v", err)
	}
	if len(parsed["message"]) != 20_000 {
		t.Fatalf("消息长度错误: %d", len(parsed["message"]))
	}
}

func TestCaptureAuditBodyCapturesSmallJSONBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	payload := []byte(`{"message":"hello"}`)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")

	captured := captureAuditBody(ctx)
	if !bytes.Equal(captured, payload) {
		t.Fatalf("小请求体审计内容错误: %q", captured)
	}
	restored, err := io.ReadAll(ctx.Request.Body)
	if err != nil || !bytes.Equal(restored, payload) {
		t.Fatalf("小请求体还原失败: %q err=%v", restored, err)
	}
}

func TestCaptureAuditBodySkipsWorkspaceTextContent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	payload := []byte("SECRET_TOKEN=workspace-content")
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/workspace/content", bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", "text/plain; charset=utf-8")

	if captured := captureAuditBody(ctx); captured != nil {
		t.Fatalf("工作区文本正文不应进入审计正文")
	}
	restored, err := io.ReadAll(ctx.Request.Body)
	if err != nil || !bytes.Equal(restored, payload) {
		t.Fatalf("工作区文本请求体还原失败: %q err=%v", restored, err)
	}
}

func TestAuditResourceForWorkspaceFile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var resourceType string
	var resourceID string
	router.PUT("/api/workspace/content", func(c *gin.Context) {
		resourceType, resourceID = auditResource(c)
		c.Status(http.StatusNoContent)
	})
	request := httptest.NewRequest(
		http.MethodPut,
		"/api/workspace/content?category=workspace&path=poc%2Fexploit.py",
		nil,
	)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if resourceType != "workspace_file" || resourceID != "poc/exploit.py" {
		t.Fatalf("工作区文件审计资源错误: type=%s id=%s", resourceType, resourceID)
	}
}

func TestSummarizeAuditBodyRedactsLLMKeyRoutes(t *testing.T) {
	body := []byte(`{"apiKeys":"sk-secret-one\nsk-secret-two"}`)
	if got := summarizeAuditBody("/api/settings/llm/keys", body); got != "***" {
		t.Fatalf("LLM Key 请求体必须完全屏蔽，实际 %q", got)
	}
	if got := summarizeAuditBody("/api/settings/ai", []byte(`{"llm":{"apiKeys":"sk-secret"}}`)); strings.Contains(got, "sk-secret") {
		t.Fatalf("LLM 设置审计不能泄露 Key: %q", got)
	}
}
