package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLoginRejectsOversizedRequestWithNoStoreHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	body := `{"username":"admin","password":"` +
		strings.Repeat("x", maxLoginRequestBytes) +
		`"}`
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	(&AuthHandler{}).Login(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("超长登录请求应返回 400，实际 %d", recorder.Code)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("登录响应必须禁止缓存")
	}
	if recorder.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("登录响应应设置 Pragma: no-cache")
	}
}
