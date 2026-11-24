package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func TestToolRegistryRedactsEnvAndIsolatesUsers(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "mcp-tool-registry.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.UpsertRegisteredTool(ctx, database.RegisteredTool{
		ID: "tool-owner", OwnerUserID: "user-1", Scope: database.ToolScopeGlobal,
		Name: "owner-tool", Command: "/tmp/owner-tool", Enabled: true,
		Env:       map[string]string{"API_KEY": "super-secret"},
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("创建用户工具失败: %v", err)
	}
	if _, err := db.UpsertRegisteredTool(ctx, database.RegisteredTool{
		ID: "tool-foreign", OwnerUserID: "user-2", Scope: database.ToolScopeGlobal,
		Name: "foreign-tool", Command: "/tmp/foreign-tool", Enabled: true,
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("创建其他用户工具失败: %v", err)
	}

	handler := &MCPHandler{db: db}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/api/mcp/tool-registry", nil)
	ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler.ToolRegistry(ginCtx)

	body := recorder.Body.String()
	if recorder.Code != http.StatusOK ||
		!strings.Contains(body, "owner-tool") ||
		strings.Contains(body, "super-secret") ||
		!strings.Contains(body, `"API_KEY":"***"`) ||
		strings.Contains(body, "foreign-tool") {
		t.Fatalf("工具注册表隔离或脱敏失败: status=%d body=%s", recorder.Code, body)
	}
}
