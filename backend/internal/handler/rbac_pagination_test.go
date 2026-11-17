package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/database"
	rbacpkg "sophon/internal/rbac"

	"github.com/gin-gonic/gin"
)

func TestListUsersPaginatesFiltersAndSorts(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "rbac-pagination.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	for _, user := range []database.User{
		{
			ID: "user-alpha", Username: "alpha", DisplayName: "Alpha",
			PasswordHash: "unused", Role: "viewer", Enabled: true, CreatedAt: now,
		},
		{
			ID: "user-zulu", Username: "zulu", DisplayName: "Zulu",
			PasswordHash: "unused", Role: "viewer", Enabled: false, CreatedAt: now.Add(time.Minute),
		},
	} {
		if err := db.CreateUser(ctx, user); err != nil {
			t.Fatalf("创建用户失败: %v", err)
		}
	}
	handler := NewRBACHandler(rbacpkg.NewService(db))
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(
		http.MethodGet,
		"/api/rbac/users?limit=1&offset=0&sort=username_desc",
		nil,
	)
	handler.ListUsers(ginCtx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("用户分页失败: %d %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Items []struct {
			Username string `json:"username"`
		} `json:"items"`
		Total      int `json:"total"`
		TotalPages int `json:"totalPages"`
		Stats      struct {
			Total   int `json:"total"`
			Enabled int `json:"enabled"`
		} `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析用户分页响应失败: %v", err)
	}
	if result.Total != 2 || result.TotalPages != 2 || len(result.Items) != 1 ||
		result.Items[0].Username != "zulu" || result.Stats.Total != 2 || result.Stats.Enabled != 1 {
		t.Fatalf("用户分页响应异常: %+v", result)
	}
}
