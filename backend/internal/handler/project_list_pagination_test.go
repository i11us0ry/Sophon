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

	"github.com/gin-gonic/gin"
)

func TestListProjectsOffsetPaginationAndFilters(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-pagination.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	for _, project := range []database.Project{
		{ID: "project-active", OwnerUserID: "user-1", Name: "Active", Status: "active"},
		{ID: "project-paused", OwnerUserID: "user-1", Name: "Paused", Status: "paused"},
	} {
		project.CreatedAt = now
		project.UpdatedAt = now
		if err := db.CreateProject(ctx, project); err != nil {
			t.Fatalf("创建项目失败: %v", err)
		}
	}
	if err := db.CreateVulnerability(ctx, database.Vulnerability{
		ID: "vuln-project-pagination", ProjectID: "project-active", OwnerUserID: "user-1",
		Title: "Risk", Severity: "high", Status: "open",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}

	handler := &BusinessHandler{db: db}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(
		http.MethodGet,
		"/api/projects?limit=1&offset=0&status=active",
		nil,
	)
	ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler.ListProjects(ginCtx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("项目分页请求失败: %d %s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		Items      []database.ProjectWithCounts `json:"items"`
		Total      int                          `json:"total"`
		Page       int                          `json:"page"`
		PageSize   int                          `json:"pageSize"`
		TotalPages int                          `json:"totalPages"`
		Stats      database.ProjectListStats    `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析项目分页响应失败: %v", err)
	}
	if result.Total != 1 || result.Page != 1 || result.PageSize != 1 || result.TotalPages != 1 ||
		len(result.Items) != 1 || result.Items[0].ID != "project-active" {
		t.Fatalf("项目分页响应异常: %+v", result)
	}
	if result.Stats.Total != 2 || result.Stats.Active != 1 || result.Stats.Paused != 1 || result.Stats.Risk != 1 {
		t.Fatalf("项目全局统计异常: %+v", result.Stats)
	}

	recorder = httptest.NewRecorder()
	ginCtx, _ = gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/api/projects?limit=20&offset=-1", nil)
	ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler.ListProjects(ginCtx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("非法 offset 应返回 400: %d %s", recorder.Code, recorder.Body.String())
	}
}
