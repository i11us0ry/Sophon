package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

type recordingProjectAgentController struct {
	pauseCalls  int
	resumeCalls int
	pauseErr    error
}

func (r *recordingProjectAgentController) PauseProject(
	context.Context,
	string,
	string,
	string,
) (int, error) {
	r.pauseCalls++
	return 1, r.pauseErr
}

func (r *recordingProjectAgentController) ResumeProject(context.Context, string, string) (int, error) {
	r.resumeCalls++
	return 1, nil
}

type recordingProjectCampaignController struct {
	pauseCalls  int
	resumeCalls int
}

func (r *recordingProjectCampaignController) PauseProjectCampaigns(
	context.Context,
	string,
	string,
) (int, error) {
	r.pauseCalls++
	return 1, nil
}

func (r *recordingProjectCampaignController) ResumeProjectCampaigns(
	context.Context,
	string,
	string,
) (int, error) {
	r.resumeCalls++
	return 1, nil
}

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

func TestUpdateProjectControlsProjectAgentLifecycle(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-agent-status.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-agent-status",
		OwnerUserID: "user-1",
		Name:        "Agent Status",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	controller := &recordingProjectAgentController{}
	campaignController := &recordingProjectCampaignController{}
	handler := &BusinessHandler{
		db:                     db,
		projectAgentController: controller,
		projectCampaigns:       campaignController,
	}
	gin.SetMode(gin.TestMode)
	request := func(status string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(recorder)
		ginCtx.Request = httptest.NewRequest(
			http.MethodPut,
			"/api/projects/project-agent-status",
			strings.NewReader(`{"name":"Agent Status","status":"`+status+`"}`),
		)
		ginCtx.Params = gin.Params{{Key: "id", Value: "project-agent-status"}}
		ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
		handler.UpdateProject(ginCtx)
		return recorder
	}
	if recorder := request("paused"); recorder.Code != http.StatusNoContent && recorder.Code != http.StatusOK {
		t.Fatalf("暂停项目失败: %d %s", recorder.Code, recorder.Body.String())
	}
	if controller.pauseCalls != 1 || controller.resumeCalls != 0 {
		t.Fatalf("项目暂停未调用 Agent 控制: %+v", controller)
	}
	if campaignController.pauseCalls != 1 || campaignController.resumeCalls != 0 {
		t.Fatalf("项目暂停未调用 Campaign 控制: %+v", campaignController)
	}
	if recorder := request("active"); recorder.Code != http.StatusNoContent && recorder.Code != http.StatusOK {
		t.Fatalf("恢复项目失败: %d %s", recorder.Code, recorder.Body.String())
	}
	if controller.pauseCalls != 1 || controller.resumeCalls != 1 {
		t.Fatalf("项目恢复未调用 Agent 控制: %+v", controller)
	}
	if campaignController.pauseCalls != 1 || campaignController.resumeCalls != 1 {
		t.Fatalf("项目恢复未调用 Campaign 控制: %+v", campaignController)
	}
}

func TestUpdateProjectCancelsJobsWhenAgentControlFails(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-agent-failure.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-agent-failure", OwnerUserID: "user-1", Name: "Failure",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conv-agent-failure", OwnerUserID: "user-1", ProjectID: "project-agent-failure",
		CreatedAt: now, UpdatedAt: now, Title: "Failure",
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	controller := &recordingProjectAgentController{pauseErr: errors.New("pause failed")}
	jobs := &recordingJobCanceller{}
	handler := &BusinessHandler{
		db:                     db,
		jobs:                   jobs,
		projectAgentController: controller,
	}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(
		http.MethodPut,
		"/api/projects/project-agent-failure",
		strings.NewReader(`{"name":"Failure","status":"paused"}`),
	)
	ginCtx.Params = gin.Params{{Key: "id", Value: "project-agent-failure"}}
	ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler.UpdateProject(ginCtx)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("Agent 控制失败应返回错误: %d %s", recorder.Code, recorder.Body.String())
	}
	if jobs.calls != 1 || jobs.conversationID != "conv-agent-failure" {
		t.Fatalf("Agent 控制失败后仍应取消 Job: %+v", jobs)
	}
}
