package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func TestCreateProjectsBatch(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	handler := &BusinessHandler{db: db}
	payload := projectBatchCreateRequest{
		Assets: "example.com\n10.0.0.0/24\nexample.com\nnot an asset\n",
	}
	recorder := performProjectBatchRequest(t, handler, payload, true)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("批量创建失败: %d %s", recorder.Code, recorder.Body.String())
	}

	var result projectBatchCreateResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if result.Created != 2 || result.Duplicate != 1 || result.Invalid != 1 || result.Failed != 0 {
		t.Fatalf("批量统计异常: %+v", result)
	}

	projects, err := db.ListProjects(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("读取项目失败: %v", err)
	}
	if len(projects) != 2 {
		t.Fatalf("项目数量应为 2，实际 %d", len(projects))
	}
	for _, project := range projects {
		assets, err := db.ListProjectAssets(context.Background(), project.ID, "user-1")
		if err != nil {
			t.Fatalf("读取项目资产失败: %v", err)
		}
		if len(assets) != 1 {
			t.Fatalf("项目 %s 应只有一个授权资产，实际 %d", project.ID, len(assets))
		}
		if assets[0].Value != project.Scope {
			t.Fatalf("项目授权资产不一致: scope=%q asset=%q", project.Scope, assets[0].Value)
		}
	}
}

func TestCreateProjectsBatchValidation(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch-validation.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler := &BusinessHandler{db: db}

	if recorder := performProjectBatchRequest(
		t,
		handler,
		projectBatchCreateRequest{Assets: " \n\r\n "},
		true,
	); recorder.Code != http.StatusBadRequest {
		t.Fatalf("空资产列表应返回 400，实际 %d", recorder.Code)
	}

	tooMany := make([]string, projectBatchMaxAssets+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("host-%d.example.com", index)
	}
	if recorder := performProjectBatchRequest(
		t,
		handler,
		projectBatchCreateRequest{Assets: strings.Join(tooMany, "\n")},
		true,
	); recorder.Code != http.StatusBadRequest {
		t.Fatalf("超过 500 个资产应返回 400，实际 %d", recorder.Code)
	}

	if recorder := performProjectBatchRequest(
		t,
		handler,
		projectBatchCreateRequest{Assets: "example.com"},
		false,
	); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("未登录请求应返回 401，实际 %d", recorder.Code)
	}
}

func performProjectBatchRequest(
	t *testing.T,
	handler *BusinessHandler,
	payload projectBatchCreateRequest,
	withUser bool,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("编码请求失败: %v", err)
	}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(
		http.MethodPost,
		"/api/projects/batch",
		bytes.NewReader(body),
	)
	ginCtx.Request.Header.Set("Content-Type", "application/json")
	if withUser {
		ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	}
	handler.CreateProjectsBatch(ginCtx)
	return recorder
}
