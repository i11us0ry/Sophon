package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	agentpkg "sophon/internal/agent"
	"sophon/internal/database"
	"sophon/internal/intel"

	"github.com/gin-gonic/gin"
)

type fakeIntelCollectionService struct{}

func (fakeIntelCollectionService) SearchIntel(
	context.Context,
	agentpkg.IntelSearchRequest,
) ([]intel.Result, []string, error) {
	return []intel.Result{{
		URL:     "https://oa.example.com:8443",
		Domain:  "oa.example.com",
		IP:      "10.0.0.8",
		Port:    8443,
		Title:   "OA",
		Sources: []string{"fofa", "hunter"},
	}}, nil, nil
}

func (fakeIntelCollectionService) IntelCapabilities(context.Context) (agentpkg.IntelCapabilities, error) {
	return agentpkg.IntelCapabilities{
		Enabled:        true,
		FOFAConfigured: true,
	}, nil
}

func (fakeIntelCollectionService) ImportIntelAssets(
	context.Context,
	string,
	string,
	[]intel.Result,
) (agentpkg.IntelAssetImportSummary, error) {
	return agentpkg.IntelAssetImportSummary{
		Created:  1,
		AssetIDs: []string{"asset-1"},
	}, nil
}

func TestIntelCollectionAPIPersistsAndImports(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.Open(filepath.Join(t.TempDir(), "intel-collection.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-intel",
		OwnerUserID: "user-1",
		Name:        "情报项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	handler := NewIntelCollectionHandler(db, fakeIntelCollectionService{})
	router := gin.New()
	withUser := func(c *gin.Context) {
		c.Set("sophon.user", &database.User{ID: "user-1", Username: "tester"})
		c.Next()
	}
	router.GET("/intel/capabilities", withUser, handler.Capabilities)
	router.GET("/intel/searches", withUser, handler.List)
	router.POST("/intel/searches", withUser, handler.Create)
	router.GET("/intel/searches/:id", withUser, handler.Get)
	router.POST("/intel/searches/:id/import", withUser, handler.Import)

	body := []byte(`{
		"provider":"fofa",
		"query":"domain=\"example.com\"",
		"projectId":"project-intel",
		"page":1,
		"page_size":20
	}`)
	request := httptest.NewRequest(http.MethodPost, "/intel/searches", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("创建查询记录失败: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var created map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("解析创建响应失败: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" || created["resultCount"].(float64) != 1 {
		t.Fatalf("创建响应异常: %s", recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/intel/searches", nil))
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(id)) {
		t.Fatalf("查询历史异常: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/intel/searches/"+id, nil))
	if recorder.Code != http.StatusOK ||
		!bytes.Contains(recorder.Body.Bytes(), []byte("https://oa.example.com:8443")) {
		t.Fatalf("查询详情异常: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(
		http.MethodPost,
		"/intel/searches/"+id+"/import",
		bytes.NewBufferString(`{"projectId":"project-intel"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"created":1`)) {
		t.Fatalf("导入资产异常: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
