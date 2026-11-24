package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func TestIntelCollectionDeleteAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.Open(filepath.Join(t.TempDir(), "intel-collection-delete.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.CreateIntelSearch(context.Background(), database.IntelSearchRecord{
		ID:                 "search-delete",
		OwnerUserID:        "user-1",
		Provider:           "fofa",
		Query:              `domain="example.com"`,
		Page:               1,
		PageSize:           20,
		ResultsJSON:        `[]`,
		ProviderErrorsJSON: `[]`,
	}); err != nil {
		t.Fatalf("创建查询记录失败: %v", err)
	}
	handler := NewIntelCollectionHandler(db, fakeIntelCollectionService{})
	router := gin.New()
	router.DELETE("/intel/searches/:id", func(c *gin.Context) {
		c.Set("sophon.user", &database.User{ID: "user-1", Username: "tester"})
		c.Next()
	}, handler.Delete)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodDelete, "/intel/searches/search-delete", nil),
	)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("删除记录失败: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if _, err := db.GetIntelSearch(context.Background(), "search-delete", "user-1"); !database.NoRows(err) {
		t.Fatalf("记录应已删除，实际 %v", err)
	}
}
