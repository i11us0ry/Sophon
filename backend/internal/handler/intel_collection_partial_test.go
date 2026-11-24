package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func TestIntelCollectionReturnsResultsWhenHistoryPersistenceFails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.Open(filepath.Join(t.TempDir(), "intel-partial.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("关闭数据库失败: %v", err)
	}
	handler := NewIntelCollectionHandler(db, fakeIntelCollectionService{})
	router := gin.New()
	router.POST("/intel/searches", func(c *gin.Context) {
		c.Set("sophon.user", &database.User{ID: "user-1", Username: "tester"})
		c.Next()
	}, handler.Create)
	body := []byte(`{"provider":"fofa","query":"domain=\"example.com\"","page":1,"page_size":20}`)
	request := httptest.NewRequest(http.MethodPost, "/intel/searches", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("历史落库失败时应返回 200，实际 status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	bodyValue := recorder.Body.String()
	if !bytes.Contains([]byte(bodyValue), []byte(`"persisted":false`)) ||
		!bytes.Contains([]byte(bodyValue), []byte("https://oa.example.com:8443")) {
		t.Fatalf("部分成功响应不完整: %s", bodyValue)
	}
}
