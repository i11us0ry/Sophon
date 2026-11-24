package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"sophon/internal/config"
	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func TestIntelSettingsAPIEncryptsAndMasksKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.Open(filepath.Join(t.TempDir(), "settings-intel.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler := NewSettingsHandler(config.Config{}, db, nil, nil, nil)
	router := gin.New()
	router.GET("/settings/intel", handler.IntelSettings)
	router.PUT("/settings/intel", handler.UpdateIntelSettings)

	body := []byte(`{
		"enabled":true,
		"fofaEmail":"user@example.com",
		"fofaKey":"fofa-secret-key",
		"hunterKey":"hunter-secret-key"
	}`)
	request := httptest.NewRequest(http.MethodPut, "/settings/intel", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("保存信息设置失败: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/settings/intel", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("读取信息设置失败: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "fofa-secret-key") ||
		strings.Contains(recorder.Body.String(), "hunter-secret-key") {
		t.Fatalf("GET 接口不应返回明文 Key: %s", recorder.Body.String())
	}
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if response["fofaKeyMasked"] == "" || response["hunterKeyMasked"] == "" {
		t.Fatalf("响应缺少掩码: %s", recorder.Body.String())
	}

	settings, err := db.GetIntelSettings(context.Background())
	if err != nil {
		t.Fatalf("读取数据库设置失败: %v", err)
	}
	if settings.FOFAKey != "fofa-secret-key" || settings.HunterKey != "hunter-secret-key" {
		t.Fatalf("密钥往返失败: %+v", settings)
	}
}
