package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRespondIntelProbeFailureUsesHTTPError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	respondIntelProbe(context, "fofa", intelProbeStatus{
		Status:  "error",
		Message: "invalid credentials",
	})
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("Provider 测试失败应返回 502，实际 %d", recorder.Code)
	}
}
