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

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func TestUpdateProfilePersistsConversationIdentity(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "profile.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	if err := db.CreateUser(context.Background(), database.User{
		ID:           "user-profile",
		Username:     "alice",
		DisplayName:  "",
		PasswordHash: "hash",
		Role:         "viewer",
		Enabled:      true,
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	handler := &AuthHandler{db: db}
	recorder := performUpdateProfileRequest(t, handler, updateProfileRequest{
		DisplayName:     "Alice",
		AssistantName:   "Sophon One",
		AssistantAvatar: "/img/icon.png",
		UserAvatar:      "data:image/png;base64,AAAA",
	})
	if recorder.Code != http.StatusOK {
		t.Fatalf("保存资料失败: %d %s", recorder.Code, recorder.Body.String())
	}
	user, err := db.GetUserByID(context.Background(), "user-profile")
	if err != nil {
		t.Fatalf("读取用户失败: %v", err)
	}
	if user.DisplayName != "Alice" {
		t.Fatalf("用户称呼未保存: %+v", user)
	}
	profile, err := db.GetUserProfile(context.Background(), "user-profile")
	if err != nil {
		t.Fatalf("读取用户资料失败: %v", err)
	}
	if profile.AssistantName != "Sophon One" ||
		profile.AssistantAvatar != "/img/icon.png" ||
		profile.UserAvatar != "data:image/png;base64,AAAA" {
		t.Fatalf("对话身份未保存: %+v", profile)
	}

	recorder = performUpdateProfileRequest(t, handler, updateProfileRequest{
		DisplayName:   "Alice",
		AssistantName: "Sophon",
		UserAvatar:    "javascript:alert(1)",
	})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("非法头像应返回 400: %d %s", recorder.Code, recorder.Body.String())
	}
}

func performUpdateProfileRequest(
	t *testing.T,
	handler *AuthHandler,
	payload updateProfileRequest,
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
		http.MethodPut,
		"/api/auth/profile",
		bytes.NewReader(body),
	)
	ginCtx.Request.Header.Set("Content-Type", "application/json")
	ginCtx.Set("sophon.user", &database.User{
		ID:       "user-profile",
		Username: "alice",
		Role:     "viewer",
		Enabled:  true,
	})
	handler.UpdateProfile(ginCtx)
	return recorder
}
