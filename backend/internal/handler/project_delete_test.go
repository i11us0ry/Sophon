package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/storage"
	"sophon/internal/task"

	"github.com/gin-gonic/gin"
)

func TestDeleteProjectCancelsTasksAndCleansFiles(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-delete.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-delete",
		OwnerUserID: "user-1",
		Name:        "删除项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID:          "conv-project-delete",
		OwnerUserID: "user-1",
		ProjectID:   "project-delete",
		Title:       "删除测试",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	manager := task.NewManagerWithLimit(3)
	taskItem, _, err := manager.CreateIfIdle("conv-project-delete", "user-1")
	if err != nil {
		t.Fatalf("创建任务失败: %v", err)
	}

	root := t.TempDir()
	storageService := storage.NewService(db, config.StorageConfig{
		ArtifactRoot: root,
		Categories: map[string]config.StorageCategoryConfig{
			"chat_uploads":           {Enabled: true, Path: "chat_uploads"},
			"conversation_artifacts": {Enabled: true, Path: "data/conversation_artifacts"},
			"workspace":              {Enabled: true, Path: "tmp/workspace"},
			"reduction":              {Enabled: true, Path: "tmp/reduction"},
		},
	}, filepath.Join(root, "data"))
	for _, category := range []string{
		"chat_uploads",
		"conversation_artifacts",
		"workspace",
		"reduction",
	} {
		dir, err := storageService.CategoryDir(category)
		if err != nil {
			t.Fatalf("解析目录失败: %v", err)
		}
		target := filepath.Join(dir, "conv-project-delete")
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatalf("创建目录失败: %v", err)
		}
		if err := os.WriteFile(filepath.Join(target, "artifact.txt"), []byte("test"), 0o600); err != nil {
			t.Fatalf("写入文件失败: %v", err)
		}
	}

	handler := &BusinessHandler{db: db, manager: manager, storage: storageService}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(
		http.MethodDelete,
		"/api/projects/project-delete",
		nil,
	)
	ginCtx.Params = gin.Params{{Key: "id", Value: "project-delete"}}
	ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler.DeleteProject(ginCtx)

	if recorder.Code != http.StatusNoContent && recorder.Code != http.StatusOK {
		t.Fatalf("删除项目失败: %d %s", recorder.Code, recorder.Body.String())
	}
	if taskItem.Snapshot().Status != task.StatusCancelled {
		t.Fatalf("项目任务应被取消: %+v", taskItem.Snapshot())
	}
	if _, err := db.GetProject(ctx, "project-delete", "user-1"); err == nil {
		t.Fatalf("项目应被删除")
	}
	for _, category := range []string{
		"chat_uploads",
		"conversation_artifacts",
		"workspace",
		"reduction",
	} {
		dir, _ := storageService.CategoryDir(category)
		if _, err := os.Stat(filepath.Join(dir, "conv-project-delete")); !os.IsNotExist(err) {
			t.Fatalf("项目文件目录应被清理 category=%s err=%v", category, err)
		}
	}
}
