package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func TestAppRunExitsAfterContextCancellation(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "app-shutdown.db"))
	if err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	application := &App{
		config: config.Config{Host: "127.0.0.1", Port: 0},
		router: gin.New(),
		db:     db,
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- application.Run(ctx)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("App.Run 未在取消后完成停机")
	}
}
