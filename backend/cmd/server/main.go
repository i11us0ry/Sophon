package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"sophon/internal/app"
	"sophon/internal/config"
	"sophon/internal/procwrap"
)

func main() {
	// 尽早收紧 umask：数据库、配置备份、会话产物等新建文件默认仅属主可读写。
	app.RestrictProcessUmask()
	if err := procwrap.Require(); err != nil {
		log.Fatalf("进程回收器不可用: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	if cfg.ConfigPath != "" {
		log.Printf("sophon config file: %s", cfg.ConfigPath)
	} else {
		log.Printf("sophon config file: 未找到 config.yml，使用默认值与环境变量")
	}

	application, err := app.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("sophon backend listening on %s:%d", cfg.Host, cfg.Port)
	if err := application.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
