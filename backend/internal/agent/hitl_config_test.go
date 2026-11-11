package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestHITLRequiredUsesConfiguredTools(t *testing.T) {
	service := &Service{cfg: config.Config{HITLEnabled: true, HITLTools: "exec, sqlmap"}}
	ctx := context.Background()

	if !service.hitlRequired(ctx, "", "exec") {
		t.Fatalf("清单内工具应需要审批")
	}
	if !service.hitlRequired(ctx, "", "SQLMAP") {
		t.Fatalf("工具名匹配应忽略大小写")
	}
	if service.hitlRequired(ctx, "", "nmap") {
		t.Fatalf("未列入清单的工具不应要求审批")
	}

	service.cfg.HITLEnabled = false
	if service.hitlRequired(ctx, "", "exec") {
		t.Fatalf("关闭 HITL 后不应要求审批")
	}

	service.cfg.HITLEnabled = true
	service.cfg.HITLTools = ""
	if !service.hitlRequired(ctx, "", "nmap") {
		t.Fatalf("空清单表示所有工具都需要审批")
	}
}

func TestHITLRequiredConversationOverride(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "hitl.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateConversation(ctx, database.Conversation{
		ID:          "conv-hitl",
		OwnerUserID: "user-1",
		Title:       "审批覆盖测试",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}

	service := &Service{db: db, cfg: config.Config{HITLEnabled: false, HITLTools: "exec"}}
	if service.hitlRequired(ctx, "conv-hitl", "exec") {
		t.Fatalf("未覆盖且全局关闭时不应审批")
	}
	if err := db.SetConversationHITLOverride(ctx, "conv-hitl", true); err != nil {
		t.Fatalf("开启会话审批失败: %v", err)
	}
	if !service.hitlRequired(ctx, "conv-hitl", "exec") {
		t.Fatalf("会话覆盖开启后应要求审批")
	}

	service.cfg.HITLEnabled = true
	if err := db.SetConversationHITLOverride(ctx, "conv-hitl", false); err != nil {
		t.Fatalf("关闭会话审批失败: %v", err)
	}
	if service.hitlRequired(ctx, "conv-hitl", "exec") {
		t.Fatalf("会话覆盖关闭后不应审批")
	}
}
