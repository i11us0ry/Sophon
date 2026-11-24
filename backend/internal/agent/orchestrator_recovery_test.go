package agent

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/config"
	"sophon/internal/database"
)

func TestRecoverBackgroundOrchestrationsKeepsPausedState(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "orchestration-recovery.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service, err := NewService(db, config.Config{AgentMock: true}, nil, nil)
	if err != nil {
		t.Fatalf("创建 Agent 服务失败: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-recovery", OwnerUserID: "user-1", Name: "恢复",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conv-recovery", OwnerUserID: "user-1", ProjectID: "project-recovery",
		Title: "恢复", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if err := db.UpsertAgentOrchestration(ctx, database.AgentOrchestration{
		ConversationID: "conv-recovery",
		ProjectID:      "project-recovery",
		OwnerUserID:    "user-1",
		Status:         database.AgentOrchestrationPaused,
		PlanJSON:       `{"mode":"agent","coordinated":true}`,
		Phase:          missionPhaseGeneral,
		AgentMode:      agentModeDeep,
		Feedback:       []string{"恢复后先确认上传点"},
		LastError:      "用户暂停",
		StartedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("写入暂停编排失败: %v", err)
	}
	recovered, err := service.RecoverBackgroundOrchestrations(ctx)
	if err != nil || recovered != 1 {
		t.Fatalf("恢复后台编排失败: recovered=%d err=%v", recovered, err)
	}
	handle := service.orchestrationFor("conv-recovery")
	if handle == nil || handle.snapshot()["status"] != database.AgentOrchestrationPaused {
		t.Fatalf("暂停编排未保持暂停: %+v", handle)
	}
	feedback := handle.takeFeedback()
	if len(feedback) != 1 || feedback[0] != "恢复后先确认上传点" {
		t.Fatalf("恢复后丢失 Planner 纠偏: %+v", feedback)
	}
}

func TestBackgroundOrchestrationAcquiresAndReleasesZhiziLease(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	node, err := service.db.CreateZhiziNode(ctx, database.ZhiziNode{
		CreatedByUserID:    "user-1",
		Name:               "background-lease",
		Host:               "127.0.0.1",
		Port:               22,
		Username:           "root",
		AuthType:           "key",
		HostKeyFingerprint: "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
		WorkRoot:           "/tmp/sophon",
		MaxSlots:           1,
		Enabled:            true,
	}, database.ZhiziNodeSecret{PrivateKey: "unused"})
	if err != nil {
		t.Fatalf("创建智子节点失败: %v", err)
	}
	if err := service.db.RecordZhiziNodeTest(ctx, node.ID, nil); err != nil {
		t.Fatalf("标记智子节点可用失败: %v", err)
	}
	if err := service.db.SetZhiziConversationEnabled(ctx, "conv-tools", "user-1", true); err != nil {
		t.Fatalf("启用会话智子失败: %v", err)
	}
	release, err := service.acquireBackgroundZhiziLease(ctx, "conv-tools", "user-1")
	if err != nil {
		t.Fatalf("后台编排获取智子租约失败: %v", err)
	}
	lease, err := service.db.GetActiveZhiziLease(ctx, "conv-tools", "user-1")
	if err != nil || lease == nil {
		t.Fatalf("后台编排期间租约不存在: lease=%+v err=%v", lease, err)
	}
	release()
	lease, err = service.db.GetActiveZhiziLease(ctx, "conv-tools", "user-1")
	if err != nil || lease != nil {
		t.Fatalf("后台编排结束后租约未释放: lease=%+v err=%v", lease, err)
	}
}
