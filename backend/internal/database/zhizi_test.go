package database

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestZhiziNodeSecretsLeasesAndCapacity(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "zhizi.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-zhizi", OwnerUserID: "user-1", Name: "智子测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	for _, conversation := range []Conversation{
		{ID: "conv-zhizi-a", OwnerUserID: "user-1", ProjectID: "project-zhizi", Title: "A", CreatedAt: now, UpdatedAt: now},
		{ID: "conv-zhizi-b", OwnerUserID: "user-1", ProjectID: "project-zhizi", Title: "B", CreatedAt: now, UpdatedAt: now},
	} {
		if err := db.CreateConversation(ctx, conversation); err != nil {
			t.Fatalf("创建对话失败: %v", err)
		}
	}
	node, err := db.CreateZhiziNode(ctx, ZhiziNode{
		CreatedByUserID:    "user-1",
		Name:               "node-a",
		Host:               "10.0.0.10",
		Port:               22,
		Username:           "root",
		AuthType:           "key",
		HostKeyFingerprint: "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
		WorkRoot:           "/home/sophon/sophon",
		MaxSlots:           1,
		Enabled:            true,
	}, ZhiziNodeSecret{PrivateKey: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"})
	if err != nil {
		t.Fatalf("创建智子节点失败: %v", err)
	}
	_, restoredSecret, err := db.GetZhiziNodeSecret(ctx, node.ID)
	if err != nil {
		t.Fatalf("读取凭据失败: %v", err)
	}
	if !strings.Contains(restoredSecret.PrivateKey, "secret") {
		t.Fatalf("凭据解密错误")
	}
	var privateKeyCipher string
	if err := db.QueryRowContext(
		ctx,
		`SELECT private_key_cipher FROM zhizi_nodes WHERE id = ?`,
		node.ID,
	).Scan(&privateKeyCipher); err != nil {
		t.Fatalf("读取凭据密文失败: %v", err)
	}
	if privateKeyCipher == restoredSecret.PrivateKey || !strings.HasPrefix(privateKeyCipher, jobCipherPrefix) {
		t.Fatalf("SSH 私钥未加密保存: %q", privateKeyCipher)
	}
	node.AuthType = "password"
	if _, err := db.UpdateZhiziNode(ctx, *node, ZhiziNodeSecret{Password: "new-password"}); err != nil {
		t.Fatalf("切换认证方式失败: %v", err)
	}
	if err := db.QueryRowContext(
		ctx,
		`SELECT private_key_cipher, password_cipher FROM zhizi_nodes WHERE id = ?`,
		node.ID,
	).Scan(&privateKeyCipher, new(string)); err != nil {
		t.Fatalf("读取切换后的凭据失败: %v", err)
	}
	if privateKeyCipher != "" {
		t.Fatalf("切换为密码认证后应清除旧私钥密文: %q", privateKeyCipher)
	}
	availability, err := db.ZhiziAvailability(ctx)
	if err != nil || availability.TotalSlots != 0 || availability.Available != 0 {
		t.Fatalf("未测试节点不应计入可用容量: %+v err=%v", availability, err)
	}
	for _, conversationID := range []string{"conv-zhizi-a", "conv-zhizi-b"} {
		if err := db.SetZhiziConversationEnabled(ctx, conversationID, "user-1", true); err != nil {
			t.Fatalf("启用会话智子失败: %v", err)
		}
	}
	if _, err := db.AcquireZhiziLease(ctx, "conv-zhizi-a", "user-1", time.Hour); !errors.Is(err, ErrZhiziNoCapacity) {
		t.Fatalf("未测试节点不应分配租约，实际: %v", err)
	}
	if err := db.RecordZhiziNodeTest(ctx, node.ID, nil); err != nil {
		t.Fatalf("记录节点测试成功失败: %v", err)
	}
	availability, err = db.ZhiziAvailability(ctx)
	if err != nil || availability.TotalSlots != 1 || availability.Available != 1 {
		t.Fatalf("测试成功节点应计入可用容量: %+v err=%v", availability, err)
	}
	leaseA, err := db.AcquireZhiziLease(ctx, "conv-zhizi-a", "user-1", time.Hour)
	if err != nil || leaseA == nil || leaseA.NodeID != node.ID {
		t.Fatalf("获取租约失败: lease=%+v err=%v", leaseA, err)
	}
	if _, err := db.AcquireZhiziLease(ctx, "conv-zhizi-b", "user-1", time.Hour); !errors.Is(err, ErrZhiziNoCapacity) {
		t.Fatalf("容量耗尽时应拒绝租约，实际: %v", err)
	}
	if err := db.ReleaseZhiziLease(ctx, leaseA.ID); err != nil {
		t.Fatalf("释放租约失败: %v", err)
	}
	leaseB, err := db.AcquireZhiziLease(ctx, "conv-zhizi-b", "user-1", time.Hour)
	if err != nil || leaseB == nil {
		t.Fatalf("释放后应可重新获取租约: lease=%+v err=%v", leaseB, err)
	}
	updatedNode := *node
	updatedNode.Name = "node-b"
	if _, err := db.UpdateZhiziNode(ctx, updatedNode, ZhiziNodeSecret{}); !errors.Is(err, ErrZhiziNodeInUse) {
		t.Fatalf("活跃租约期间更新节点应被拒绝: %v", err)
	}
	if _, err := db.DeleteZhiziNodes(ctx, []string{node.ID}); !errors.Is(err, ErrZhiziNodeInUse) {
		t.Fatalf("活跃租约期间删除节点应被拒绝: %v", err)
	}
	if stored, err := db.GetZhiziNode(ctx, node.ID); err != nil || stored == nil {
		t.Fatalf("被拒绝删除后节点仍应存在: node=%+v err=%v", stored, err)
	}
	availability, err = db.ZhiziAvailability(ctx)
	if err != nil || availability.Available != 0 || availability.ActiveSlots != 1 {
		t.Fatalf("容量统计错误: %+v err=%v", availability, err)
	}
	if err := db.SetZhiziNodeEnabled(ctx, node.ID, false); err != nil {
		t.Fatalf("停用节点失败: %v", err)
	}
	active, err := db.GetActiveZhiziLease(ctx, "conv-zhizi-b", "user-1")
	if err != nil || active != nil {
		t.Fatalf("停用节点后应释放租约: lease=%+v err=%v", active, err)
	}
	if err := db.SetZhiziNodeEnabled(ctx, node.ID, true); err != nil {
		t.Fatalf("重新启用节点失败: %v", err)
	}
	if _, err := db.AcquireZhiziLease(ctx, "conv-zhizi-b", "user-1", time.Hour); err != nil {
		t.Fatalf("重新获取租约失败: %v", err)
	}
	released, err := db.RecoverZhiziLeasesOnStartup(ctx)
	if err != nil || released == 0 {
		t.Fatalf("启动回收租约失败: released=%d err=%v", released, err)
	}
	active, err = db.GetActiveZhiziLease(ctx, "conv-zhizi-b", "user-1")
	if err != nil || active != nil {
		t.Fatalf("启动回收后不应存在活跃租约: lease=%+v err=%v", active, err)
	}
}
