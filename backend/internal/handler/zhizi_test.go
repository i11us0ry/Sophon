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
	"time"

	"sophon/internal/database"
	zhizipkg "sophon/internal/zhizi"

	"github.com/gin-gonic/gin"
)

func TestZhiziNodeHandlerDoesNotExposeCredentials(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "zhizi-handler.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler := NewZhiziHandler(db, zhizipkg.NewExecutor(db))
	gin.SetMode(gin.TestMode)

	payload := `{
		"name":"node-a",
		"host":"10.0.0.10",
		"port":22,
		"username":"root",
		"authType":"key",
		"privateKey":"-----BEGIN PRIVATE KEY-----\nPRIVATE-CONTENT\n-----END PRIVATE KEY-----",
		"hostFingerprint":"SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
		"workRoot":"/home/sophon/sophon",
		"maxSlots":2,
		"enabled":true
	}`
	createRecorder := httptest.NewRecorder()
	createCtx, _ := gin.CreateTestContext(createRecorder)
	createCtx.Request = httptest.NewRequest(http.MethodPost, "/api/zhizi/nodes", bytes.NewBufferString(payload))
	createCtx.Request.Header.Set("Content-Type", "application/json")
	createCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "admin", Role: "admin", Enabled: true})
	handler.Create(createCtx)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("创建智子节点失败: %d %s", createRecorder.Code, createRecorder.Body.String())
	}

	listRecorder := httptest.NewRecorder()
	listCtx, _ := gin.CreateTestContext(listRecorder)
	listCtx.Request = httptest.NewRequest(http.MethodGet, "/api/zhizi/nodes", nil)
	handler.List(listCtx)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("读取智子节点失败: %d %s", listRecorder.Code, listRecorder.Body.String())
	}
	body := listRecorder.Body.String()
	if strings.Contains(body, "PRIVATE-CONTENT") || strings.Contains(body, "privateKey") {
		t.Fatalf("节点列表泄露了 SSH 凭据: %s", body)
	}
	var response struct {
		Items []database.ZhiziNode `json:"items"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析节点列表失败: %v", err)
	}
	if len(response.Items) != 1 || response.Items[0].Name != "node-a" {
		t.Fatalf("节点列表内容错误: %+v", response.Items)
	}
}

func TestZhiziHandlerCreatesMultiplePasswordNodes(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "zhizi-multi.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler := NewZhiziHandler(db, zhizipkg.NewExecutor(db))
	gin.SetMode(gin.TestMode)
	payload := `{
		"name":"prod",
		"hosts":["10.0.0.1","10.0.0.2","10.0.0.1"],
		"port":22,
		"username":"root",
		"authType":"password",
		"password":"secret",
		"hostFingerprints":{
			"10.0.0.1":"SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
			"10.0.0.2":"SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg"
		},
		"workRoot":"/home/sophon/sophon",
		"maxSlots":1,
		"enabled":true
	}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/zhizi/nodes", bytes.NewBufferString(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("sophon.user", &database.User{ID: "user-1", Username: "admin", Role: "admin", Enabled: true})
	handler.Create(ctx)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("批量创建智子节点失败: %d %s", recorder.Code, recorder.Body.String())
	}
	items, err := db.ListZhiziNodes(context.Background())
	if err != nil {
		t.Fatalf("读取批量节点失败: %v", err)
	}
	if len(items) != 2 || items[0].Name == items[1].Name {
		t.Fatalf("批量节点数量或名称错误: %+v", items)
	}
	for _, item := range items {
		if item.AuthType != "password" || !strings.Contains(item.Name, "prod-") {
			t.Fatalf("批量节点字段错误: %+v", item)
		}
	}
	var passwordCipher, privateKeyCipher string
	if err := db.QueryRowContext(
		context.Background(),
		`SELECT password_cipher, private_key_cipher FROM zhizi_nodes WHERE id = ?`,
		items[0].ID,
	).Scan(&passwordCipher, &privateKeyCipher); err != nil {
		t.Fatalf("读取批量凭据失败: %v", err)
	}
	if !strings.HasPrefix(passwordCipher, "enc:v1:") || privateKeyCipher != "" {
		t.Fatalf("批量密码凭据存储错误: password=%q privateKey=%q", passwordCipher, privateKeyCipher)
	}
}

func TestZhiziHandlerRejectsBatchPrivateKeyNodes(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "zhizi-multi-key.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler := NewZhiziHandler(db, zhizipkg.NewExecutor(db))
	gin.SetMode(gin.TestMode)
	payload := `{
		"name":"prod",
		"hosts":["10.0.0.1","10.0.0.2"],
		"port":22,
		"username":"root",
		"authType":"key",
		"privateKey":"key",
		"hostFingerprint":"SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
		"workRoot":"/home/sophon/sophon",
		"maxSlots":1,
		"enabled":true
	}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/zhizi/nodes", bytes.NewBufferString(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("sophon.user", &database.User{ID: "user-1", Username: "admin", Role: "admin", Enabled: true})
	handler.Create(ctx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("私钥认证批量创建应被拒绝: %d %s", recorder.Code, recorder.Body.String())
	}
	items, err := db.ListZhiziNodes(context.Background())
	if err != nil || len(items) != 0 {
		t.Fatalf("拒绝批量私钥后不应写入节点: %+v err=%v", items, err)
	}
}

func TestZhiziHandlerRejectsUpdateWhileNodeInUse(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "zhizi-update-in-use.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID: "project-zhizi-update", OwnerUserID: "user-1", Name: "project",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conv-zhizi-update", OwnerUserID: "user-1", ProjectID: "project-zhizi-update",
		Title: "conv", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	node, err := db.CreateZhiziNode(ctx, database.ZhiziNode{
		CreatedByUserID: "user-1", Name: "node-update", Host: "10.0.0.10", Port: 22,
		Username: "root", AuthType: "key",
		HostKeyFingerprint: "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
		WorkRoot:           "/home/sophon/sophon", MaxSlots: 1, Enabled: true,
	}, database.ZhiziNodeSecret{PrivateKey: "unused"})
	if err != nil {
		t.Fatalf("创建节点失败: %v", err)
	}
	if err := db.RecordZhiziNodeTest(ctx, node.ID, nil); err != nil {
		t.Fatalf("记录节点测试成功失败: %v", err)
	}
	if err := db.SetZhiziConversationEnabled(ctx, "conv-zhizi-update", "user-1", true); err != nil {
		t.Fatalf("启用对话智子失败: %v", err)
	}
	if _, err := db.AcquireZhiziLease(ctx, "conv-zhizi-update", "user-1", time.Minute); err != nil {
		t.Fatalf("获取租约失败: %v", err)
	}
	handler := NewZhiziHandler(db, zhizipkg.NewExecutor(db))
	payload := `{
		"name":"node-update-renamed",
		"host":"10.0.0.10",
		"port":22,
		"username":"root",
		"authType":"key",
		"hostFingerprint":"SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
		"workRoot":"/home/sophon/sophon",
		"maxSlots":1,
		"enabled":true
	}`
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(
		http.MethodPut,
		"/api/zhizi/nodes/"+node.ID,
		strings.NewReader(payload),
	)
	ginCtx.Request.Header.Set("Content-Type", "application/json")
	ginCtx.Params = gin.Params{{Key: "id", Value: node.ID}}
	handler.Update(ginCtx)
	if recorder.Code != http.StatusConflict ||
		!strings.Contains(recorder.Body.String(), `"code":"zhizi_node_in_use"`) {
		t.Fatalf("使用中的节点更新应返回 409: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestZhiziHandlerBatchTestsSelectedNodes(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "zhizi-batch-test.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler := NewZhiziHandler(db, zhizipkg.NewExecutor(db))
	gin.SetMode(gin.TestMode)
	nodes, err := db.CreateZhiziNodes(context.Background(), []database.ZhiziNode{
		{
			ID: "node-a", CreatedByUserID: "user-1", Name: "node-a",
			Host: "127.0.0.1", Port: 1, Username: "root", AuthType: "password",
			HostKeyFingerprint: "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
			WorkRoot:           "/tmp/sophon", MaxSlots: 1, Enabled: true,
		},
		{
			ID: "node-b", CreatedByUserID: "user-1", Name: "node-b",
			Host: "127.0.0.1", Port: 1, Username: "root", AuthType: "password",
			HostKeyFingerprint: "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
			WorkRoot:           "/tmp/sophon", MaxSlots: 1, Enabled: true,
		},
	}, database.ZhiziNodeSecret{Password: "secret"})
	if err != nil {
		t.Fatalf("创建测试节点失败: %v", err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodPost,
		"/api/zhizi/nodes/test",
		bytes.NewBufferString(`{"ids":["node-a","node-b"]}`),
	)
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler.TestBatch(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("批量测试请求失败: %d %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Total     int `json:"total"`
		Succeeded int `json:"succeeded"`
		Failed    int `json:"failed"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("解析批量测试结果失败: %v", err)
	}
	if response.Total != len(nodes) || response.Succeeded != 0 || response.Failed != len(nodes) {
		t.Fatalf("批量测试统计错误: %+v", response)
	}
	var failed int
	if err := db.QueryRowContext(
		context.Background(),
		`SELECT COUNT(*) FROM zhizi_nodes WHERE id IN ('node-a','node-b') AND last_test_error <> ''`,
	).Scan(&failed); err != nil {
		t.Fatalf("读取批量测试结果失败: %v", err)
	}
	if failed != len(nodes) {
		t.Fatalf("批量测试结果未写回节点: %d", failed)
	}
}

func TestZhiziHandlerBatchInitializeAndDeleteSelectedNodes(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "zhizi-batch-ops.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler := NewZhiziHandler(db, zhizipkg.NewExecutor(db))
	gin.SetMode(gin.TestMode)
	nodes := make([]database.ZhiziNode, 0, 5)
	for index := 0; index < 5; index++ {
		nodes = append(nodes, database.ZhiziNode{
			ID:                 "init-node-" + string(rune('a'+index)),
			CreatedByUserID:    "user-1",
			Name:               "init-node-" + string(rune('a'+index)),
			Host:               "127.0.0.1",
			Port:               1,
			Username:           "root",
			AuthType:           "password",
			HostKeyFingerprint: "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
			WorkRoot:           "/tmp/sophon",
			MaxSlots:           1,
			Enabled:            true,
		})
	}
	if _, err := db.CreateZhiziNodes(
		context.Background(),
		nodes,
		database.ZhiziNodeSecret{Password: "secret"},
	); err != nil {
		t.Fatalf("创建测试节点失败: %v", err)
	}
	ids := make([]string, 0, len(nodes))
	for _, node := range nodes {
		ids = append(ids, node.ID)
	}
	body, _ := json.Marshal(map[string]interface{}{"ids": ids})
	initRecorder := httptest.NewRecorder()
	initCtx, _ := gin.CreateTestContext(initRecorder)
	initCtx.Request = httptest.NewRequest(
		http.MethodPost,
		"/api/zhizi/nodes/init",
		bytes.NewReader(body),
	)
	initCtx.Request.Header.Set("Content-Type", "application/json")
	handler.InitializeBatch(initCtx)
	if initRecorder.Code != http.StatusAccepted {
		t.Fatalf("批量初始化提交失败: %d %s", initRecorder.Code, initRecorder.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var running int
		if err := db.QueryRowContext(
			context.Background(),
			`SELECT COUNT(*) FROM zhizi_nodes WHERE init_status IN ('queued', 'running')`,
		).Scan(&running); err != nil {
			t.Fatalf("读取初始化状态失败: %v", err)
		}
		if running == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	deleteRecorder := httptest.NewRecorder()
	deleteCtx, _ := gin.CreateTestContext(deleteRecorder)
	deleteCtx.Request = httptest.NewRequest(
		http.MethodPost,
		"/api/zhizi/nodes/delete",
		bytes.NewReader(body),
	)
	deleteCtx.Request.Header.Set("Content-Type", "application/json")
	handler.DeleteBatch(deleteCtx)
	if deleteRecorder.Code != http.StatusOK {
		t.Fatalf("批量删除失败: %d %s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	remaining, err := db.ListZhiziNodes(context.Background())
	if err != nil || len(remaining) != 0 {
		t.Fatalf("批量删除后仍存在节点: %+v err=%v", remaining, err)
	}
}
