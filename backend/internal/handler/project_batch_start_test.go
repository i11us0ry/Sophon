package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"sophon/internal/database"
	"sophon/internal/task"

	"github.com/gin-gonic/gin"
)

func TestStartProjectsBatchQueuesBeyondFive(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch-start.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	projectIDs := make([]string, 7)
	for index := range projectIDs {
		projectIDs[index] = fmt.Sprintf("project-%d", index)
		seedProjectForBatchStart(t, db, projectIDs[index], true)
	}

	startedCampaigns := 0
	handler := &ChatHandler{
		db:      db,
		manager: task.NewManagerWithLimit(5),
		campaignStarter: func(_, _ string) error {
			startedCampaigns++
			return nil
		},
	}
	recorder := performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{ProjectIDs: projectIDs},
		true,
	)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("批量启动失败: %d %s", recorder.Code, recorder.Body.String())
	}
	var result projectBatchStartResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if result.Created != 7 || result.Started != 7 ||
		result.Queued != 2 || result.Skipped != 0 ||
		result.Failed != 0 || result.MaxConcurrency != 5 {
		t.Fatalf("批量启动统计异常: %+v", result)
	}
	if startedCampaigns != 7 {
		t.Fatalf("应提交 7 个后台战役，实际 %d", startedCampaigns)
	}

	ready := 0
	for _, item := range result.Items {
		if item.Status != "started" || item.ConversationID == "" || item.CampaignID == "" {
			t.Fatalf("启动条目异常: %+v", item)
		}
		conversation, err := db.GetConversation(
			context.Background(),
			item.ConversationID,
			"user-1",
		)
		if err != nil {
			t.Fatalf("读取批量会话失败: %v", err)
		}
		if conversation.ProjectID != item.ProjectID || conversation.BatchID != item.CampaignID {
			t.Fatalf("批量会话绑定异常: %+v", conversation)
		}
		ready++
	}
	if ready != 7 {
		t.Fatalf("应创建 7 个批量会话，实际 %d", ready)
	}

	recorder = performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{ProjectIDs: projectIDs},
		true,
	)
	if recorder.Code != http.StatusOK ||
		!bytes.Contains(recorder.Body.Bytes(), []byte(`"skipped":7`)) {
		t.Fatalf("重复启动应全部跳过: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestStartProjectsBatchSkipsInvalidProjects(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch-start-invalid.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedProjectForBatchStart(t, db, "project-active", true)
	seedProjectForBatchStart(t, db, "project-empty", false)
	seedProjectForBatchStartWithAssetStatus(t, db, "project-inactive-asset", "inactive")
	if err := db.CreateProject(context.Background(), database.Project{
		ID:          "project-paused",
		OwnerUserID: "user-1",
		Name:        "停用项目",
		Status:      "paused",
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("创建停用项目失败: %v", err)
	}

	handler := &ChatHandler{
		db:      db,
		manager: task.NewManagerWithLimit(5),
		campaignStarter: func(_, _ string) error {
			return nil
		},
	}
	recorder := performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{
			ProjectIDs: []string{
				"project-active",
				"project-empty",
				"project-inactive-asset",
				"project-paused",
				"project-missing",
			},
		},
		true,
	)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("有效项目应启动成功: %d %s", recorder.Code, recorder.Body.String())
	}
	var result projectBatchStartResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if result.Started != 1 || result.Skipped != 4 || result.Failed != 0 {
		t.Fatalf("跳过统计异常: %+v", result)
	}
}

func TestStartProjectsBatchMarksStarterFailure(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch-start-failure.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedProjectForBatchStart(t, db, "project-failure", true)

	handler := &ChatHandler{
		db:      db,
		manager: task.NewManagerWithLimit(5),
		campaignStarter: func(_, _ string) error {
			return fmt.Errorf("scheduler unavailable")
		},
	}
	recorder := performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{ProjectIDs: []string{"project-failure"}},
		true,
	)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("创建成功但启动失败应返回 201: %d %s", recorder.Code, recorder.Body.String())
	}
	var result projectBatchStartResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if result.Created != 1 || result.Started != 0 ||
		result.Failed != 1 || result.Items[0].CampaignID == "" {
		t.Fatalf("失败统计异常: %+v", result)
	}
	campaign, err := db.GetCampaign(
		context.Background(),
		result.Items[0].CampaignID,
		"user-1",
	)
	if err != nil {
		t.Fatalf("读取失败战役异常: %v", err)
	}
	if campaign.Status != database.CampaignStatusFailed {
		t.Fatalf("启动失败后战役应标记 failed: %+v", campaign)
	}
}

func TestStartProjectsBatchValidation(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch-start-validation.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler := &ChatHandler{db: db, manager: task.NewManagerWithLimit(5)}

	if recorder := performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{},
		true,
	); recorder.Code != http.StatusBadRequest {
		t.Fatalf("空项目列表应返回 400，实际 %d", recorder.Code)
	}
	if recorder := performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{ProjectIDs: []string{"project-1"}},
		false,
	); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("未登录请求应返回 401，实际 %d", recorder.Code)
	}
}

func TestStartProjectsBatchBindsAgentRole(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch-start-role.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedProjectForBatchStart(t, db, "project-role", true)
	now := time.Now().UTC()
	if err := db.CreateAgentRole(context.Background(), database.AgentRole{
		ID:        "role-batch",
		Name:      "批量测试角色",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建角色失败: %v", err)
	}

	handler := &ChatHandler{
		db:      db,
		manager: task.NewManagerWithLimit(5),
		campaignStarter: func(_, _ string) error {
			return nil
		},
	}
	recorder := performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{
			ProjectIDs: []string{"project-role"},
			RoleID:     "role-batch",
		},
		true,
	)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("带角色批量启动失败: %d %s", recorder.Code, recorder.Body.String())
	}
	var result projectBatchStartResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(result.Items) != 1 || result.Items[0].ConversationID == "" {
		t.Fatalf("批量启动条目异常: %+v", result)
	}
	conversation, err := db.GetConversation(
		context.Background(),
		result.Items[0].ConversationID,
		"user-1",
	)
	if err != nil {
		t.Fatalf("读取批量会话失败: %v", err)
	}
	if conversation.AgentRoleID != "role-batch" {
		t.Fatalf("批量会话角色绑定异常: %+v", conversation)
	}

	recorder = performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{
			ProjectIDs: []string{"project-role"},
			RoleID:     "role-missing",
		},
		true,
	)
	if recorder.Code != http.StatusBadRequest ||
		!bytes.Contains(recorder.Body.Bytes(), []byte(`"code":"invalid_agent_role"`)) {
		t.Fatalf("非法角色应返回 400: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestStartProjectsBatchEnablesZhizi(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch-start-zhizi.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedProjectForBatchStart(t, db, "project-zhizi", true)
	node, err := db.CreateZhiziNode(
		context.Background(),
		database.ZhiziNode{
			CreatedByUserID:    "user-1",
			Name:               "node-batch-start",
			Host:               "10.0.0.10",
			Port:               22,
			Username:           "root",
			AuthType:           "key",
			HostKeyFingerprint: "SHA256:n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg",
			WorkRoot:           "/home/sophon/sophon",
			MaxSlots:           1,
			Enabled:            true,
		},
		database.ZhiziNodeSecret{PrivateKey: "unused"},
	)
	if err != nil {
		t.Fatalf("创建智子节点失败: %v", err)
	}
	if err := db.RecordZhiziNodeTest(context.Background(), node.ID, nil); err != nil {
		t.Fatalf("记录智子节点测试成功失败: %v", err)
	}

	handler := &ChatHandler{
		db:      db,
		manager: task.NewManagerWithLimit(5),
		campaignStarter: func(_, _ string) error {
			return nil
		},
	}
	recorder := performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{
			ProjectIDs: []string{"project-zhizi"},
			UseZhizi:   true,
		},
		true,
	)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("启用智子批量启动失败: %d %s", recorder.Code, recorder.Body.String())
	}
	var result projectBatchStartResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if result.Started != 1 || len(result.Items) != 1 {
		t.Fatalf("批量启动统计异常: %+v", result)
	}
	state, err := db.GetZhiziConversationState(
		context.Background(),
		result.Items[0].ConversationID,
		"user-1",
	)
	if err != nil {
		t.Fatalf("读取智子会话状态失败: %v", err)
	}
	if !state.Enabled {
		t.Fatalf("批量启动会话未启用智子分身: %+v", state)
	}
}

func TestStartProjectsBatchRejectsZhiziWithoutCapacity(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch-start-zhizi-empty.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedProjectForBatchStart(t, db, "project-zhizi-empty", true)
	handler := &ChatHandler{db: db, manager: task.NewManagerWithLimit(5)}
	recorder := performProjectBatchStartRequest(
		t,
		handler,
		projectBatchStartRequest{
			ProjectIDs: []string{"project-zhizi-empty"},
			UseZhizi:   true,
		},
		true,
	)
	if recorder.Code != http.StatusConflict ||
		!bytes.Contains(recorder.Body.Bytes(), []byte(`"code":"zhizi_no_capacity"`)) {
		t.Fatalf("无智子容量应返回 409: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestStopProjectBatchConversationStopsCampaign(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "project-batch-stop.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	seedProjectForBatchStart(t, db, "project-stop", true)

	now := time.Now().UTC()
	const conversationID = "conversation-stop"
	const campaignID = "campaign-stop"
	if err := db.CreateProjectSessionCampaign(
		context.Background(),
		database.ConversationBatch{
			ID:          campaignID,
			OwnerUserID: "user-1",
			ProjectID:   "project-stop",
			Title:       "停止测试",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		database.Conversation{
			ID:          conversationID,
			OwnerUserID: "user-1",
			ProjectID:   "project-stop",
			Title:       "停止测试",
			CreatedAt:   now,
			UpdatedAt:   now,
		},
		"执行测试并停止",
	); err != nil {
		t.Fatalf("创建项目会话失败: %v", err)
	}

	handler := &ChatHandler{db: db, manager: task.NewManagerWithLimit(5)}
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(
		http.MethodPost,
		"/api/conversations/"+conversationID+"/stop",
		nil,
	)
	ginCtx.Params = gin.Params{{Key: "id", Value: conversationID}}
	ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler.StopConversation(ginCtx)

	if recorder.Code != http.StatusOK ||
		!bytes.Contains(recorder.Body.Bytes(), []byte(`"campaignStopped":true`)) {
		t.Fatalf("停止项目会话失败: %d %s", recorder.Code, recorder.Body.String())
	}
	campaign, err := db.GetCampaign(context.Background(), campaignID, "user-1")
	if err != nil {
		t.Fatalf("读取战役失败: %v", err)
	}
	if campaign.Status != database.CampaignStatusStopped {
		t.Fatalf("项目会话内部战役应停止，实际 %s", campaign.Status)
	}
}

func seedProjectForBatchStart(t *testing.T, db *database.DB, projectID string, withAsset bool) {
	t.Helper()
	status := ""
	if withAsset {
		status = "active"
	}
	seedProjectForBatchStartWithAssetStatus(t, db, projectID, status)
}

func seedProjectForBatchStartWithAssetStatus(
	t *testing.T,
	db *database.DB,
	projectID string,
	status string,
) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          projectID,
		OwnerUserID: "user-1",
		Name:        projectID,
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if status == "" {
		return
	}
	if err := db.CreateAsset(ctx, database.Asset{
		ID:          "asset-" + projectID,
		ProjectID:   projectID,
		OwnerUserID: "user-1",
		Name:        projectID,
		Kind:        "domain",
		Value:       projectID + ".example.com",
		Status:      status,
		Criticality: "medium",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
}

func performProjectBatchStartRequest(
	t *testing.T,
	handler *ChatHandler,
	payload projectBatchStartRequest,
	withUser bool,
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
		http.MethodPost,
		"/api/projects/batch-start",
		bytes.NewReader(body),
	)
	ginCtx.Request.Header.Set("Content-Type", "application/json")
	if withUser {
		ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	}
	handler.StartProjectsBatch(ginCtx)
	return recorder
}
