package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func seedCampaignP1Handler(t *testing.T) (*ChatHandler, string, string) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "campaign-p1-handler.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := context.Background()
	now := time.Now().UTC()
	const projectID = "handler-p1-project"
	if err := db.CreateProject(ctx, database.Project{
		ID:          projectID,
		OwnerUserID: "user-1",
		Name:        "Handler P1",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	asset := database.Asset{
		ID:          "handler-p1-asset",
		ProjectID:   projectID,
		OwnerUserID: "user-1",
		Name:        "目标",
		Kind:        "url",
		Value:       "https://handler-p1.example.com/",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	peer := asset
	peer.ID = "handler-p1-peer"
	peer.Value = "https://handler-p1.example.com/admin"
	parent := database.Conversation{
		ID:          "handler-p1-parent",
		OwnerUserID: "user-1",
		ProjectID:   projectID,
		Title:       "Handler P1",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	const campaignID = "handler-p1-campaign"
	if _, _, err := db.CreateConversationBatch(
		ctx,
		database.ConversationBatch{
			ID:                   campaignID,
			OwnerUserID:          "user-1",
			ProjectID:            projectID,
			ParentConversationID: parent.ID,
			Title:                "Handler P1",
			Instruction:          "验证目标",
			Total:                2,
			CreatedAt:            now,
			UpdatedAt:            now,
		},
		parent,
		[]database.ConversationBatchItem{
			{
				Asset: asset,
				Conversation: database.Conversation{
					ID:          "handler-p1-child-a",
					OwnerUserID: "user-1",
					ProjectID:   projectID,
					Title:       "目标",
					CreatedAt:   now,
					UpdatedAt:   now,
				},
			},
			{
				Asset: peer,
				Conversation: database.Conversation{
					ID:          "handler-p1-child-b",
					OwnerUserID: "user-1",
					ProjectID:   projectID,
					Title:       "管理端",
					CreatedAt:   now,
					UpdatedAt:   now,
				},
			},
		},
		"",
		false,
	); err != nil {
		t.Fatalf("创建 Campaign 失败: %v", err)
	}
	if _, err := db.EnqueueFindingVerification(
		ctx,
		campaignID,
		"handler-p1-finding",
		asset.ID,
		"critical",
		"命令注入",
	); err != nil {
		t.Fatalf("创建验证任务失败: %v", err)
	}
	if _, err := db.CreateCampaignLink(ctx, database.CampaignLink{
		CampaignID: campaignID,
		ProjectID:  projectID,
		SrcAssetID: asset.ID,
		DstAssetID: peer.ID,
		Kind:       "shared_infra",
		Summary:    "共享网关",
		Confidence: 90,
	}); err != nil {
		t.Fatalf("创建跨资产关系失败: %v", err)
	}
	return &ChatHandler{db: db}, campaignID, asset.ID
}

func callCampaignP1Handler(
	t *testing.T,
	handler *ChatHandler,
	method string,
	path string,
	campaignID string,
	run func(*gin.Context),
) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(method, path, nil)
	ginCtx.Params = gin.Params{{Key: "id", Value: campaignID}}
	ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	run(ginCtx)
	return recorder
}

func TestCampaignP1Handlers(t *testing.T) {
	handler, campaignID, _ := seedCampaignP1Handler(t)

	status := callCampaignP1Handler(
		t,
		handler,
		http.MethodGet,
		"/api/conversation-batches/"+campaignID+"/status",
		campaignID,
		handler.GetCampaignStatus,
	)
	if status.Code != http.StatusOK ||
		!strings.Contains(status.Body.String(), `"pendingFrontier":1`) ||
		!strings.Contains(status.Body.String(), `"pendingVerification":1`) ||
		!strings.Contains(status.Body.String(), `"linkCount":1`) {
		t.Fatalf("状态接口缺少 P1 统计: status=%d body=%s", status.Code, status.Body.String())
	}

	cases := []struct {
		name string
		path string
		run  func(*gin.Context)
		want string
	}{
		{
			name: "frontier",
			path: "/api/conversation-batches/" + campaignID + "/frontier",
			run:  handler.ListCampaignFrontier,
			want: `"kind":"verify_finding"`,
		},
		{
			name: "verifications",
			path: "/api/conversation-batches/" + campaignID + "/verifications",
			run:  handler.ListCampaignVerifications,
			want: `"findingId":"handler-p1-finding"`,
		},
		{
			name: "links",
			path: "/api/conversation-batches/" + campaignID + "/links",
			run:  handler.ListCampaignLinks,
			want: `"kind":"shared_infra"`,
		},
	}
	for _, item := range cases {
		recorder := callCampaignP1Handler(
			t,
			handler,
			http.MethodGet,
			item.path,
			campaignID,
			item.run,
		)
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), item.want) {
			t.Fatalf("%s 接口异常: status=%d body=%s", item.name, recorder.Code, recorder.Body.String())
		}
	}

	recompute := callCampaignP1Handler(
		t,
		handler,
		http.MethodPost,
		"/api/conversation-batches/"+campaignID+"/priority/recompute",
		campaignID,
		handler.RecomputeCampaignPriorities,
	)
	if recompute.Code != http.StatusOK {
		t.Fatalf("重算优先级接口异常: status=%d body=%s", recompute.Code, recompute.Body.String())
	}
}
