package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func callCampaignP2Handler(
	t *testing.T,
	handler *ChatHandler,
	method string,
	path string,
	body string,
	params gin.Params,
	run func(*gin.Context),
) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginCtx.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	ginCtx.Request.Header.Set("Content-Type", "application/json")
	ginCtx.Params = params
	ginCtx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	run(ginCtx)
	return recorder
}

func TestCampaignP2Handlers(t *testing.T) {
	handler, campaignID, _ := seedCampaignP1Handler(t)
	groups, err := handler.db.ListCampaignGroups(t.Context(), campaignID)
	if err != nil || len(groups) == 0 {
		t.Fatalf("读取资产组失败: groups=%+v err=%v", groups, err)
	}
	priority := callCampaignP2Handler(
		t,
		handler,
		http.MethodPut,
		"/api/conversation-batches/"+campaignID+"/groups/"+groups[0].ID+"/priority",
		`{"businessSystem":"核心交易系统","businessPriority":95}`,
		gin.Params{
			{Key: "id", Value: campaignID},
			{Key: "groupId", Value: groups[0].ID},
		},
		handler.SetCampaignGroupPriority,
	)
	if priority.Code != http.StatusOK ||
		!strings.Contains(priority.Body.String(), "核心交易系统") {
		t.Fatalf("业务优先级接口异常: status=%d body=%s", priority.Code, priority.Body.String())
	}

	links, err := handler.db.ListCampaignLinks(t.Context(), campaignID, 10)
	if err != nil || len(links) == 0 {
		t.Fatalf("读取测试关系失败: links=%+v err=%v", links, err)
	}
	if _, err := handler.db.GenerateCampaignChains(t.Context(), campaignID); err != nil {
		t.Fatalf("生成攻击链失败: %v", err)
	}
	chains := callCampaignP2Handler(
		t,
		handler,
		http.MethodGet,
		"/api/conversation-batches/"+campaignID+"/chains",
		"",
		gin.Params{{Key: "id", Value: campaignID}},
		handler.ListCampaignChains,
	)
	if chains.Code != http.StatusOK ||
		!strings.Contains(chains.Body.String(), "finding_pivot") {
		t.Fatalf("攻击链接口异常: status=%d body=%s", chains.Code, chains.Body.String())
	}

	if err := handler.db.RefreshCampaignMemory(t.Context(), campaignID); err != nil {
		t.Fatalf("刷新长期记忆失败: %v", err)
	}
	memory := callCampaignP2Handler(
		t,
		handler,
		http.MethodGet,
		"/api/conversation-batches/"+campaignID+"/memory?keyword=战役",
		"",
		gin.Params{{Key: "id", Value: campaignID}},
		handler.QueryCampaignMemory,
	)
	if memory.Code != http.StatusOK || !strings.Contains(memory.Body.String(), "战役") {
		t.Fatalf("长期记忆接口异常: status=%d body=%s", memory.Code, memory.Body.String())
	}

	recompute := callCampaignP2Handler(
		t,
		handler,
		http.MethodPost,
		"/api/conversation-batches/"+campaignID+"/priority/recompute",
		"{}",
		gin.Params{{Key: "id", Value: campaignID}},
		handler.RecomputeCampaignPriorities,
	)
	if recompute.Code != http.StatusOK {
		t.Fatalf("调度重算接口异常: status=%d body=%s", recompute.Code, recompute.Body.String())
	}

	stop := callCampaignP2Handler(
		t,
		handler,
		http.MethodPost,
		"/api/conversation-batches/"+campaignID+"/stop",
		"{}",
		gin.Params{{Key: "id", Value: campaignID}},
		handler.StopCampaign,
	)
	if stop.Code != http.StatusOK || !strings.Contains(stop.Body.String(), "stopped") {
		t.Fatalf("停止战役接口异常: status=%d body=%s", stop.Code, stop.Body.String())
	}
	campaign, err := handler.db.GetCampaign(t.Context(), campaignID, "user-1")
	if err != nil || campaign.Status != database.CampaignStatusStopped {
		t.Fatalf("停止状态未落库: campaign=%+v err=%v", campaign, err)
	}
}
