package agent

import (
	"context"
	"testing"
	"time"

	"sophon/internal/database"
)

func TestMissionScopeUsesLatestUserTarget(t *testing.T) {
	service, ctx := openProjectToolService(t, true)
	if _, err := invokeProjectTool(t, service, ctx, "project_insert_assets", map[string]interface{}{
		"assets_json": `[{"name":"Falcon","kind":"url","value":"https://falcon.example.com","criticality":"high"}]`,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if err := service.db.AddMessage(context.Background(), database.Message{
		ID: "scope-user", ConversationID: "conv-tools", Role: "user",
		Content: "深入挖掘 falcon.example.com 的 user_info 接口", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("写入用户消息失败: %v", err)
	}
	scope := service.missionScopeForConversation(ctx, "conv-tools")
	if !scope.Active || len(scope.Hosts) != 1 || scope.Hosts[0] != "falcon.example.com" {
		t.Fatalf("任务范围识别错误: %+v", scope)
	}
	if len(scope.AssetIDs) != 1 {
		t.Fatalf("任务范围资产未匹配: %+v", scope)
	}
	if !scope.IncludesNode(database.GraphNode{
		Title: "攻坚 falcon.example.com /falcon/user_info/*",
	}) {
		t.Fatalf("目标节点应属于当前任务范围")
	}
	if scope.IncludesNode(database.GraphNode{Title: "无关资产 other.example.com"}) {
		t.Fatalf("无关节点不应属于当前任务范围")
	}
}
