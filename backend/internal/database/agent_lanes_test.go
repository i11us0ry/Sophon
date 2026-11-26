package database

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnsureAgentLaneConversationsMigratesDeepAndCreatesFast(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "agent-lanes.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-lanes",
		OwnerUserID: "user-1",
		Name:        "双通道项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID:          "conv-deep-existing",
		OwnerUserID: "user-1",
		ProjectID:   "project-lanes",
		Title:       "旧协调会话",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建旧会话失败: %v", err)
	}
	if err := db.SetConversationAgentMode(ctx, "conv-deep-existing", "deep"); err != nil {
		t.Fatalf("保存旧会话模式失败: %v", err)
	}

	lanes, err := db.EnsureAgentLaneConversations(ctx, "user-1", "project-lanes")
	if err != nil {
		t.Fatalf("创建主 Agent 通道失败: %v", err)
	}
	if lanes.Coordinated.ID != "conv-deep-existing" {
		t.Fatalf("应复用已有协调会话: %+v", lanes.Coordinated)
	}
	if lanes.Coordinated.ExecutionLane != ConversationLaneCoordinated ||
		lanes.Fast.ExecutionLane != ConversationLaneFast ||
		lanes.Fast.ID == "" ||
		lanes.Fast.ID == lanes.Coordinated.ID {
		t.Fatalf("主 Agent 通道结果错误: coordinated=%+v fast=%+v", lanes.Coordinated, lanes.Fast)
	}
	if lanes.Coordinated.Title != "旧协调会话" {
		t.Fatalf("迁移不应覆盖用户标题: %q", lanes.Coordinated.Title)
	}
	if len(lanes.Changes) != 2 ||
		!strings.Contains(lanes.Changes[0], "coordinated=migrated") ||
		!strings.Contains(lanes.Changes[1], "fast=created") {
		t.Fatalf("通道初始化变更审计信息错误: %+v", lanes.Changes)
	}

	again, err := db.EnsureAgentLaneConversations(ctx, "user-1", "project-lanes")
	if err != nil {
		t.Fatalf("重复创建主 Agent 通道失败: %v", err)
	}
	if again.Coordinated.ID != lanes.Coordinated.ID || again.Fast.ID != lanes.Fast.ID {
		t.Fatalf("主 Agent 通道创建应幂等: first=%+v second=%+v", lanes, again)
	}
	var count int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM conversations
		 WHERE owner_user_id = ? AND project_id = ?
		   AND execution_lane IN (?, ?)`,
		"user-1",
		"project-lanes",
		ConversationLaneCoordinated,
		ConversationLaneFast,
	).Scan(&count); err != nil {
		t.Fatalf("统计主 Agent 通道失败: %v", err)
	}
	if count != 2 {
		t.Fatalf("主 Agent 通道数量错误: %d", count)
	}
	if err := EnsureCoreAgentSessions(ctx, db, lanes.Fast.ID); err != nil {
		t.Fatalf("初始化 Fast 主 Agent 会话失败: %v", err)
	}
	fastSessions, err := db.ListAgentSessions(ctx, lanes.Fast.ID)
	if err != nil {
		t.Fatalf("读取 Fast Agent Sessions 失败: %v", err)
	}
	if len(fastSessions) != 1 || fastSessions[0].Role != AgentRoleMain {
		t.Fatalf("Fast 通道不应生成 Planner/System 占位会话: %+v", fastSessions)
	}
}

func TestEnsureAgentLaneConversationsConcurrentIdempotent(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "agent-lanes-concurrent.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID:          "project-lanes-concurrent",
		OwnerUserID: "user-1",
		Name:        "并发通道项目",
		Status:      "active",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}

	results := make(chan AgentLaneConversations, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for index := 0; index < 2; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lanes, err := db.EnsureAgentLaneConversations(
				context.Background(),
				"user-1",
				"project-lanes-concurrent",
			)
			results <- lanes
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("并发初始化主 Agent 通道失败: %v", err)
		}
	}
	var first AgentLaneConversations
	for lanes := range results {
		if first.Coordinated == nil {
			first = lanes
			continue
		}
		if first.Coordinated.ID != lanes.Coordinated.ID || first.Fast.ID != lanes.Fast.ID {
			t.Fatalf("并发初始化结果不一致: first=%+v second=%+v", first, lanes)
		}
	}
}
