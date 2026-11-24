package database

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentSessionMigrationBackfillsLegacyProcessDetails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-agent-sessions.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("打开旧数据库失败: %v", err)
	}
	now := time.Now().UTC().Unix()
	if _, err := legacy.Exec(`
		CREATE TABLE conversations (
			id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, title TEXT NOT NULL,
			created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
		);
		CREATE TABLE process_details (
			id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, message_id TEXT,
			event_type TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',
			data TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
		);
		INSERT INTO conversations(id, owner_user_id, title, created_at, updated_at)
		VALUES ('conv-legacy', 'user-1', '旧会话', ?, ?);
		INSERT INTO process_details(id, conversation_id, message_id, event_type, message, data, created_at)
		VALUES ('planner-legacy', 'conv-legacy', 'msg-1', 'subagent.started', 'Planner 已启动',
			'{"agentId":"planner-1","agentKind":"planner","status":"running"}', ?);
		INSERT INTO process_details(id, conversation_id, message_id, event_type, message, data, created_at)
		VALUES ('invalid-legacy', 'conv-legacy', 'msg-1', 'tool_call', '旧数据', 'not-json', ?);
	`, now, now, now, now); err != nil {
		_ = legacy.Close()
		t.Fatalf("创建旧表失败: %v", err)
	}
	_ = legacy.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("迁移旧数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	var sessionID string
	if err := db.QueryRow(
		`SELECT session_id FROM process_details WHERE id = 'planner-legacy'`,
	).Scan(&sessionID); err != nil {
		t.Fatalf("读取迁移后的 session_id 失败: %v", err)
	}
	if sessionID != "planner:conv-legacy" {
		t.Fatalf("旧事件 session_id 回填错误: %s", sessionID)
	}
	var invalidSessionID string
	if err := db.QueryRow(
		`SELECT session_id FROM process_details WHERE id = 'invalid-legacy'`,
	).Scan(&invalidSessionID); err != nil {
		t.Fatalf("读取非法旧数据 session_id 失败: %v", err)
	}
	if invalidSessionID != "main:conv-legacy" {
		t.Fatalf("非法旧数据应回退到主 Agent Session: %s", invalidSessionID)
	}
	var role string
	if err := db.QueryRow(
		`SELECT role FROM agent_sessions WHERE id = ?`,
		sessionID,
	).Scan(&role); err != nil {
		t.Fatalf("迁移后缺少 Planner Session: %v", err)
	}
	if role != AgentRolePlanner {
		t.Fatalf("Planner Session 角色错误: %s", role)
	}
}

func TestAgentSessionsSeparateRolesAndPageHistory(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "agent-sessions.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-session", OwnerUserID: "user-1", Name: "会话测试",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-session", OwnerUserID: "user-1", ProjectID: "project-session",
		Title: "Agent Session", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	details := []ProcessDetail{
		{
			ID: "main-1", ConversationID: "conv-session", MessageID: "msg-1",
			EventType: "tool_call",
			Message:   "project_list",
			Data: map[string]interface{}{
				"agentId": "mainagent", "agentKind": "mainagent", "toolCallId": "call-1",
			},
			CreatedAt: now,
		},
		{
			ID: "planner-1", ConversationID: "conv-session", MessageID: "msg-1",
			EventType: "subagent.started",
			Message:   "Planner 已启动",
			Data: map[string]interface{}{
				"agentId": "planner-1", "agentKind": "planner", "status": "running",
			},
			CreatedAt: now.Add(time.Second),
		},
		{
			ID: "worker-1", ConversationID: "conv-session", MessageID: "msg-1",
			EventType: "tool_call",
			Message:   "exec",
			Data: map[string]interface{}{
				"agentId": "worker-1", "agentKind": "worker", "hypothesisId": "hyp-1",
				"workerFocus": "上传审计",
			},
			CreatedAt: now.Add(2 * time.Second),
		},
	}
	if err := db.AddProcessDetails(ctx, details); err != nil {
		t.Fatalf("写入过程明细失败: %v", err)
	}
	if err := db.AddProcessDetail(ctx, details[2]); err != nil {
		t.Fatalf("重复写入过程明细失败: %v", err)
	}
	sessions, err := db.ListAgentSessions(ctx, "conv-session")
	if err != nil {
		t.Fatalf("读取 Agent Session 失败: %v", err)
	}
	byRole := map[string]AgentSession{}
	for _, session := range sessions {
		byRole[session.Role] = session
	}
	if byRole[AgentRoleMain].ActivityCount != 1 ||
		byRole[AgentRolePlanner].ActivityCount != 1 ||
		byRole[AgentRolePlanner].Status != "running" ||
		byRole[AgentRoleWorker].ActivityCount != 1 ||
		byRole[AgentRoleWorker].Title != "上传审计" {
		t.Fatalf("Agent Session 统计错误: %+v", sessions)
	}
	workerID := AgentSessionID("conv-session", AgentRoleWorker, "worker-1", "hyp-1")
	items, total, hasMore, err := db.ListAgentSessionDetailsPage(
		ctx,
		"conv-session",
		workerID,
		10,
		0,
	)
	if err != nil {
		t.Fatalf("读取 Worker Session 历史失败: %v", err)
	}
	if total != 1 || hasMore || len(items) != 1 ||
		items[0].SessionID != workerID || items[0].Sequence <= 0 {
		t.Fatalf("Worker Session 历史错误: items=%+v total=%d hasMore=%v", items, total, hasMore)
	}
}

func TestPauseProjectAgentSessionsSettlesActiveRoles(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "pause-project-sessions.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-pause-sessions", OwnerUserID: "user-1", Name: "暂停会话",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-pause-sessions", OwnerUserID: "user-1", ProjectID: "project-pause-sessions",
		Title: "暂停会话", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	for _, session := range []AgentSession{
		{
			ID:             AgentSessionID("conv-pause-sessions", AgentRoleMain, "", ""),
			ConversationID: "conv-pause-sessions", Role: AgentRoleMain,
			Title: "主 Agent", Status: "running",
		},
		{
			ID:             AgentSessionID("conv-pause-sessions", AgentRolePlanner, "", ""),
			ConversationID: "conv-pause-sessions", Role: AgentRolePlanner,
			Title: "规划 Planner", Status: "waiting",
		},
		{
			ID:             AgentSessionID("conv-pause-sessions", AgentRoleWorker, "", "hyp-running"),
			ConversationID: "conv-pause-sessions", Role: AgentRoleWorker,
			Title: "Worker", Status: "running", HypothesisID: "hyp-running",
		},
		{
			ID:             AgentSessionID("conv-pause-sessions", AgentRoleWorker, "", "hyp-done"),
			ConversationID: "conv-pause-sessions", Role: AgentRoleWorker,
			Title: "Worker", Status: "completed", HypothesisID: "hyp-done",
		},
	} {
		if err := db.upsertAgentSession(ctx, session, false); err != nil {
			t.Fatalf("写入 Agent Session 失败: %v", err)
		}
	}
	affected, err := db.PauseProjectAgentSessions(
		ctx,
		"project-pause-sessions",
		"user-1",
		"[project_pause] 测试暂停",
	)
	if err != nil || affected != 3 {
		t.Fatalf("暂停项目 session 失败: affected=%d err=%v", affected, err)
	}
	items, err := db.ListAgentSessions(ctx, "conv-pause-sessions")
	if err != nil {
		t.Fatalf("读取 Agent Session 失败: %v", err)
	}
	byID := map[string]AgentSession{}
	for _, item := range items {
		byID[item.ID] = item
	}
	for _, role := range []string{AgentRoleMain, AgentRolePlanner} {
		id := AgentSessionID("conv-pause-sessions", role, "", "")
		if byID[id].Status != "paused" {
			t.Fatalf("%s 未暂停: %+v", role, byID[id])
		}
	}
	runningID := AgentSessionID("conv-pause-sessions", AgentRoleWorker, "", "hyp-running")
	doneID := AgentSessionID("conv-pause-sessions", AgentRoleWorker, "", "hyp-done")
	if byID[runningID].Status != "paused" || byID[doneID].Status != "completed" {
		t.Fatalf("Worker 状态收口错误: running=%+v done=%+v", byID[runningID], byID[doneID])
	}
}

func TestLateRunningEventCannotRestartPausedProjectSession(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "late-session-event.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-late-session", OwnerUserID: "user-1", Name: "迟到事件",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-late-session", OwnerUserID: "user-1", ProjectID: "project-late-session",
		Title: "迟到事件", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	started := ProcessDetail{
		ID: "late-start", ConversationID: "conv-late-session", MessageID: "msg-late",
		EventType: "subagent.started", Message: "Worker 已启动",
		Data: map[string]interface{}{
			"agentId": "worker-late", "agentKind": AgentRoleWorker,
			"hypothesisId": "hyp-late", "status": "running",
		},
		CreatedAt: now,
	}
	if err := db.AddProcessDetail(ctx, started); err != nil {
		t.Fatalf("写入启动事件失败: %v", err)
	}
	if _, err := db.ExecContext(
		ctx,
		`UPDATE projects SET status = 'paused' WHERE id = ?`,
		"project-late-session",
	); err != nil {
		t.Fatalf("暂停项目失败: %v", err)
	}
	if err := db.AddProcessDetail(ctx, ProcessDetail{
		ID: "late-tool", ConversationID: "conv-late-session", MessageID: "msg-late",
		EventType: "tool_call", Message: "exec",
		Data: map[string]interface{}{
			"agentId": "worker-late", "agentKind": AgentRoleWorker,
			"hypothesisId": "hyp-late", "toolCallId": "late-call", "status": "running",
		},
		CreatedAt: now.Add(time.Second),
	}); err != nil {
		t.Fatalf("写入迟到事件失败: %v", err)
	}
	sessionID := AgentSessionID("conv-late-session", AgentRoleWorker, "worker-late", "hyp-late")
	sessions, err := db.ListAgentSessions(ctx, "conv-late-session")
	if err != nil {
		t.Fatalf("读取 Agent Session 失败: %v", err)
	}
	for _, item := range sessions {
		if item.ID == sessionID {
			if item.Status != "paused" {
				t.Fatalf("迟到事件不应恢复 running: %+v", item)
			}
			if item.Metadata["statusReason"] == "" {
				t.Fatalf("迟到事件缺少暂停原因: %+v", item.Metadata)
			}
			return
		}
	}
	t.Fatalf("未找到 Worker Session %s", sessionID)
}

func TestPauseRunningAgentSessionsOnStartup(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "startup-session-pause.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-startup-sessions", OwnerUserID: "user-1", Name: "启动恢复",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-startup-sessions", OwnerUserID: "user-1", ProjectID: "project-startup-sessions",
		Title: "启动恢复", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	for _, session := range []AgentSession{
		{
			ID:             AgentSessionID("conv-startup-sessions", AgentRoleMain, "", ""),
			ConversationID: "conv-startup-sessions", Role: AgentRoleMain,
			Title: "主 Agent", Status: "running",
		},
		{
			ID:             AgentSessionID("conv-startup-sessions", AgentRoleWorker, "", "hyp-startup"),
			ConversationID: "conv-startup-sessions", Role: AgentRoleWorker,
			Title: "Worker", Status: "waiting", HypothesisID: "hyp-startup",
		},
	} {
		if err := db.upsertAgentSession(ctx, session, false); err != nil {
			t.Fatalf("写入 Agent Session 失败: %v", err)
		}
	}
	affected, err := db.PauseRunningAgentSessionsOnStartup(ctx, "服务重启导致 Agent 会话中断")
	if err != nil || affected != 2 {
		t.Fatalf("启动恢复失败: affected=%d err=%v", affected, err)
	}
	items, err := db.ListAgentSessions(ctx, "conv-startup-sessions")
	if err != nil {
		t.Fatalf("读取 Agent Session 失败: %v", err)
	}
	byID := map[string]AgentSession{}
	for _, item := range items {
		byID[item.ID] = item
	}
	for _, sessionID := range []string{
		AgentSessionID("conv-startup-sessions", AgentRoleMain, "", ""),
		AgentSessionID("conv-startup-sessions", AgentRoleWorker, "", "hyp-startup"),
	} {
		if byID[sessionID].Status != "paused" {
			t.Fatalf("启动后遗留会话未暂停: %+v", byID[sessionID])
		}
	}
}

func TestAgentSessionsSeparateSystemReviewers(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "system-agent-sessions.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, Project{
		ID: "project-system-session", OwnerUserID: "user-1", Name: "系统 Agent 会话",
		Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateConversation(ctx, Conversation{
		ID: "conv-system-session", OwnerUserID: "user-1", ProjectID: "project-system-session",
		Title: "系统 Agent 会话", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	safetyID := AgentSessionID("conv-system-session", AgentRoleSystem, "system-mission-policy", "")
	reviewerID := AgentSessionID("conv-system-session", AgentRoleSystem, "system-vulnerability-reviewer", "")
	if safetyID == reviewerID {
		t.Fatalf("不同系统 Agent 必须使用不同 Session ID: %s", safetyID)
	}
	if legacyID := AgentSessionID("conv-system-session", AgentRoleSystem, "", ""); legacyID != "system:conv-system-session" {
		t.Fatalf("旧系统 Session ID 必须保持兼容: %s", legacyID)
	}
	details := []ProcessDetail{
		{
			ID: "safety-review", ConversationID: "conv-system-session", MessageID: "msg-system",
			EventType: "subagent.completed", Message: "安全边界和工具约束已应用",
			Data: map[string]interface{}{
				"agentId": "system-mission-policy", "agentName": "安全审核",
				"agentKind": AgentRoleSystem, "status": "completed",
			},
			CreatedAt: now,
		},
		{
			ID: "vulnerability-review", ConversationID: "conv-system-session", MessageID: "msg-system",
			EventType: "subagent.completed", Message: "漏洞审核完成",
			Data: map[string]interface{}{
				"agentId": "system-vulnerability-reviewer", "agentName": "漏洞审核",
				"agentKind": AgentRoleSystem, "status": "completed", "result": "审核通过",
			},
			CreatedAt: now.Add(time.Second),
		},
	}
	if err := db.AddProcessDetails(ctx, details); err != nil {
		t.Fatalf("写入系统 Agent 过程明细失败: %v", err)
	}
	sessions, err := db.ListAgentSessions(ctx, "conv-system-session")
	if err != nil {
		t.Fatalf("读取 Agent Session 失败: %v", err)
	}
	byID := map[string]AgentSession{}
	for _, session := range sessions {
		byID[session.ID] = session
	}
	if byID[safetyID].Title != "安全审核" || byID[safetyID].Status != "completed" {
		t.Fatalf("安全审核 Session 错误: %+v", byID[safetyID])
	}
	if byID[reviewerID].Title != "漏洞审核" || byID[reviewerID].Status != "completed" {
		t.Fatalf("漏洞审核 Session 错误: %+v", byID[reviewerID])
	}
	for _, sessionID := range []string{safetyID, reviewerID} {
		items, total, hasMore, err := db.ListAgentSessionDetailsPage(
			ctx,
			"conv-system-session",
			sessionID,
			10,
			0,
		)
		if err != nil {
			t.Fatalf("读取系统 Agent 历史失败: %v", err)
		}
		if total != 1 || hasMore || len(items) != 1 || items[0].SessionID != sessionID {
			t.Fatalf("系统 Agent 历史错误: session=%s items=%+v total=%d hasMore=%v", sessionID, items, total, hasMore)
		}
	}
}
