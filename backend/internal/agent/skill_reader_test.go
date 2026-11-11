package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/tool"

	"sophon/internal/config"
	"sophon/internal/database"
	"sophon/internal/execctx"
)

func TestSkillSummaryParsesBlockScalar(t *testing.T) {
	content := "---\nname: demo-skill\ndescription: >-\n  第一行说明\n  第二行说明\nmetadata:\n  tags: [demo]\n---\n\n## demo-skill\n"
	if got := skillSummary(content); got != "第一行说明 第二行说明" {
		t.Fatalf("block scalar description 解析错误: %q", got)
	}
}

func TestSkillSummaryFallbacks(t *testing.T) {
	if got := skillSummary("---\nname: demo-skill\ndescription: 内联说明\n---\n正文\n"); got != "内联说明" {
		t.Fatalf("内联 description 解析错误: %q", got)
	}
	if got := skillSummary("普通技能正文\n"); got != "普通技能正文" {
		t.Fatalf("无 frontmatter 兜底解析错误: %q", got)
	}
}

func TestReadSkillTool(t *testing.T) {
	dir := t.TempDir()
	skillsDir := filepath.Join(dir, "skills")
	skillDir := filepath.Join(skillsDir, "demo-skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("create skill dir: %v", err)
	}
	content := "---\nname: demo-skill\ndescription: 演示\n---\n\n## 步骤\n1. 先侦察\n"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write skill: %v", err)
	}

	db, err := database.Open(filepath.Join(dir, "skills.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if err := db.CreateConversation(context.Background(), database.Conversation{
		ID: "conv-no-role", OwnerUserID: "user-1", Title: "测试",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建无角色对话失败: %v", err)
	}
	ctx := execctx.WithConversationID(context.Background(), "conv-no-role")
	ctx = execctx.WithUserID(ctx, "user-1")
	service := &Service{db: db, cfg: config.Config{SkillsDir: skillsDir}}
	item := newSkillReaderTool(service)
	info, err := item.Info(ctx)
	if err != nil || info.Name != readSkillToolName {
		t.Fatalf("read_skill 工具信息不正确: %+v, %v", info, err)
	}
	if !strings.Contains(info.Desc, "没有成果") || !strings.Contains(info.Desc, "不是必读门禁") {
		t.Fatalf("read_skill 工具描述未体现兜底参考语义: %q", info.Desc)
	}
	invokable, ok := item.(tool.InvokableTool)
	if !ok {
		t.Fatalf("read_skill 不是 InvokableTool")
	}

	raw, err := invokable.InvokableRun(ctx, `{"name":"demo-skill"}`)
	if err != nil {
		t.Fatalf("读取技能失败: %v", err)
	}
	if !strings.Contains(raw, "## 步骤") {
		t.Fatalf("技能内容不完整: %q", raw)
	}

	if _, err := invokable.InvokableRun(ctx, `{"name":"../etc"}`); err == nil {
		t.Fatalf("非法技能名应当报错")
	}
	if _, err := invokable.InvokableRun(ctx, `{"name":"missing-skill"}`); err == nil {
		t.Fatalf("不存在的技能应当报错")
	}
}

func TestReadSkillNotRequireHITL(t *testing.T) {
	service := &Service{cfg: config.Config{
		HITLEnabled: true,
		HITLTools:   "exec,execute-python-script,install-python-package",
	}}
	if service.hitlRequired(context.Background(), "", readSkillToolName) {
		t.Fatalf("read_skill 不应进入默认 HITL 审批清单")
	}
}

func TestReadSkillRestrictedToRoleSkills(t *testing.T) {
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "skills.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()
	skillsDir := filepath.Join(dir, "skills")
	for _, name := range []string{"allowed-skill", "unbound-skill", "subset-other"} {
		skillDir := filepath.Join(skillsDir, name)
		if err := os.MkdirAll(skillDir, 0o755); err != nil {
			t.Fatalf("创建技能目录失败: %v", err)
		}
		if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# "+name), 0o644); err != nil {
			t.Fatalf("写入技能失败: %v", err)
		}
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.UpsertAgentRole(ctx, database.AgentRole{
		ID: "role-bound", Name: "绑定角色", Description: "测试", Prompt: "测试",
		DefaultMode: "auto", Skills: []string{"allowed-skill"}, Builtin: true,
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建角色失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conv-bound", OwnerUserID: "user-1", Title: "测试",
		AgentRoleID: "role-bound", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	service := &Service{db: db, cfg: config.Config{SkillsDir: skillsDir}}
	reader := newSkillReaderTool(service).(tool.InvokableTool)
	roleCtx := execctx.WithConversationID(ctx, "conv-bound")
	roleCtx = execctx.WithUserID(roleCtx, "user-1")
	if _, err := reader.InvokableRun(roleCtx, `{"name":"allowed-skill"}`); err != nil {
		t.Fatalf("应允许读取角色绑定技能: %v", err)
	}
	if _, err := reader.InvokableRun(roleCtx, `{"name":"unbound-skill"}`); err == nil {
		t.Fatalf("应拒绝读取角色未绑定技能")
	}
	if _, err := reader.InvokableRun(ctx, `{"name":"allowed-skill"}`); err == nil {
		t.Fatalf("缺少角色会话上下文时应拒绝读取技能")
	}

	if err := db.UpsertAgentRole(ctx, database.AgentRole{
		ID: "role-subset", Name: "Worker 技能子集", Description: "测试", Prompt: "测试",
		DefaultMode: "auto", Skills: []string{"allowed-skill", "subset-other"}, Builtin: true,
		Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建 Worker 技能子集角色失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conv-subset", OwnerUserID: "user-1", Title: "测试",
		AgentRoleID: "role-subset", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建 Worker 技能子集对话失败: %v", err)
	}
	workerCtx := execctx.WithConversationID(ctx, "conv-subset")
	workerCtx = execctx.WithUserID(workerCtx, "user-1")
	workerCtx = execctx.WithSubagent(workerCtx, execctx.SubagentInfo{
		ID: "worker-1", Kind: "worker", Mode: subagentModeReadOnly, Depth: 1,
		WorkerFocus: "路由鉴权", AllowedSkills: []string{"allowed-skill"},
	})
	if _, err := reader.InvokableRun(workerCtx, `{"name":"allowed-skill"}`); err != nil {
		t.Fatalf("应允许 Worker 读取本次分配技能: %v", err)
	}
	if _, err := reader.InvokableRun(workerCtx, `{"name":"subset-other"}`); err == nil {
		t.Fatalf("应拒绝读取角色绑定但未分配给 Worker 的技能")
	}

	for _, test := range []struct {
		id      string
		enabled bool
		skills  []string
	}{
		{id: "role-no-skills", enabled: true, skills: []string{}},
		{id: "role-disabled", enabled: false, skills: []string{"allowed-skill"}},
	} {
		if err := db.UpsertAgentRole(ctx, database.AgentRole{
			ID: test.id, Name: test.id, Description: "测试", Prompt: "测试",
			DefaultMode: "auto", Skills: test.skills, Builtin: true,
			Enabled: test.enabled, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("创建角色 %s 失败: %v", test.id, err)
		}
		conversationID := "conv-" + test.id
		if err := db.CreateConversation(ctx, database.Conversation{
			ID: conversationID, OwnerUserID: "user-1", Title: "测试",
			AgentRoleID: test.id, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("创建角色 %s 的对话失败: %v", test.id, err)
		}
		testCtx := execctx.WithConversationID(ctx, conversationID)
		testCtx = execctx.WithUserID(testCtx, "user-1")
		if _, err := reader.InvokableRun(testCtx, `{"name":"allowed-skill"}`); err == nil {
			t.Fatalf("角色 %s 不应读取未授权技能", test.id)
		}
	}
}

func TestDelegatedRoleBriefIncludesFullPrompt(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(filepath.Join(t.TempDir(), "role-brief.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer db.Close()
	now := time.Now().UTC()
	prompt := "只允许静态分析，禁止联网和执行项目代码。"
	if err := db.UpsertAgentRole(ctx, database.AgentRole{
		ID: "role-brief", Name: "代码审计", Description: "静态审计",
		Prompt: prompt, DefaultMode: "auto", Skills: []string{},
		Builtin: true, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建角色失败: %v", err)
	}
	if err := db.CreateConversation(ctx, database.Conversation{
		ID: "conv-brief", OwnerUserID: "user-1", Title: "测试",
		AgentRoleID: "role-brief", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建对话失败: %v", err)
	}
	roleCtx := execctx.WithConversationID(ctx, "conv-brief")
	roleCtx = execctx.WithUserID(roleCtx, "user-1")
	brief := (&Service{db: db}).delegatedRoleBrief(roleCtx)
	if !strings.Contains(brief, prompt) || !strings.Contains(brief, "本次 Worker 可用技能：无") {
		t.Fatalf("子 Agent 角色简报缺少完整约束: %q", brief)
	}
}

func TestRoleInstructionInjectsBlockScalarSkillSummary(t *testing.T) {
	dir := t.TempDir()
	db, err := database.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()

	skillsDir := filepath.Join(dir, "skills")
	skillDir := filepath.Join(skillsDir, "demo-skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("create skill dir: %v", err)
	}
	content := "---\nname: demo-skill\ndescription: >-\n  第一行说明\n  第二行说明\n---\n\n## demo-skill\n"
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(content), 0o644); err != nil {
		t.Fatalf("write skill: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.UpsertAgentRole(ctx, database.AgentRole{
		ID:          "role-skillfix",
		Name:        "skillfix-tester",
		Description: "回归测试角色",
		Prompt:      "你是回归测试角色。",
		Skills:      []string{"demo-skill"},
		Builtin:     true,
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("upsert role: %v", err)
	}

	service := &Service{db: db, cfg: config.Config{SkillsDir: skillsDir}}
	instruction := service.roleInstruction(ctx, "role-skillfix")
	if !strings.Contains(instruction, "第一行说明 第二行说明") {
		t.Fatalf("角色提示词未注入块标量技能描述: %q", instruction)
	}
	if !strings.Contains(instruction, skillsDir) {
		t.Fatalf("角色提示词缺少技能目录绝对路径: %q", instruction)
	}
	if !strings.Contains(instruction, readSkillToolName) {
		t.Fatalf("角色提示词未提示 read_skill 工具: %q", instruction)
	}
	for _, want := range []string{"仅用于补充思路", "没有成果", "漏洞覆盖上限"} {
		if !strings.Contains(instruction, want) {
			t.Fatalf("角色提示词缺少技能兜底语义 %q: %q", want, instruction)
		}
	}
}

func TestBundledSkillSummariesParse(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "skills", "*", "SKILL.md"))
	if err != nil {
		t.Fatalf("glob skills: %v", err)
	}
	if len(paths) == 0 {
		t.Skip("skills 目录不存在，跳过内置技能校验")
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		summary := strings.TrimSpace(skillSummary(string(raw)))
		if summary == "" || summary == ">-" || summary == ">" || summary == "|" || summary == "|-" {
			t.Fatalf("技能 %s 摘要未解析: %q", path, summary)
		}
	}
}

func TestDotnetInjectionSkillCoversTransmissiveSQL(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "skills", "dotnet-injection-audit", "SKILL.md",
	))
	if err != nil {
		t.Fatalf("读取 dotnet-injection-audit 失败: %v", err)
	}
	content := string(raw)
	for _, want := range []string{
		"完整 SQL 文本",
		"零 `SqlParameter`",
		"DBUtils.ExecuteDataSet(ctx, sql)",
		"不能因为当前方法没有",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("SQL 技能缺少形参透传检查项 %q", want)
		}
	}
}
