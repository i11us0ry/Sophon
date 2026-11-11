package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentpkg "sophon/internal/agent"
	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func TestAgentRoleSkillValidation(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "role-skills.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	skillsDir := t.TempDir()
	for _, name := range []string{"valid-skill"} {
		dir := filepath.Join(skillsDir, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("创建技能目录失败: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# skill"), 0o600); err != nil {
			t.Fatalf("写入技能文件失败: %v", err)
		}
	}
	handler := NewAgentRoleHandler(db, skillsDir)

	skills, err := handler.normalizeSkillNames([]string{"valid-skill", "valid-skill"})
	if err != nil || len(skills) != 1 || skills[0] != "valid-skill" {
		t.Fatalf("合法技能去重失败: skills=%v err=%v", skills, err)
	}
	if _, err := handler.normalizeSkillNames([]string{"../secret"}); err == nil {
		t.Fatalf("路径越界技能名应被拒绝")
	}
	if _, err := handler.normalizeSkillNames([]string{"missing-skill"}); err == nil {
		t.Fatalf("不存在的技能应被拒绝")
	}

	many := make([]string, 0, maxRoleSkills+1)
	for index := 0; index <= maxRoleSkills; index++ {
		name := fmt.Sprintf("skill-%02d", index)
		dir := filepath.Join(skillsDir, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("创建批量技能目录失败: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("# skill"), 0o600); err != nil {
			t.Fatalf("写入批量技能文件失败: %v", err)
		}
		many = append(many, name)
	}
	if _, err := handler.normalizeSkillNames(many); err == nil {
		t.Fatalf("超过最大技能数量应被拒绝")
	}
}

func TestAgentRoleDefaultModeValidation(t *testing.T) {
	for input, want := range map[string]string{
		"":     "auto",
		"AUTO": "auto",
		"fast": "fast",
		"deep": "deep",
	} {
		got, err := normalizeRoleDefaultMode(input)
		if err != nil || got != want {
			t.Fatalf("默认模式解析错误 input=%q got=%q err=%v", input, got, err)
		}
	}
	if _, err := normalizeRoleDefaultMode("turbo"); err == nil {
		t.Fatalf("非法默认模式应被拒绝")
	}
}

func TestAgentRoleUpdatePreservesDefaultModeWhenOmitted(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "role-default-mode.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	if err := db.CreateAgentRole(t.Context(), database.AgentRole{
		ID: "role-mode", Name: "测试角色", Description: "旧描述", Prompt: "旧提示词",
		DefaultMode: "fast", Skills: []string{}, Enabled: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建角色失败: %v", err)
	}
	handler := NewAgentRoleHandler(db, "")
	ctx, recorder := vulnerabilityTestContext(
		http.MethodPut,
		"/api/agent-roles/role-mode",
		`{"name":"测试角色","description":"新描述","prompt":"新提示词","skills":[],"enabled":true}`,
	)
	ctx.Params = gin.Params{{Key: "id", Value: "role-mode"}}
	handler.Update(ctx)
	if recorder.Code >= http.StatusBadRequest {
		t.Fatalf("更新角色失败: %d %s", recorder.Code, recorder.Body.String())
	}
	role, err := db.GetAgentRole(t.Context(), "role-mode")
	if err != nil {
		t.Fatalf("读取角色失败: %v", err)
	}
	if role.DefaultMode != "fast" {
		t.Fatalf("省略 defaultMode 时不应重置执行模式: %s", role.DefaultMode)
	}
}

func TestAgentRoleListIncludesMandatoryInternalAgentsOnDemand(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "role-internal.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UTC()
	if err := db.CreateAgentRole(t.Context(), database.AgentRole{
		ID:          "role-normal",
		Name:        "普通角色",
		Description: "普通角色",
		Prompt:      "普通提示词",
		Skills:      []string{},
		Enabled:     true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建普通角色失败: %v", err)
	}
	if err := agentpkg.EnsureSystemAgentRoles(t.Context(), db); err != nil {
		t.Fatalf("初始化系统 Agent 失败: %v", err)
	}
	handler := NewAgentRoleHandler(db, "")
	gin.SetMode(gin.TestMode)
	readItems := func(path string) []agentRoleListItem {
		recorder := httptest.NewRecorder()
		ginCtx, _ := gin.CreateTestContext(recorder)
		ginCtx.Request = httptest.NewRequest(http.MethodGet, path, nil)
		handler.List(ginCtx)
		if recorder.Code != http.StatusOK {
			t.Fatalf("读取角色列表失败: %d %s", recorder.Code, recorder.Body.String())
		}
		var response struct {
			Items []agentRoleListItem `json:"items"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("解析角色列表失败: %v", err)
		}
		return response.Items
	}

	normalItems := readItems("/api/agent-roles")
	if len(normalItems) != 1 || normalItems[0].Internal {
		t.Fatalf("默认角色列表不应包含系统 Agent: %+v", normalItems)
	}
	items := readItems("/api/agent-roles?includeInternal=true")
	if len(items) != 7 {
		t.Fatalf("角色管理应返回普通角色和六个可管理系统 Agent: %+v", items)
	}
	if !items[0].Internal || !items[1].Internal || !items[2].Internal {
		t.Fatalf("系统 Agent 应优先展示: %+v", items)
	}
	internal := 0
	editable := 0
	for _, item := range items {
		if item.ID == agentpkg.SystemIntentAgentID {
			t.Fatalf("内部意图预审不应作为可管理 Agent 返回: %+v", item)
		}
		if !item.Internal {
			continue
		}
		internal++
		if !item.Enabled || !item.Builtin {
			t.Fatalf("系统 Agent 必须开启且不可变: %+v", item)
		}
		if item.ID == agentpkg.SystemVulnerabilityReviewerID {
			if item.Mandatory || !item.Editable {
				t.Fatalf("漏洞审核应为可编辑、可停用系统 Agent: %+v", item)
			}
		} else if !item.Mandatory || item.Editable {
			t.Fatalf("其他系统 Agent 必须强制启用且只读: %+v", item)
		}
		if len([]rune(item.Prompt)) < 200 {
			t.Fatalf("系统 Agent 应提供完整原始 Prompt: %+v", item)
		}
		if item.Editable {
			editable++
			if item.ID != agentpkg.SystemVulnerabilityReviewerID {
				t.Fatalf("仅漏洞审核角色应可编辑: %+v", item)
			}
		}
	}
	if internal != 6 {
		t.Fatalf("应返回六个可管理系统 Agent，实际 %d", internal)
	}
	if editable != 1 {
		t.Fatalf("应仅返回一个可编辑系统 Agent，实际 %d", editable)
	}
}

func TestReadOnlySystemAgentsCannotBeEditedDisabledOrDeleted(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "role-system-edit.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := agentpkg.EnsureSystemAgentRoles(t.Context(), db); err != nil {
		t.Fatalf("初始化系统 Agent 失败: %v", err)
	}
	handler := NewAgentRoleHandler(db, "")
	gin.SetMode(gin.TestMode)
	for _, id := range []string{
		agentpkg.SystemIntentAgentID,
		agentpkg.SystemReportAgentID,
		agentpkg.SystemMissionPolicyAgentID,
		agentpkg.SystemDeepPathPlannerID,
		agentpkg.SystemDeepPathWorkerID,
		agentpkg.SystemDeepPathSubAgentID,
	} {
		role, err := db.GetAgentRole(t.Context(), id)
		if err != nil {
			t.Fatalf("读取系统 Agent %s 失败: %v", id, err)
		}
		updatedPrompt := role.Prompt + "\n补充规则：优先识别只读任务。"
		editCtx, editRecorder := vulnerabilityTestContext(
			http.MethodPut,
			"/api/agent-roles/"+role.ID,
			fmt.Sprintf(
				`{"name":%q,"description":"试图修改描述","prompt":%q,"icon":%q,"skills":[],"enabled":true}`,
				role.Name,
				updatedPrompt,
				role.Icon,
			),
		)
		editCtx.Params = gin.Params{{Key: "id", Value: role.ID}}
		handler.Update(editCtx)
		if editRecorder.Code != http.StatusBadRequest {
			t.Fatalf("系统 Agent %s 不允许编辑: %d %s", role.Name, editRecorder.Code, editRecorder.Body.String())
		}
		stored, err := db.GetAgentRole(t.Context(), role.ID)
		if err != nil || stored.Prompt != role.Prompt || stored.Description != role.Description {
			t.Fatalf("系统 Agent %s 编辑请求不应修改数据: %+v err=%v", role.Name, stored, err)
		}

		disableCtx, disableRecorder := vulnerabilityTestContext(
			http.MethodPut,
			"/api/agent-roles/"+role.ID,
			fmt.Sprintf(
				`{"name":%q,"description":"描述","prompt":%q,"icon":%q,"skills":[],"enabled":false}`,
				role.Name,
				updatedPrompt,
				role.Icon,
			),
		)
		disableCtx.Params = gin.Params{{Key: "id", Value: role.ID}}
		handler.Update(disableCtx)
		if disableRecorder.Code != http.StatusBadRequest {
			t.Fatalf("系统 Agent %s 不允许编辑或停用: %d %s", role.Name, disableRecorder.Code, disableRecorder.Body.String())
		}

		deleteCtx, deleteRecorder := vulnerabilityTestContext(
			http.MethodDelete,
			"/api/agent-roles/"+role.ID,
			"",
		)
		deleteCtx.Params = gin.Params{{Key: "id", Value: role.ID}}
		handler.Delete(deleteCtx)
		if deleteRecorder.Code != http.StatusBadRequest {
			t.Fatalf("系统 Agent %s 不允许删除: %d %s", role.Name, deleteRecorder.Code, deleteRecorder.Body.String())
		}
	}
}

func TestVulnerabilityReviewerCanBeEditedDisabledButNotDeleted(t *testing.T) {
	db, err := database.Open(filepath.Join(t.TempDir(), "role-reviewer-edit.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := agentpkg.EnsureSystemAgentRoles(t.Context(), db); err != nil {
		t.Fatalf("初始化系统 Agent 失败: %v", err)
	}
	handler := NewAgentRoleHandler(db, "")
	gin.SetMode(gin.TestMode)
	role, err := db.GetAgentRole(t.Context(), agentpkg.SystemVulnerabilityReviewerID)
	if err != nil {
		t.Fatalf("读取漏洞审核角色失败: %v", err)
	}
	updatedPrompt := role.Prompt + "\n补充规则：保留静态审计候选。"
	editCtx, editRecorder := vulnerabilityTestContext(
		http.MethodPut,
		"/api/agent-roles/"+role.ID,
		fmt.Sprintf(
			`{"name":%q,"description":"用户自定义审核描述","prompt":%q,"icon":"x","skills":[],"enabled":true}`,
			role.Name,
			updatedPrompt,
		),
	)
	editCtx.Params = gin.Params{{Key: "id", Value: role.ID}}
	handler.Update(editCtx)
	if editRecorder.Code >= http.StatusBadRequest {
		t.Fatalf("漏洞审核角色应允许编辑: %d %s", editRecorder.Code, editRecorder.Body.String())
	}
	stored, err := db.GetAgentRole(t.Context(), role.ID)
	if err != nil || stored.Prompt != updatedPrompt || stored.Description != "用户自定义审核描述" {
		t.Fatalf("漏洞审核角色未保存修改: %+v err=%v", stored, err)
	}

	disableCtx, disableRecorder := vulnerabilityTestContext(
		http.MethodPut,
		"/api/agent-roles/"+role.ID,
		fmt.Sprintf(
			`{"name":%q,"description":%q,"prompt":%q,"icon":%q,"skills":[],"enabled":false}`,
			stored.Name,
			stored.Description,
			stored.Prompt,
			stored.Icon,
		),
	)
	disableCtx.Params = gin.Params{{Key: "id", Value: role.ID}}
	handler.Update(disableCtx)
	if disableRecorder.Code >= http.StatusBadRequest {
		t.Fatalf("漏洞审核角色编辑请求不应失败: %d %s", disableRecorder.Code, disableRecorder.Body.String())
	}
	stored, err = db.GetAgentRole(t.Context(), role.ID)
	if err != nil || stored.Enabled {
		t.Fatalf("漏洞审核角色应允许停用: %+v err=%v", stored, err)
	}

	deleteCtx, deleteRecorder := vulnerabilityTestContext(
		http.MethodDelete,
		"/api/agent-roles/"+role.ID,
		"",
	)
	deleteCtx.Params = gin.Params{{Key: "id", Value: role.ID}}
	handler.Delete(deleteCtx)
	if deleteRecorder.Code != http.StatusBadRequest {
		t.Fatalf("漏洞审核角色不允许删除: %d %s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
}
