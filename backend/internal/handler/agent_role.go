package handler

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentpkg "sophon/internal/agent"
	"sophon/internal/database"
	"sophon/internal/middleware"
	"sophon/internal/skillname"

	"github.com/gin-gonic/gin"
)

type AgentRoleHandler struct {
	db        *database.DB
	skillsDir string
}

type agentRoleListItem struct {
	database.AgentRole
	Internal  bool `json:"internal"`
	Mandatory bool `json:"mandatory"`
	Editable  bool `json:"editable"`
}

const (
	maxRolePromptRunes = 32 * 1024
	maxRoleSkills      = 50
)

func NewAgentRoleHandler(db *database.DB, skillsDir string) *AgentRoleHandler {
	return &AgentRoleHandler{db: db, skillsDir: strings.TrimSpace(skillsDir)}
}

type agentRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Prompt      string   `json:"prompt"`
	Icon        string   `json:"icon"`
	DefaultMode *string  `json:"defaultMode"`
	Skills      []string `json:"skills"`
	Enabled     *bool    `json:"enabled"`
}

func (h *AgentRoleHandler) List(c *gin.Context) {
	onlyEnabled := strings.EqualFold(strings.TrimSpace(c.Query("enabled")), "true")
	includeInternal := strings.EqualFold(strings.TrimSpace(c.Query("includeInternal")), "true")
	roles, err := h.db.ListAgentRoles(c.Request.Context(), onlyEnabled)
	if err != nil {
		internalError(c, "list_agent_roles_failed", "读取角色失败")
		return
	}
	systemItems := make([]agentRoleListItem, 0, 2)
	items := make([]agentRoleListItem, 0, len(roles))
	for _, role := range roles {
		if role.ID == agentpkg.SystemIntentAgentID {
			continue
		}
		_, isSystem := agentpkg.SystemAgentDefinitionForRole(role)
		if isSystem && !includeInternal && role.ID != agentpkg.SystemRetestAgentID {
			continue
		}
		item := agentRoleListItem{
			AgentRole: role,
			Internal:  isSystem,
			Mandatory: isSystem && !agentpkg.SystemAgentDisableableForRole(role),
			Editable:  agentpkg.SystemAgentEditableForRole(role),
		}
		if isSystem {
			systemItems = append(systemItems, item)
		} else {
			items = append(items, item)
		}
	}
	c.JSON(http.StatusOK, gin.H{"items": append(systemItems, items...)})
}

func (h *AgentRoleHandler) Create(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request agentRoleRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_agent_role", "角色请求格式错误")
		return
	}
	name := truncateRunes(request.Name, 60)
	if strings.TrimSpace(name) == "" {
		badRequest(c, "invalid_agent_role", "角色名称不能为空")
		return
	}
	if strings.TrimSpace(request.Prompt) == "" {
		badRequest(c, "invalid_agent_role", "角色提示词不能为空")
		return
	}
	defaultMode := "auto"
	if request.DefaultMode != nil {
		var err error
		defaultMode, err = normalizeRoleDefaultMode(*request.DefaultMode)
		if err != nil {
			badRequest(c, "invalid_agent_role", err.Error())
			return
		}
	}
	if len([]rune(request.Prompt)) > maxRolePromptRunes {
		badRequest(c, "invalid_agent_role", "角色提示词不能超过 32768 个字符")
		return
	}
	skills, err := h.normalizeSkillNames(request.Skills)
	if err != nil {
		badRequest(c, "invalid_agent_role", err.Error())
		return
	}
	if existing, err := h.db.GetAgentRoleByName(c.Request.Context(), name); err == nil {
		if !existing.Deleted {
			badRequest(c, "agent_role_exists", "角色名称已存在")
			return
		}
		now := time.Now().UTC()
		restored := database.AgentRole{
			ID:          existing.ID,
			Name:        name,
			Description: truncateRunes(request.Description, 200),
			Prompt:      strings.TrimSpace(request.Prompt),
			Icon:        truncateRunes(request.Icon, 8),
			DefaultMode: defaultMode,
			Skills:      skills,
			Builtin:     existing.Builtin,
			Enabled:     request.Enabled == nil || *request.Enabled,
			CreatedAt:   existing.CreatedAt,
			UpdatedAt:   now,
		}
		if strings.TrimSpace(restored.Prompt) == "" {
			badRequest(c, "invalid_agent_role", "角色提示词不能为空")
			return
		}
		if err := h.db.RestoreAgentRole(c.Request.Context(), restored); err != nil {
			internalError(c, "create_agent_role_failed", "创建角色失败")
			return
		}
		restored.Deleted = false
		c.JSON(http.StatusCreated, restored)
		return
	}
	now := time.Now().UTC()
	role := database.AgentRole{
		ID:          randomID(),
		Name:        name,
		Description: truncateRunes(request.Description, 200),
		Prompt:      strings.TrimSpace(request.Prompt),
		Icon:        truncateRunes(request.Icon, 8),
		DefaultMode: defaultMode,
		Skills:      skills,
		Builtin:     false,
		Enabled:     request.Enabled == nil || *request.Enabled,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := h.db.CreateAgentRole(c.Request.Context(), role); err != nil {
		internalError(c, "create_agent_role_failed", "创建角色失败")
		return
	}
	c.JSON(http.StatusCreated, role)
}

func (h *AgentRoleHandler) Update(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	role, err := h.db.GetAgentRole(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondMutationError(c, err, "agent_role_not_found", "角色不存在", "update_agent_role_failed", "更新角色失败")
		return
	}
	if _, isSystem := agentpkg.SystemAgentDefinitionForRole(*role); isSystem &&
		!agentpkg.SystemAgentEditableForRole(*role) {
		badRequest(c, "system_agent_read_only", "系统 Agent 只能查看，不能编辑")
		return
	}
	var request agentRoleRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_agent_role", "角色请求格式错误")
		return
	}
	if name := truncateRunes(request.Name, 60); strings.TrimSpace(name) != "" && name != role.Name {
		if role.Builtin {
			badRequest(c, "invalid_agent_role", "内置角色名称不能修改")
			return
		}
		if existing, err := h.db.GetAgentRoleByName(c.Request.Context(), name); err == nil && existing.ID != role.ID {
			badRequest(c, "agent_role_exists", "角色名称已存在")
			return
		}
		role.Name = name
	}
	if strings.TrimSpace(request.Prompt) != "" {
		if len([]rune(request.Prompt)) > maxRolePromptRunes {
			badRequest(c, "invalid_agent_role", "角色提示词不能超过 32768 个字符")
			return
		}
		role.Prompt = strings.TrimSpace(request.Prompt)
	}
	if request.DefaultMode != nil {
		defaultMode, err := normalizeRoleDefaultMode(*request.DefaultMode)
		if err != nil {
			badRequest(c, "invalid_agent_role", err.Error())
			return
		}
		role.DefaultMode = defaultMode
	}
	skills, err := h.normalizeSkillNames(request.Skills)
	if err != nil {
		badRequest(c, "invalid_agent_role", err.Error())
		return
	}
	role.Description = truncateRunes(request.Description, 200)
	role.Icon = truncateRunes(request.Icon, 8)
	role.Skills = skills
	if request.Enabled != nil {
		if _, isSystem := agentpkg.SystemAgentDefinitionForRole(*role); !isSystem ||
			agentpkg.SystemAgentDisableableForRole(*role) {
			role.Enabled = *request.Enabled
		}
	}
	role.UpdatedAt = time.Now().UTC()
	if err := h.db.UpdateAgentRole(c.Request.Context(), *role); err != nil {
		respondMutationError(c, err, "agent_role_not_found", "角色不存在", "update_agent_role_failed", "更新角色失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AgentRoleHandler) Delete(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	role, err := h.db.GetAgentRole(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondMutationError(c, err, "agent_role_not_found", "角色不存在", "delete_agent_role_failed", "删除角色失败")
		return
	}
	if _, isSystem := agentpkg.SystemAgentDefinitionForRole(*role); isSystem {
		badRequest(c, "invalid_agent_role", "系统 Agent 不允许删除")
		return
	}
	if err := h.db.DeleteAgentRole(c.Request.Context(), role.ID); err != nil {
		respondMutationError(c, err, "agent_role_not_found", "角色不存在", "delete_agent_role_failed", "删除角色失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AgentRoleHandler) normalizeSkillNames(values []string) ([]string, error) {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		if !skillname.Valid(value) {
			return nil, fmt.Errorf("技能名称不合法: %s", value)
		}
		if h.skillsDir == "" {
			return nil, fmt.Errorf("未配置技能目录")
		}
		path := filepath.Join(h.skillsDir, value, "SKILL.md")
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return nil, fmt.Errorf("技能不存在: %s", value)
		}
		seen[value] = true
		result = append(result, value)
		if len(result) > maxRoleSkills {
			return nil, fmt.Errorf("单个角色最多绑定 %d 个技能", maxRoleSkills)
		}
	}
	return result, nil
}

func normalizeRoleDefaultMode(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return "auto", nil
	case "fast":
		return "fast", nil
	case "deep":
		return "deep", nil
	default:
		return "", fmt.Errorf("默认执行模式必须是 auto、fast 或 deep")
	}
}
