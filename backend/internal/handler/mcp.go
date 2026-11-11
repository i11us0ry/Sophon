package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	agentpkg "sophon/internal/agent"
	"sophon/internal/database"
	"sophon/internal/mcpclient"
	"sophon/internal/middleware"
	"sophon/internal/policy"

	"github.com/cloudwego/eino/schema"
	"github.com/gin-gonic/gin"
)

type MCPHandler struct {
	db       *database.DB
	manager  *mcpclient.Manager
	toolsDir string
	agent    *agentpkg.Service
}

func NewMCPHandler(
	db *database.DB,
	manager *mcpclient.Manager,
	toolsDir string,
	agentService *agentpkg.Service,
) *MCPHandler {
	return &MCPHandler{db: db, manager: manager, toolsDir: toolsDir, agent: agentService}
}

type mcpServerRequest struct {
	Name        string            `json:"name"`
	Transport   string            `json:"transport"`
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	URL         string            `json:"url"`
	Description string            `json:"description"`
	Enabled     *bool             `json:"enabled"`
}

func (h *MCPHandler) List(c *gin.Context) {
	items, err := h.db.ListMCPServers(c.Request.Context())
	if err != nil {
		internalError(c, "list_mcp_servers_failed", "读取 MCP 服务失败")
		return
	}
	result := make([]database.MCPServer, 0, len(items))
	for _, item := range items {
		if status, count := h.manager.RuntimeStatus(item.ID); status != "" {
			item.Status = status
			item.ToolCount = count
			if status == "error" {
				if message := h.manager.RuntimeError(item.ID); message != "" {
					item.LastError = message
				}
			}
		}
		result = append(result, item)
	}
	c.JSON(http.StatusOK, gin.H{"items": result})
}

func (h *MCPHandler) Create(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request mcpServerRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_mcp_server", "MCP 服务请求格式错误")
		return
	}
	item, err := buildMCPServer(database.MCPServer{}, request)
	if err != nil {
		badRequest(c, "invalid_mcp_server", err.Error())
		return
	}
	if _, err := h.db.GetMCPServerByName(c.Request.Context(), item.Name); err == nil {
		badRequest(c, "mcp_server_exists", "服务名称已存在")
		return
	}
	now := time.Now().UTC()
	item.ID = randomID()
	item.Status = "unknown"
	item.CreatedAt = now
	item.UpdatedAt = now
	if err := h.db.CreateMCPServer(c.Request.Context(), item); err != nil {
		internalError(c, "create_mcp_server_failed", "创建 MCP 服务失败")
		return
	}
	c.JSON(http.StatusCreated, item)
}

func (h *MCPHandler) Update(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	item, err := h.db.GetMCPServer(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondMutationError(c, err, "mcp_server_not_found", "MCP 服务不存在", "update_mcp_server_failed", "更新 MCP 服务失败")
		return
	}
	var request mcpServerRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_mcp_server", "MCP 服务请求格式错误")
		return
	}
	updated, err := buildMCPServer(*item, request)
	if err != nil {
		badRequest(c, "invalid_mcp_server", err.Error())
		return
	}
	if updated.Name != item.Name {
		if existing, err := h.db.GetMCPServerByName(c.Request.Context(), updated.Name); err == nil && existing.ID != item.ID {
			badRequest(c, "mcp_server_exists", "服务名称已存在")
			return
		}
	}
	updated.ID = item.ID
	updated.UpdatedAt = time.Now().UTC()
	if err := h.db.UpdateMCPServer(c.Request.Context(), updated); err != nil {
		respondMutationError(c, err, "mcp_server_not_found", "MCP 服务不存在", "update_mcp_server_failed", "更新 MCP 服务失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *MCPHandler) Delete(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	item, err := h.db.GetMCPServer(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondMutationError(c, err, "mcp_server_not_found", "MCP 服务不存在", "delete_mcp_server_failed", "删除 MCP 服务失败")
		return
	}
	if item.Builtin {
		badRequest(c, "mcp_server_builtin", "内置 MCP 服务不能删除，可以停用")
		return
	}
	if err := h.db.DeleteMCPServer(c.Request.Context(), item.ID); err != nil {
		respondMutationError(c, err, "mcp_server_not_found", "MCP 服务不存在", "delete_mcp_server_failed", "删除 MCP 服务失败")
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *MCPHandler) Test(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	item, err := h.db.GetMCPServer(c.Request.Context(), c.Param("id"))
	if err != nil {
		respondMutationError(c, err, "mcp_server_not_found", "MCP 服务不存在", "test_mcp_server_failed", "测试 MCP 服务失败")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()
	tools, testErr := mcpclient.TestConnection(
		ctx,
		*item,
		10*time.Second,
		10*time.Second,
		h.manager.ProxyEnv(),
	)
	if testErr != nil {
		_ = h.db.UpdateMCPServerStatus(c.Request.Context(), item.ID, "error", testErr.Error(), 0)
		c.JSON(http.StatusOK, gin.H{
			"status":  "error",
			"message": testErr.Error(),
			"tools":   []string{},
		})
		return
	}
	_ = h.db.UpdateMCPServerStatus(c.Request.Context(), item.ID, "connected", "", len(tools))
	c.JSON(http.StatusOK, gin.H{
		"status":    "connected",
		"tools":     tools,
		"toolCount": len(tools),
	})
}

type mcpToolParameter struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	Enum        []string `json:"enum,omitempty"`
}

type mcpToolItem struct {
	ServerID    string             `json:"serverId"`
	ServerName  string             `json:"serverName"`
	Builtin     bool               `json:"builtin"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Parameters  []mcpToolParameter `json:"parameters"`
	Enabled     bool               `json:"enabled"`
	Capability  string             `json:"capability"`
}

// Tools 返回所有已连接服务的工具明细与启停配置。
func (h *MCPHandler) Tools(c *gin.Context) {
	servers, err := h.db.ListMCPServers(c.Request.Context())
	if err != nil {
		internalError(c, "list_mcp_tools_failed", "读取 MCP 工具列表失败")
		return
	}
	settings, err := h.db.ListMCPToolSettings(c.Request.Context())
	if err != nil {
		internalError(c, "list_mcp_tools_failed", "读取 MCP 工具配置失败")
		return
	}
	state := make(map[string]database.MCPToolSetting, len(settings))
	for _, item := range settings {
		state[item.ServerName+"\x00"+item.ToolName] = item
	}

	items := make([]mcpToolItem, 0)
	for _, server := range servers {
		if !server.Enabled {
			continue
		}
		for _, info := range h.manager.Tools(server.ID) {
			setting, ok := state[server.Name+"\x00"+info.Name]
			enabled := true
			capability := string(policy.DefaultCapability(info.Name))
			if ok {
				enabled = setting.Enabled
				if normalized, valid := policy.NormalizeCapability(setting.Capability); valid {
					capability = string(normalized)
				}
			}
			items = append(items, mcpToolItem{
				ServerID:    server.ID,
				ServerName:  server.Name,
				Builtin:     server.Builtin,
				Name:        info.Name,
				Description: info.Desc,
				Parameters:  toolParameters(info),
				Enabled:     enabled,
				Capability:  capability,
			})
		}
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

// AgentTools 返回 Agent 视角的工具清单：直接暴露给模型的内置/直连工具，
// 以及只能通过 mcp_search_tools + mcp_use_tool 调用的 MCP 工具。
func (h *MCPHandler) AgentTools(c *gin.Context) {
	if middleware.UserFromContext(c) == nil {
		unauthorized(c)
		return
	}
	if h.agent == nil {
		c.JSON(http.StatusOK, agentpkg.ToolInventory{
			Direct:     []agentpkg.InventoryTool{},
			Searchable: []agentpkg.InventoryTool{},
		})
		return
	}
	c.JSON(http.StatusOK, h.agent.ToolInventory(c.Request.Context()))
}

// UpdateTools 批量保存工具启停配置；未保存过的工具默认启用。
func (h *MCPHandler) UpdateTools(c *gin.Context) {
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	var request struct {
		Items []struct {
			ServerName string  `json:"serverName"`
			ToolName   string  `json:"toolName"`
			Enabled    *bool   `json:"enabled"`
			Capability *string `json:"capability"`
		} `json:"items"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_mcp_tools", "工具配置请求格式错误")
		return
	}
	if len(request.Items) == 0 || len(request.Items) > 500 {
		badRequest(c, "invalid_mcp_tools", "工具配置数量需在 1-500 之间")
		return
	}

	now := time.Now().UTC()
	settings := make([]database.MCPToolSetting, 0, len(request.Items))
	for _, item := range request.Items {
		serverName := strings.TrimSpace(item.ServerName)
		toolName := strings.TrimSpace(item.ToolName)
		if serverName == "" || toolName == "" || len(serverName) > 200 || len(toolName) > 200 {
			badRequest(c, "invalid_mcp_tools", "工具配置包含非法名称")
			return
		}
		if item.Enabled == nil {
			badRequest(c, "invalid_mcp_tools", "工具配置缺少 enabled 字段")
			return
		}
		capability := string(policy.DefaultCapability(toolName))
		if item.Capability != nil {
			normalized, valid := policy.NormalizeCapability(*item.Capability)
			if !valid {
				badRequest(c, "invalid_mcp_tools", "工具能力标签不合法")
				return
			}
			capability = string(normalized)
		}
		settings = append(settings, database.MCPToolSetting{
			ServerName: serverName,
			ToolName:   toolName,
			Enabled:    *item.Enabled,
			Capability: capability,
			UpdatedAt:  now,
		})
	}
	if err := h.db.UpsertMCPToolSettings(c.Request.Context(), settings); err != nil {
		internalError(c, "update_mcp_tools_failed", "保存工具配置失败")
		return
	}
	c.JSON(http.StatusOK, gin.H{"saved": len(settings)})
}

func toolParameters(info *schema.ToolInfo) []mcpToolParameter {
	if info == nil || info.ParamsOneOf == nil {
		return []mcpToolParameter{}
	}
	raw, err := info.ParamsOneOf.ToJSONSchema()
	if err != nil || raw == nil {
		return []mcpToolParameter{}
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return []mcpToolParameter{}
	}
	var parsed struct {
		Properties map[string]struct {
			Type        string   `json:"type"`
			Description string   `json:"description"`
			Enum        []string `json:"enum"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(encoded, &parsed); err != nil {
		return []mcpToolParameter{}
	}
	required := make(map[string]bool, len(parsed.Required))
	for _, name := range parsed.Required {
		required[name] = true
	}
	names := make([]string, 0, len(parsed.Properties))
	for name := range parsed.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	items := make([]mcpToolParameter, 0, len(names))
	for _, name := range names {
		property := parsed.Properties[name]
		items = append(items, mcpToolParameter{
			Name:        name,
			Type:        property.Type,
			Description: property.Description,
			Required:    required[name],
			Enum:        property.Enum,
		})
	}
	return items
}

func buildMCPServer(base database.MCPServer, request mcpServerRequest) (database.MCPServer, error) {
	name := truncateRunes(request.Name, 60)
	if strings.TrimSpace(name) == "" {
		return base, fmt.Errorf("服务名称不能为空")
	}
	transport := strings.ToLower(strings.TrimSpace(request.Transport))
	if transport == "" {
		transport = "stdio"
	}
	if transport != "stdio" && transport != "sse" {
		return base, fmt.Errorf("transport 仅支持 stdio 或 sse")
	}
	command := strings.TrimSpace(request.Command)
	if transport == "stdio" && command == "" {
		return base, fmt.Errorf("stdio 服务需要填写启动命令")
	}
	url := strings.TrimSpace(request.URL)
	if transport == "sse" && url == "" {
		return base, fmt.Errorf("sse 服务需要填写 url")
	}

	base.Name = name
	base.Transport = transport
	base.Command = command
	base.Args = normalizeMCPArgs(request.Args)
	base.Env = normalizeMCPEnv(request.Env)
	base.URL = url
	base.Description = truncateRunes(request.Description, 200)
	base.Enabled = request.Enabled == nil || *request.Enabled
	return base, nil
}

func normalizeMCPArgs(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		result = append(result, value)
		if len(result) >= 32 {
			break
		}
	}
	return result
}

func normalizeMCPEnv(values map[string]string) map[string]string {
	result := map[string]string{}
	for key, value := range values {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		result[key] = strings.TrimSpace(value)
		if len(result) >= 32 {
			break
		}
	}
	return result
}
