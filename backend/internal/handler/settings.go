package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	agentpkg "sophon/internal/agent"
	"sophon/internal/config"
	knowledgepkg "sophon/internal/knowledge"

	"github.com/gin-gonic/gin"
)

type SettingsHandler struct {
	mu             sync.RWMutex
	cfg            config.Config
	knowledge      *knowledgepkg.Service
	agent          *agentpkg.Service
	configPath     string
	llmKeyStatusMu sync.Mutex
	llmKeyStatuses map[string]llmKeyStatus

	llmKeyProbeMu      sync.Mutex
	llmKeyProbeLast    map[string]time.Time
	llmKeyProbeRunning map[string]bool
}

func NewSettingsHandler(
	cfg config.Config,
	knowledgeService *knowledgepkg.Service,
	agentService *agentpkg.Service,
) *SettingsHandler {
	return &SettingsHandler{
		cfg:                cfg,
		knowledge:          knowledgeService,
		agent:              agentService,
		configPath:         strings.TrimSpace(cfg.ConfigPath),
		llmKeyStatuses:     map[string]llmKeyStatus{},
		llmKeyProbeLast:    map[string]time.Time{},
		llmKeyProbeRunning: map[string]bool{},
	}
}

func (h *SettingsHandler) currentConfig() config.Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}

func (h *SettingsHandler) AIStatus(c *gin.Context) {
	cfg := h.currentConfig()

	knowledgeMode := "disabled"
	knowledgeDimensions := 0
	if h.knowledge != nil {
		knowledgeMode = h.knowledge.Mode()
		knowledgeDimensions = h.knowledge.Dimensions()
	}

	envLocked := make([]string, 0)
	envFields := map[string]string{
		"llm.provider":               "SOPHON_LLM_PROVIDER",
		"llm.apiKey":                 "SOPHON_LLM_API_KEY",
		"llm.apiKeys":                "SOPHON_LLM_API_KEYS",
		"llm.baseUrl":                "SOPHON_LLM_BASE_URL",
		"llm.model":                  "SOPHON_LLM_MODEL",
		"llm.allowPrivateNetwork":    "SOPHON_LLM_ALLOW_PRIVATE_NETWORK",
		"llm.timeoutSeconds":         "SOPHON_LLM_TIMEOUT_SECONDS",
		"agent.mock":                 "SOPHON_AGENT_MOCK",
		"agent.contextMaxChars":      "SOPHON_AGENT_CONTEXT_MAX_CHARS",
		"agent.maxIterations":        "SOPHON_AGENT_MAX_ITERATIONS",
		"hitl.enabled":               "SOPHON_HITL_ENABLED",
		"hitl.tools":                 "SOPHON_HITL_TOOLS",
		"hitl.timeoutSeconds":        "SOPHON_HITL_TIMEOUT_SECONDS",
		"mcp.callTimeoutSeconds":     "SOPHON_MCP_CALL_TIMEOUT_SECONDS",
		"mcp.maxConcurrentPerServer": "SOPHON_MCP_MAX_CONCURRENT_PER_SERVER",
		"mcp.maxConcurrentTotal":     "SOPHON_MCP_MAX_CONCURRENT_TOTAL",
		"proxy.enabled":              "SOPHON_PROXY_ENABLED",
		"proxy.type":                 "SOPHON_PROXY_TYPE",
		"proxy.host":                 "SOPHON_PROXY_HOST",
		"proxy.port":                 "SOPHON_PROXY_PORT",
		"proxy.username":             "SOPHON_PROXY_USERNAME",
		"proxy.password":             "SOPHON_PROXY_PASSWORD",
		"proxy.noProxy":              "SOPHON_PROXY_NO_PROXY",
	}
	for field, envKey := range envFields {
		if config.EnvLocked(envKey) {
			envLocked = append(envLocked, field)
		}
	}
	if config.EnvLocked("SOPHON_LLM_API_KEY") {
		envLocked = append(envLocked, "llm.apiKeys")
	}
	if config.EnvLocked("SOPHON_LLM_API_KEYS") {
		envLocked = append(envLocked, "llm.apiKey")
	}
	llmAPIKeys := effectiveLLMAPIKeys(cfg)

	c.JSON(http.StatusOK, gin.H{
		"configPath": h.configPath,
		"editable":   h.configPath != "",
		"envLocked":  envLocked,
		"requiresRestart": []string{
			"mcp.callTimeoutSeconds",
			"mcp.maxConcurrentPerServer",
			"mcp.maxConcurrentTotal",
			"embedding",
		},
		"values": gin.H{
			"llm": gin.H{
				"provider":            cfg.LLMProvider,
				"baseUrl":             cfg.LLMBaseURL,
				"apiKey":              config.MaskSecret(cfg.LLMAPIKey),
				"apiKeys":             maskedLLMAPIKeys(llmAPIKeys),
				"apiKeyCount":         len(llmAPIKeys),
				"model":               cfg.LLMModel,
				"allowPrivateNetwork": cfg.LLMAllowPrivateNetwork,
				"timeoutSeconds":      cfg.LLMTimeoutSeconds,
				"configured":          len(llmAPIKeys) > 0,
				"mock":                cfg.AgentMock,
			},
			"agent": gin.H{
				"mock":            cfg.AgentMock,
				"contextMaxChars": cfg.AgentContextMaxChars,
				"maxTurnTokens":   cfg.AgentMaxTurnTokens,
				"maxIterations":   cfg.AgentMaxIterations,
				"maxHypotheses":   cfg.AgentMaxHypotheses,
			},
			"hitl": gin.H{
				"enabled":        cfg.HITLEnabled,
				"tools":          splitList(cfg.HITLTools),
				"timeoutSeconds": cfg.HITLTimeoutSeconds,
			},
			"mcp": gin.H{
				"callTimeoutSeconds":     cfg.MCPCallTimeout,
				"maxConcurrentPerServer": cfg.MCPMaxConcurrentPerServer,
				"maxConcurrentTotal":     cfg.MCPMaxConcurrentTotal,
			},
			"embedding": gin.H{
				"baseUrl":    cfg.EmbeddingBaseURL,
				"model":      cfg.EmbeddingModel,
				"mode":       knowledgeMode,
				"dimensions": knowledgeDimensions,
				"configured": strings.TrimSpace(cfg.EmbeddingAPIKey) != "",
				"mock":       cfg.EmbeddingMock,
			},
			"proxy": gin.H{
				"enabled":  cfg.Proxy.Enabled,
				"type":     cfg.Proxy.Type,
				"host":     cfg.Proxy.Host,
				"port":     cfg.Proxy.Port,
				"username": cfg.Proxy.Username,
				"password": config.MaskSecret(cfg.Proxy.Password),
				"noProxy":  cfg.Proxy.NoProxy,
			},
		},
	})
}

type settingsLLMRequest struct {
	Provider            *string `json:"provider"`
	BaseURL             *string `json:"baseUrl"`
	APIKey              *string `json:"apiKey"`
	APIKeys             *string `json:"apiKeys"`
	Model               *string `json:"model"`
	AllowPrivateNetwork *bool   `json:"allowPrivateNetwork"`
	TimeoutSeconds      *int    `json:"timeoutSeconds"`
}

type settingsAgentRequest struct {
	Mock            *bool `json:"mock"`
	ContextMaxChars *int  `json:"contextMaxChars"`
	MaxTurnTokens   *int  `json:"maxTurnTokens"`
	MaxIterations   *int  `json:"maxIterations"`
	MaxHypotheses   *int  `json:"maxHypotheses"`
}

type settingsHITLRequest struct {
	Enabled        *bool     `json:"enabled"`
	Tools          *[]string `json:"tools"`
	TimeoutSeconds *int      `json:"timeoutSeconds"`
}

type settingsMCPRequest struct {
	CallTimeoutSeconds     *int `json:"callTimeoutSeconds"`
	MaxConcurrentPerServer *int `json:"maxConcurrentPerServer"`
	MaxConcurrentTotal     *int `json:"maxConcurrentTotal"`
}

type settingsProxyRequest struct {
	Enabled  *bool   `json:"enabled"`
	Type     *string `json:"type"`
	Host     *string `json:"host"`
	Port     *int    `json:"port"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	NoProxy  *string `json:"noProxy"`
}

type settingsUpdateRequest struct {
	LLM   *settingsLLMRequest   `json:"llm"`
	Agent *settingsAgentRequest `json:"agent"`
	HITL  *settingsHITLRequest  `json:"hitl"`
	MCP   *settingsMCPRequest   `json:"mcp"`
	Proxy *settingsProxyRequest `json:"proxy"`
}

func (h *SettingsHandler) Update(c *gin.Context) {
	configMutationMu.Lock()
	defer configMutationMu.Unlock()
	if h.configPath == "" {
		badRequest(c, "config_not_writable", "未找到 config.yml，无法保存在线修改")
		return
	}
	var request settingsUpdateRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_settings", "设置请求格式错误")
		return
	}

	next := h.currentConfig()
	updates := make([]config.FieldUpdate, 0, 12)
	reloaded := make([]string, 0, 8)
	// lockState 返回是否写入该字段、是否已中断请求：
	// 环境变量锁定且请求值与当前生效值一致时跳过写入，避免单个锁定字段阻断整页保存；
	// 锁定字段发生变化时拒绝保存。
	lockState := func(field, envKey string, changed bool) (apply bool, abort bool) {
		if !config.EnvLocked(envKey) {
			return true, false
		}
		if changed {
			badRequest(c, "settings_env_locked", "字段 "+field+" 由环境变量锁定，请修改环境变量")
			return false, true
		}
		return false, false
	}

	if request.LLM != nil {
		if request.LLM.Provider != nil {
			value := strings.ToLower(strings.TrimSpace(*request.LLM.Provider))
			switch value {
			case "openai", "openai_compatible":
				value = "openai_compatible"
			case "anthropic", "claude":
				value = "anthropic"
			default:
				badRequest(c, "invalid_settings", "LLM 接口格式需为 openai_compatible 或 anthropic")
				return
			}
			apply, abort := lockState("llm.provider", "SOPHON_LLM_PROVIDER", value != next.LLMProvider)
			if abort {
				return
			}
			if apply {
				next.LLMProvider = value
				updates = append(updates, config.FieldUpdate{Path: []string{"agent", "llm", "provider"}, Value: value})
			}
		}
		if request.LLM.BaseURL != nil {
			value := strings.TrimSpace(*request.LLM.BaseURL)
			if err := validateHTTPURL(value); err != nil {
				badRequest(c, "invalid_settings", "LLM API 地址不合法")
				return
			}
			apply, abort := lockState("llm.baseUrl", "SOPHON_LLM_BASE_URL", value != next.LLMBaseURL)
			if abort {
				return
			}
			if apply {
				next.LLMBaseURL = value
				updates = append(updates, config.FieldUpdate{Path: []string{"agent", "llm", "base_url"}, Value: value})
			}
		}
		if request.LLM.APIKeys != nil || request.LLM.APIKey != nil {
			raw := ""
			if request.LLM.APIKeys != nil {
				raw = *request.LLM.APIKeys
			} else if request.LLM.APIKey != nil {
				raw = *request.LLM.APIKey
			}
			keys, changed, errText := parseSettingsLLMAPIKeys(raw)
			if errText != "" {
				badRequest(c, "invalid_settings", errText)
				return
			}
			if changed {
				current := effectiveLLMAPIKeys(next)
				changed = !sameStrings(current, keys)
			}
			if changed {
				if config.EnvLocked("SOPHON_LLM_API_KEYS") || config.EnvLocked("SOPHON_LLM_API_KEY") {
					badRequest(c, "settings_env_locked", "字段 llm.apiKeys 由环境变量锁定，请修改环境变量")
					return
				}
				next.LLMAPIKeys = keys
				next.LLMAPIKey = keys[0]
				updates = append(
					updates,
					config.FieldUpdate{Path: []string{"agent", "llm", "api_keys"}, Value: keys},
					config.FieldUpdate{Path: []string{"agent", "llm", "api_key"}, Value: ""},
				)
			}
		}
		if request.LLM.Model != nil {
			value := strings.TrimSpace(*request.LLM.Model)
			if value == "" {
				badRequest(c, "invalid_settings", "模型名称不能为空")
				return
			}
			apply, abort := lockState("llm.model", "SOPHON_LLM_MODEL", value != next.LLMModel)
			if abort {
				return
			}
			if apply {
				next.LLMModel = value
				updates = append(updates, config.FieldUpdate{Path: []string{"agent", "llm", "model"}, Value: value})
			}
		}
		if request.LLM.AllowPrivateNetwork != nil {
			value := *request.LLM.AllowPrivateNetwork
			apply, abort := lockState(
				"llm.allowPrivateNetwork",
				"SOPHON_LLM_ALLOW_PRIVATE_NETWORK",
				value != next.LLMAllowPrivateNetwork,
			)
			if abort {
				return
			}
			if apply {
				next.LLMAllowPrivateNetwork = value
				updates = append(updates, config.FieldUpdate{
					Path:  []string{"agent", "llm", "allow_private_network"},
					Value: value,
				})
			}
		}
		if request.LLM.TimeoutSeconds != nil {
			value := *request.LLM.TimeoutSeconds
			if value < 1 || value > 3600 {
				badRequest(c, "invalid_settings", "LLM 超时需在 1-3600 秒之间")
				return
			}
			apply, abort := lockState("llm.timeoutSeconds", "SOPHON_LLM_TIMEOUT_SECONDS", value != next.LLMTimeoutSeconds)
			if abort {
				return
			}
			if apply {
				next.LLMTimeoutSeconds = value
				updates = append(updates, config.FieldUpdate{Path: []string{"agent", "llm", "timeout_seconds"}, Value: value})
			}
		}
		reloaded = append(reloaded, "llm")
	}

	if request.Agent != nil {
		if request.Agent.Mock != nil {
			apply, abort := lockState("agent.mock", "SOPHON_AGENT_MOCK", *request.Agent.Mock != next.AgentMock)
			if abort {
				return
			}
			if apply {
				next.AgentMock = *request.Agent.Mock
				updates = append(updates, config.FieldUpdate{Path: []string{"agent", "mock"}, Value: *request.Agent.Mock})
			}
		}
		if request.Agent.ContextMaxChars != nil {
			value := *request.Agent.ContextMaxChars
			if value < 1000 || value > 200000 {
				badRequest(c, "invalid_settings", "上下文上限需在 1000-200000 之间")
				return
			}
			apply, abort := lockState("agent.contextMaxChars", "SOPHON_AGENT_CONTEXT_MAX_CHARS", value != next.AgentContextMaxChars)
			if abort {
				return
			}
			if apply {
				next.AgentContextMaxChars = value
				updates = append(updates, config.FieldUpdate{Path: []string{"agent", "context_max_chars"}, Value: value})
			}
		}
		if request.Agent.MaxIterations != nil {
			value := *request.Agent.MaxIterations
			if value < 0 || value > 1000 {
				badRequest(c, "invalid_settings", "最大迭代数需在 0-1000 之间，0 表示不限")
				return
			}
			apply, abort := lockState("agent.maxIterations", "SOPHON_AGENT_MAX_ITERATIONS", value != next.AgentMaxIterations)
			if abort {
				return
			}
			if apply {
				next.AgentMaxIterations = value
				updates = append(updates, config.FieldUpdate{Path: []string{"agent", "max_iterations"}, Value: value})
			}
		}
		if request.Agent.MaxTurnTokens != nil {
			value := *request.Agent.MaxTurnTokens
			if value < 0 || value > 100000000 {
				badRequest(c, "invalid_settings", "单轮 token 上限需在 0-100000000 之间")
				return
			}
			apply, abort := lockState("agent.maxTurnTokens", "SOPHON_AGENT_MAX_TURN_TOKENS", value != next.AgentMaxTurnTokens)
			if abort {
				return
			}
			if apply {
				next.AgentMaxTurnTokens = value
				updates = append(updates, config.FieldUpdate{Path: []string{"agent", "max_turn_tokens"}, Value: value})
			}
		}
		if request.Agent.MaxHypotheses != nil {
			value := *request.Agent.MaxHypotheses
			if value < 0 || value > 2000 {
				badRequest(c, "invalid_settings", "活跃假设上限需在 0-2000 之间，0 表示不限")
				return
			}
			apply, abort := lockState("agent.maxHypotheses", "SOPHON_AGENT_MAX_HYPOTHESES", value != next.AgentMaxHypotheses)
			if abort {
				return
			}
			if apply {
				next.AgentMaxHypotheses = value
				updates = append(updates, config.FieldUpdate{Path: []string{"agent", "max_hypotheses"}, Value: value})
			}
		}
		reloaded = append(reloaded, "agent")
	}

	if request.HITL != nil {
		if request.HITL.Enabled != nil {
			apply, abort := lockState("hitl.enabled", "SOPHON_HITL_ENABLED", *request.HITL.Enabled != next.HITLEnabled)
			if abort {
				return
			}
			if apply {
				next.HITLEnabled = *request.HITL.Enabled
				updates = append(updates, config.FieldUpdate{Path: []string{"hitl", "enabled"}, Value: *request.HITL.Enabled})
			}
		}
		if request.HITL.Tools != nil {
			tools := make([]string, 0, len(*request.HITL.Tools))
			for _, tool := range *request.HITL.Tools {
				tool = strings.TrimSpace(tool)
				if tool == "" {
					continue
				}
				if strings.ContainsAny(tool, " \t\n,，") {
					badRequest(c, "invalid_settings", "工具名不能包含空格或逗号")
					return
				}
				tools = append(tools, tool)
			}
			joined := strings.Join(tools, ",")
			current := strings.Join(splitList(next.HITLTools), ",")
			apply, abort := lockState("hitl.tools", "SOPHON_HITL_TOOLS", joined != current)
			if abort {
				return
			}
			if apply {
				next.HITLTools = joined
				updates = append(updates, config.FieldUpdate{Path: []string{"hitl", "tools"}, Value: tools})
			}
		}
		if request.HITL.TimeoutSeconds != nil {
			value := *request.HITL.TimeoutSeconds
			if value < 1 || value > 86400 {
				badRequest(c, "invalid_settings", "审批超时需在 1-86400 秒之间")
				return
			}
			apply, abort := lockState("hitl.timeoutSeconds", "SOPHON_HITL_TIMEOUT_SECONDS", value != next.HITLTimeoutSeconds)
			if abort {
				return
			}
			if apply {
				next.HITLTimeoutSeconds = value
				updates = append(updates, config.FieldUpdate{Path: []string{"hitl", "timeout_seconds"}, Value: value})
			}
		}
		reloaded = append(reloaded, "hitl")
	}

	requiresRestart := make([]string, 0, 2)
	if request.MCP != nil {
		if request.MCP.CallTimeoutSeconds != nil {
			value := *request.MCP.CallTimeoutSeconds
			if value < 1 || value > 3600 {
				badRequest(c, "invalid_settings", "工具等待时长需在 1-3600 秒之间")
				return
			}
			apply, abort := lockState("mcp.callTimeoutSeconds", "SOPHON_MCP_CALL_TIMEOUT_SECONDS", value != next.MCPCallTimeout)
			if abort {
				return
			}
			if apply {
				next.MCPCallTimeout = value
				updates = append(updates, config.FieldUpdate{Path: []string{"mcp", "call_timeout_seconds"}, Value: value})
				requiresRestart = append(requiresRestart, "mcp.callTimeoutSeconds")
			}
		}
		if request.MCP.MaxConcurrentPerServer != nil {
			value := *request.MCP.MaxConcurrentPerServer
			if value < -1 || value > 128 {
				badRequest(c, "invalid_settings", "单服务并发上限需在 -1 到 128 之间")
				return
			}
			apply, abort := lockState("mcp.maxConcurrentPerServer", "SOPHON_MCP_MAX_CONCURRENT_PER_SERVER", value != next.MCPMaxConcurrentPerServer)
			if abort {
				return
			}
			if apply {
				next.MCPMaxConcurrentPerServer = value
				updates = append(updates, config.FieldUpdate{Path: []string{"mcp", "max_concurrent_per_server"}, Value: value})
				requiresRestart = append(requiresRestart, "mcp.maxConcurrentPerServer")
			}
		}
		if request.MCP.MaxConcurrentTotal != nil {
			value := *request.MCP.MaxConcurrentTotal
			if value < -1 || value > 512 {
				badRequest(c, "invalid_settings", "全局并发上限需在 -1 到 512 之间")
				return
			}
			apply, abort := lockState("mcp.maxConcurrentTotal", "SOPHON_MCP_MAX_CONCURRENT_TOTAL", value != next.MCPMaxConcurrentTotal)
			if abort {
				return
			}
			if apply {
				next.MCPMaxConcurrentTotal = value
				updates = append(updates, config.FieldUpdate{Path: []string{"mcp", "max_concurrent_total"}, Value: value})
				requiresRestart = append(requiresRestart, "mcp.maxConcurrentTotal")
			}
		}
	}

	if request.Proxy != nil {
		if request.Proxy.Enabled != nil {
			apply, abort := lockState("proxy.enabled", "SOPHON_PROXY_ENABLED", *request.Proxy.Enabled != next.Proxy.Enabled)
			if abort {
				return
			}
			if apply {
				next.Proxy.Enabled = *request.Proxy.Enabled
				updates = append(updates, config.FieldUpdate{Path: []string{"proxy", "enabled"}, Value: *request.Proxy.Enabled})
			}
		}
		if request.Proxy.Type != nil {
			value, ok := normalizeProxyTypeInput(*request.Proxy.Type)
			if !ok {
				badRequest(c, "invalid_settings", "代理类型仅支持 http、https、socks5")
				return
			}
			apply, abort := lockState("proxy.type", "SOPHON_PROXY_TYPE", value != next.Proxy.Type)
			if abort {
				return
			}
			if apply {
				next.Proxy.Type = value
				updates = append(updates, config.FieldUpdate{Path: []string{"proxy", "type"}, Value: value})
			}
		}
		if request.Proxy.Host != nil {
			value := strings.TrimSpace(*request.Proxy.Host)
			if len([]rune(value)) > 255 {
				badRequest(c, "invalid_settings", "代理主机不能超过 255 个字符")
				return
			}
			apply, abort := lockState("proxy.host", "SOPHON_PROXY_HOST", value != next.Proxy.Host)
			if abort {
				return
			}
			if apply {
				next.Proxy.Host = value
				updates = append(updates, config.FieldUpdate{Path: []string{"proxy", "host"}, Value: value})
			}
		}
		if request.Proxy.Port != nil {
			value := *request.Proxy.Port
			if value < 0 || value > 65535 {
				badRequest(c, "invalid_settings", "代理端口需在 0-65535 之间")
				return
			}
			apply, abort := lockState("proxy.port", "SOPHON_PROXY_PORT", value != next.Proxy.Port)
			if abort {
				return
			}
			if apply {
				next.Proxy.Port = value
				updates = append(updates, config.FieldUpdate{Path: []string{"proxy", "port"}, Value: value})
			}
		}
		if request.Proxy.Username != nil {
			value := strings.TrimSpace(*request.Proxy.Username)
			if len([]rune(value)) > 512 {
				badRequest(c, "invalid_settings", "代理用户名不能超过 512 个字符")
				return
			}
			apply, abort := lockState("proxy.username", "SOPHON_PROXY_USERNAME", value != next.Proxy.Username)
			if abort {
				return
			}
			if apply {
				if value != next.Proxy.Username && (request.Proxy.Password == nil || strings.TrimSpace(*request.Proxy.Password) == "") && !config.EnvLocked("SOPHON_PROXY_PASSWORD") {
					next.Proxy.Password = ""
					updates = append(updates, config.FieldUpdate{Path: []string{"proxy", "password"}, Value: ""})
				}
				next.Proxy.Username = value
				updates = append(updates, config.FieldUpdate{Path: []string{"proxy", "username"}, Value: value})
			}
		}
		if request.Proxy.Password != nil {
			value := *request.Proxy.Password
			changed := value != "" && !strings.Contains(value, "****") && value != next.Proxy.Password
			if changed {
				if len([]rune(value)) > 512 {
					badRequest(c, "invalid_settings", "代理密码不能超过 512 个字符")
					return
				}
			}
			apply, abort := lockState("proxy.password", "SOPHON_PROXY_PASSWORD", changed)
			if abort {
				return
			}
			if apply && changed {
				next.Proxy.Password = value
				updates = append(updates, config.FieldUpdate{Path: []string{"proxy", "password"}, Value: value})
			}
		}
		if request.Proxy.NoProxy != nil {
			value := strings.TrimSpace(*request.Proxy.NoProxy)
			if len([]rune(value)) > 4096 {
				badRequest(c, "invalid_settings", "NO_PROXY 不能超过 4096 个字符")
				return
			}
			apply, abort := lockState("proxy.noProxy", "SOPHON_PROXY_NO_PROXY", value != next.Proxy.NoProxy)
			if abort {
				return
			}
			if apply {
				next.Proxy.NoProxy = value
				updates = append(updates, config.FieldUpdate{Path: []string{"proxy", "no_proxy"}, Value: value})
			}
		}
		if err := next.Proxy.Validate(); err != nil {
			badRequest(c, "invalid_settings", err.Error())
			return
		}
		reloaded = append(reloaded, "proxy.llm")
		requiresRestart = append(requiresRestart, "proxy.mcp", "proxy.embedding", "proxy.tools")
	}

	if len(updates) == 0 {
		badRequest(c, "invalid_settings", "没有需要保存的修改")
		return
	}
	if err := config.UpdateFile(h.configPath, updates); err != nil {
		internalError(c, "save_settings_failed", err.Error())
		return
	}

	if h.agent != nil {
		if err := h.agent.Reload(next); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"code":    "reload_agent_failed",
				"message": "配置已保存，但热更新失败，请重启服务",
				"saved":   true,
			})
			return
		}
	}
	h.mu.Lock()
	h.cfg = next
	h.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{
		"saved":           true,
		"reloaded":        reloaded,
		"requiresRestart": requiresRestart,
	})
}

func validateHTTPURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("仅支持 http/https 地址")
	}
	if strings.TrimSpace(parsed.Host) == "" {
		return fmt.Errorf("地址缺少主机名")
	}
	return nil
}

func normalizeProxyTypeInput(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "http":
		return "http", true
	case "https":
		return "https", true
	case "socks5", "socks5h":
		return "socks5", true
	default:
		return "", false
	}
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func effectiveLLMAPIKeys(cfg config.Config) []string {
	keys := config.NormalizeLLMAPIKeys(cfg.LLMAPIKeys)
	if len(keys) > 0 {
		return keys
	}
	if value := strings.TrimSpace(cfg.LLMAPIKey); value != "" {
		return []string{value}
	}
	return nil
}

func maskedLLMAPIKeys(keys []string) []string {
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, config.MaskSecret(key))
	}
	return result
}

func parseSettingsLLMAPIKeys(raw string) ([]string, bool, string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	if strings.TrimSpace(raw) == "" || strings.Contains(raw, "****") {
		return nil, false, ""
	}
	lines := strings.Split(raw, "\n")
	keys := make([]string, 0, len(lines))
	seen := make(map[string]bool, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || seen[line] {
			continue
		}
		if len(line) > 4096 {
			return nil, false, "单个 API Key 不能超过 4096 个字符"
		}
		seen[line] = true
		keys = append(keys, line)
		if len(keys) > 20 {
			return nil, false, "最多配置 20 个 API Key"
		}
	}
	if len(keys) == 0 {
		return nil, false, ""
	}
	return keys, true, ""
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
