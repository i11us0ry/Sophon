package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigName   = "config.yml"
	defaultExampleName  = "config.example.yml"
	fallbackConfigPath  = "/opt/sophon/config.yml"
	maxConfigValueLimit = 65535
)

type Config struct {
	Host                       string
	Port                       int
	DataDir                    string
	Version                    string
	SessionDurationHours       int
	CookieSecure               bool
	BootstrapAdminUsername     string
	BootstrapAdminPassword     string
	LLMProvider                string
	LLMBaseURL                 string
	LLMAPIKey                  string
	LLMAPIKeys                 []string
	LLMModel                   string
	LLMAllowPrivateNetwork     bool
	LLMTimeoutSeconds          int
	AgentMock                  bool
	EmbeddingBaseURL           string
	EmbeddingAPIKey            string
	EmbeddingModel             string
	EmbeddingDimensions        int
	EmbeddingTimeout           int
	EmbeddingMock              bool
	AgentContextMaxChars       int
	AgentContextMaxTokens      int
	AgentMaxTurnTokens         int
	AgentMaxIterations         int
	AgentMaxHypotheses         int
	AgentMaxConcurrentSessions int
	AgentSubagentConcurrency   int
	AgentSubagentMaxToolCalls  int
	AgentSubagentMaxDuration   int
	AgentSubagentMaxCPUSeconds int
	AgentSubagentMaxProcesses  int
	HITLEnabled                bool
	HITLTools                  string
	HITLTimeoutSeconds         int
	MCPCommand                 string
	MCPConnectTimeout          int
	MCPCallTimeout             int
	MCPMaxConcurrentPerServer  int
	MCPMaxConcurrentTotal      int
	Proxy                      ProxyConfig
	SkillsDir                  string
	RolesDir                   string
	ConfigPath                 string
	Storage                    StorageConfig
	Observability              ObservabilityConfig
}

type fileConfig struct {
	Version   *string          `yaml:"version"`
	Server    serverSection    `yaml:"server"`
	Auth      authSection      `yaml:"auth"`
	Agent     agentSection     `yaml:"agent"`
	Embedding embeddingSection `yaml:"embedding"`
	HITL      hitlSection      `yaml:"hitl"`
	MCP       mcpSection       `yaml:"mcp"`
	Proxy     proxySection     `yaml:"proxy"`
	Storage   storageSection   `yaml:"storage"`
	// Observability 控制本地事件流输出（JSONL），供外部采集与聚合。
	Observability observabilitySection `yaml:"observability"`
}

// ObservabilityConfig 是运行事件流配置；默认只写元数据，不写提示词与工具参数。
type ObservabilityConfig struct {
	Enabled    bool
	JSONLPath  string
	MaxFileMB  int
	SampleRate float64
}

type observabilitySection struct {
	Enabled    *bool    `yaml:"enabled"`
	JSONLPath  *string  `yaml:"jsonl_path"`
	MaxFileMB  *int     `yaml:"max_file_mb"`
	SampleRate *float64 `yaml:"sample_rate"`
}

type serverSection struct {
	Host         *string `yaml:"host"`
	Port         *int    `yaml:"port"`
	DataDir      *string `yaml:"data_dir"`
	SkillsDir    *string `yaml:"skills_dir"`
	RolesDir     *string `yaml:"roles_dir"`
	CookieSecure *bool   `yaml:"cookie_secure"`
}

type authSection struct {
	SessionDurationHours *int `yaml:"session_duration_hours"`
	BootstrapAdmin       struct {
		Username *string `yaml:"username"`
		Password *string `yaml:"password"`
	} `yaml:"bootstrap_admin"`
}

type agentSection struct {
	Mock                   *bool      `yaml:"mock"`
	ContextMaxChars        *int       `yaml:"context_max_chars"`
	ContextMaxTokens       *int       `yaml:"context_max_tokens"`
	MaxTurnTokens          *int       `yaml:"max_turn_tokens"`
	MaxIterations          *int       `yaml:"max_iterations"`
	MaxHypotheses          *int       `yaml:"max_hypotheses"`
	MaxConcurrentSessions  *int       `yaml:"max_concurrent_sessions"`
	SubagentMaxConcurrency *int       `yaml:"subagent_max_concurrency"`
	SubagentMaxToolCalls   *int       `yaml:"subagent_max_tool_calls"`
	SubagentMaxDuration    *int       `yaml:"subagent_max_duration_seconds"`
	SubagentMaxCPUSeconds  *int       `yaml:"subagent_max_cpu_seconds"`
	SubagentMaxProcesses   *int       `yaml:"subagent_max_processes"`
	LLM                    llmSection `yaml:"llm"`
}

type llmSection struct {
	Provider            *string  `yaml:"provider"`
	BaseURL             *string  `yaml:"base_url"`
	APIKey              *string  `yaml:"api_key"`
	APIKeys             []string `yaml:"api_keys"`
	Model               *string  `yaml:"model"`
	AllowPrivateNetwork *bool    `yaml:"allow_private_network"`
	TimeoutSeconds      *int     `yaml:"timeout_seconds"`
}

type embeddingSection struct {
	Mock           *bool   `yaml:"mock"`
	BaseURL        *string `yaml:"base_url"`
	APIKey         *string `yaml:"api_key"`
	Model          *string `yaml:"model"`
	Dimensions     *int    `yaml:"dimensions"`
	TimeoutSeconds *int    `yaml:"timeout_seconds"`
}

type hitlSection struct {
	Enabled        *bool    `yaml:"enabled"`
	Tools          []string `yaml:"tools"`
	TimeoutSeconds *int     `yaml:"timeout_seconds"`
}

type mcpSection struct {
	Command                *string `yaml:"command"`
	ConnectTimeoutSeconds  *int    `yaml:"connect_timeout_seconds"`
	CallTimeoutSeconds     *int    `yaml:"call_timeout_seconds"`
	MaxConcurrentPerServer *int    `yaml:"max_concurrent_per_server"`
	MaxConcurrentTotal     *int    `yaml:"max_concurrent_total"`
}

type proxySection struct {
	Enabled  *bool   `yaml:"enabled"`
	Type     *string `yaml:"type"`
	Host     *string `yaml:"host"`
	Port     *int    `yaml:"port"`
	Username *string `yaml:"username"`
	Password *string `yaml:"password"`
	NoProxy  *string `yaml:"no_proxy"`
}

type StorageCategoryConfig struct {
	Enabled       bool
	RetentionDays int
	Path          string
}

type StorageConfig struct {
	AutoClean        bool
	IntervalMinutes  int
	ArtifactRoot     string
	ActiveGraceHours int
	Categories       map[string]StorageCategoryConfig
}

func defaultStorageConfig() StorageConfig {
	return StorageConfig{
		AutoClean:        false,
		IntervalMinutes:  60,
		ArtifactRoot:     "",
		ActiveGraceHours: 24,
		Categories: map[string]StorageCategoryConfig{
			"audit_logs":             {Enabled: true, RetentionDays: 90},
			"tool_executions":        {Enabled: true, RetentionDays: 90},
			"tool_jobs":              {Enabled: true, RetentionDays: 30},
			"token_usage":            {Enabled: true, RetentionDays: 180},
			"hitl_requests":          {Enabled: true, RetentionDays: 90},
			"process_details":        {Enabled: true, RetentionDays: 30},
			"reasoning_content":      {Enabled: true, RetentionDays: 30},
			"context_compactions":    {Enabled: true, RetentionDays: 180},
			"memory_writes":          {Enabled: true, RetentionDays: 180},
			"workspace":              {Enabled: true, RetentionDays: 30, Path: "tmp/workspace"},
			"reduction":              {Enabled: true, RetentionDays: 7, Path: "tmp/reduction"},
			"conversation_artifacts": {Enabled: true, RetentionDays: 30, Path: "data/conversation_artifacts"},
			"chat_uploads":           {Enabled: true, RetentionDays: 90, Path: "chat_uploads"},
		},
	}
}

type storageSection struct {
	AutoClean        *bool   `yaml:"auto_clean"`
	IntervalMinutes  *int    `yaml:"interval_minutes"`
	ArtifactRoot     *string `yaml:"artifact_root"`
	ActiveGraceHours *int    `yaml:"active_grace_hours"`
	Categories       map[string]struct {
		Enabled       *bool   `yaml:"enabled"`
		RetentionDays *int    `yaml:"retention_days"`
		Path          *string `yaml:"path"`
	} `yaml:"categories"`
}

func Load() (Config, error) {
	path := resolveConfigPath()
	file, loadedPath, err := loadConfigFile(path)
	if err != nil {
		return Config{}, err
	}
	dataDir := pickString("SOPHON_DATA_DIR", file.Server.DataDir, "./data")
	llmAPIKeys := resolveLLMAPIKeys(file.Agent.LLM.APIKeys, file.Agent.LLM.APIKey)
	cfg := Config{
		Host:                       pickString("SOPHON_HOST", file.Server.Host, "127.0.0.1"),
		Port:                       pickInt("SOPHON_PORT", file.Server.Port, 18080),
		DataDir:                    dataDir,
		Version:                    pickString("SOPHON_VERSION", file.Version, "dev"),
		SessionDurationHours:       pickInt("SOPHON_SESSION_HOURS", file.Auth.SessionDurationHours, 12),
		CookieSecure:               pickBool("SOPHON_COOKIE_SECURE", file.Server.CookieSecure, false),
		BootstrapAdminUsername:     pickString("SOPHON_ADMIN_USERNAME", file.Auth.BootstrapAdmin.Username, "admin"),
		BootstrapAdminPassword:     pickString("SOPHON_ADMIN_PASSWORD", file.Auth.BootstrapAdmin.Password, ""),
		LLMBaseURL:                 pickString("SOPHON_LLM_BASE_URL", file.Agent.LLM.BaseURL, "https://api.deepseek.com/v1"),
		LLMProvider:                normalizeLLMProvider(pickString("SOPHON_LLM_PROVIDER", file.Agent.LLM.Provider, "openai_compatible")),
		LLMAPIKey:                  firstLLMAPIKey(llmAPIKeys),
		LLMAPIKeys:                 llmAPIKeys,
		LLMModel:                   pickString("SOPHON_LLM_MODEL", file.Agent.LLM.Model, "deepseek-chat"),
		LLMAllowPrivateNetwork:     pickBool("SOPHON_LLM_ALLOW_PRIVATE_NETWORK", file.Agent.LLM.AllowPrivateNetwork, false),
		LLMTimeoutSeconds:          pickInt("SOPHON_LLM_TIMEOUT_SECONDS", file.Agent.LLM.TimeoutSeconds, 120),
		AgentMock:                  pickBool("SOPHON_AGENT_MOCK", file.Agent.Mock, true),
		EmbeddingBaseURL:           pickString("SOPHON_EMBEDDING_BASE_URL", file.Embedding.BaseURL, "https://api.openai.com/v1"),
		EmbeddingAPIKey:            pickString("SOPHON_EMBEDDING_API_KEY", file.Embedding.APIKey, ""),
		EmbeddingModel:             pickString("SOPHON_EMBEDDING_MODEL", file.Embedding.Model, "text-embedding-3-small"),
		EmbeddingDimensions:        pickInt("SOPHON_EMBEDDING_DIMENSIONS", file.Embedding.Dimensions, 256),
		EmbeddingTimeout:           pickInt("SOPHON_EMBEDDING_TIMEOUT_SECONDS", file.Embedding.TimeoutSeconds, 60),
		EmbeddingMock:              pickBool("SOPHON_EMBEDDING_MOCK", file.Embedding.Mock, true),
		AgentContextMaxChars:       pickInt("SOPHON_AGENT_CONTEXT_MAX_CHARS", file.Agent.ContextMaxChars, 24000),
		AgentContextMaxTokens:      pickIntAllowZero("SOPHON_AGENT_CONTEXT_MAX_TOKENS", file.Agent.ContextMaxTokens, 0),
		AgentMaxTurnTokens:         pickIntAllowZero("SOPHON_AGENT_MAX_TURN_TOKENS", file.Agent.MaxTurnTokens, 0),
		AgentMaxIterations:         pickIntAllowZero("SOPHON_AGENT_MAX_ITERATIONS", file.Agent.MaxIterations, 40),
		AgentMaxHypotheses:         normalizeAgentMaxHypotheses(pickIntAllowZero("SOPHON_AGENT_MAX_HYPOTHESES", file.Agent.MaxHypotheses, 200)),
		AgentMaxConcurrentSessions: normalizeAgentMaxConcurrentSessions(pickInt("SOPHON_AGENT_MAX_CONCURRENT_SESSIONS", file.Agent.MaxConcurrentSessions, 5)),
		AgentSubagentConcurrency:   normalizeSubagentMaxConcurrency(pickInt("SOPHON_AGENT_SUBAGENT_MAX_CONCURRENCY", file.Agent.SubagentMaxConcurrency, 2)),
		AgentSubagentMaxToolCalls:  normalizeSubagentMaxToolCalls(pickInt("SOPHON_AGENT_SUBAGENT_MAX_TOOL_CALLS", file.Agent.SubagentMaxToolCalls, 80)),
		AgentSubagentMaxDuration:   normalizeSubagentMaxDuration(pickInt("SOPHON_AGENT_SUBAGENT_MAX_DURATION_SECONDS", file.Agent.SubagentMaxDuration, 1800)),
		AgentSubagentMaxCPUSeconds: normalizeSubagentMaxCPUSeconds(pickInt("SOPHON_AGENT_SUBAGENT_MAX_CPU_SECONDS", file.Agent.SubagentMaxCPUSeconds, 900)),
		AgentSubagentMaxProcesses:  normalizeSubagentMaxProcesses(pickInt("SOPHON_AGENT_SUBAGENT_MAX_PROCESSES", file.Agent.SubagentMaxProcesses, 8)),
		HITLEnabled:                pickBool("SOPHON_HITL_ENABLED", file.HITL.Enabled, true),
		HITLTools:                  pickHITLTools(file.HITL.Tools),
		HITLTimeoutSeconds:         pickInt("SOPHON_HITL_TIMEOUT_SECONDS", file.HITL.TimeoutSeconds, 300),
		MCPCommand:                 pickString("SOPHON_MCP_COMMAND", file.MCP.Command, "/opt/sophon/backend/sophon-mcp-tools"),
		MCPConnectTimeout:          pickInt("SOPHON_MCP_CONNECT_TIMEOUT_SECONDS", file.MCP.ConnectTimeoutSeconds, 20),
		MCPCallTimeout:             pickInt("SOPHON_MCP_CALL_TIMEOUT_SECONDS", file.MCP.CallTimeoutSeconds, 900),
		MCPMaxConcurrentPerServer:  pickIntAllowZero("SOPHON_MCP_MAX_CONCURRENT_PER_SERVER", file.MCP.MaxConcurrentPerServer, 2),
		MCPMaxConcurrentTotal:      pickIntAllowZero("SOPHON_MCP_MAX_CONCURRENT_TOTAL", file.MCP.MaxConcurrentTotal, 16),
		Proxy: ProxyConfig{
			Enabled:  pickBool("SOPHON_PROXY_ENABLED", file.Proxy.Enabled, false),
			Type:     normalizeProxyType(pickString("SOPHON_PROXY_TYPE", file.Proxy.Type, "http")),
			Host:     pickString("SOPHON_PROXY_HOST", file.Proxy.Host, ""),
			Port:     pickIntAllowZero("SOPHON_PROXY_PORT", file.Proxy.Port, 0),
			Username: pickString("SOPHON_PROXY_USERNAME", file.Proxy.Username, ""),
			Password: pickString("SOPHON_PROXY_PASSWORD", file.Proxy.Password, ""),
			NoProxy:  pickString("SOPHON_PROXY_NO_PROXY", file.Proxy.NoProxy, "localhost,127.0.0.1,::1"),
		},
		SkillsDir:  pickString("SOPHON_SKILLS_DIR", file.Server.SkillsDir, "/opt/sophon/skills"),
		RolesDir:   pickString("SOPHON_ROLES_DIR", file.Server.RolesDir, "/opt/sophon/roles"),
		ConfigPath: loadedPath,
		Storage:    buildStorageConfig(file.Storage, dataDir),
		Observability: buildObservabilityConfig(
			file.Observability,
			dataDir,
		),
	}
	if err := cfg.Proxy.Validate(); err != nil {
		return Config{}, fmt.Errorf("代理配置无效: %w", err)
	}
	return cfg, nil
}

// buildObservabilityConfig 组装事件流配置：默认开启，写入 <data_dir>/observability。
func buildObservabilityConfig(section observabilitySection, dataDir string) ObservabilityConfig {
	cfg := ObservabilityConfig{
		Enabled:    true,
		JSONLPath:  filepath.Join(strings.TrimSpace(dataDir), "observability", "events.jsonl"),
		MaxFileMB:  64,
		SampleRate: 1,
	}
	if section.Enabled != nil {
		cfg.Enabled = *section.Enabled
	}
	if section.JSONLPath != nil && strings.TrimSpace(*section.JSONLPath) != "" {
		cfg.JSONLPath = strings.TrimSpace(*section.JSONLPath)
	}
	if section.MaxFileMB != nil && *section.MaxFileMB >= 1 && *section.MaxFileMB <= 4096 {
		cfg.MaxFileMB = *section.MaxFileMB
	}
	if section.SampleRate != nil && *section.SampleRate > 0 && *section.SampleRate <= 1 {
		cfg.SampleRate = *section.SampleRate
	}
	if raw := strings.TrimSpace(os.Getenv("SOPHON_OBSERVABILITY_ENABLED")); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			cfg.Enabled = parsed
		}
	}
	if raw := strings.TrimSpace(os.Getenv("SOPHON_OBSERVABILITY_JSONL_PATH")); raw != "" {
		cfg.JSONLPath = raw
	}
	return cfg
}

func buildStorageConfig(section storageSection, dataDir string) StorageConfig {
	storage := defaultStorageConfig()
	if section.AutoClean != nil {
		storage.AutoClean = *section.AutoClean
	}
	if section.IntervalMinutes != nil && *section.IntervalMinutes >= 5 {
		storage.IntervalMinutes = *section.IntervalMinutes
	}
	if section.ArtifactRoot != nil && strings.TrimSpace(*section.ArtifactRoot) != "" {
		storage.ArtifactRoot = strings.TrimSpace(*section.ArtifactRoot)
	}
	if section.ActiveGraceHours != nil && *section.ActiveGraceHours >= 0 && *section.ActiveGraceHours <= 720 {
		storage.ActiveGraceHours = *section.ActiveGraceHours
	}
	for name, item := range section.Categories {
		category, ok := storage.Categories[name]
		if !ok {
			continue
		}
		if item.Enabled != nil {
			category.Enabled = *item.Enabled
		}
		if item.RetentionDays != nil && *item.RetentionDays >= 0 {
			category.RetentionDays = *item.RetentionDays
		}
		if item.Path != nil && strings.TrimSpace(*item.Path) != "" {
			category.Path = strings.TrimSpace(*item.Path)
		}
		storage.Categories[name] = category
	}
	if root := strings.TrimSpace(os.Getenv("SOPHON_STORAGE_ARTIFACT_ROOT")); root != "" {
		storage.ArtifactRoot = root
	}
	if raw := strings.TrimSpace(os.Getenv("SOPHON_STORAGE_ACTIVE_GRACE_HOURS")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 && parsed <= 720 {
			storage.ActiveGraceHours = parsed
		}
	}
	if raw := strings.TrimSpace(os.Getenv("SOPHON_STORAGE_AUTO_CLEAN")); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			storage.AutoClean = parsed
		}
	}
	if raw := strings.TrimSpace(os.Getenv("SOPHON_STORAGE_INTERVAL_MINUTES")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 5 && parsed <= 10080 {
			storage.IntervalMinutes = parsed
		}
	}
	if storage.ArtifactRoot == "" {
		storage.ArtifactRoot = defaultArtifactRoot(dataDir)
	}
	return storage
}

// defaultArtifactRoot 使用数据目录的父目录（如 /opt/sophon/data -> /opt/sophon）。
func defaultArtifactRoot(dataDir string) string {
	absolute, err := filepath.Abs(strings.TrimSpace(dataDir))
	if err != nil {
		return "."
	}
	if filepath.Base(absolute) == "data" {
		return filepath.Dir(absolute)
	}
	return absolute
}

func resolveConfigPath() string {
	if value := strings.TrimSpace(os.Getenv("SOPHON_CONFIG")); value != "" {
		return value
	}
	if _, err := os.Stat(defaultConfigName); err == nil {
		return defaultConfigName
	}
	if _, err := os.Stat(fallbackConfigPath); err == nil {
		return fallbackConfigPath
	}
	return defaultConfigName
}

func loadConfigFile(path string) (fileConfig, string, error) {
	var file fileConfig
	if strings.TrimSpace(path) == "" {
		return file, "", nil
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		created, createErr := ensureConfigFile(path)
		if createErr != nil {
			log.Printf("config: %v", createErr)
			return file, "", nil
		}
		if !created {
			return file, "", nil
		}
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return file, "", fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &file); err != nil {
		return file, "", fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
	}
	return file, path, nil
}

func ensureConfigFile(path string) (bool, error) {
	examplePath := filepath.Join(filepath.Dir(path), defaultExampleName)
	data, err := os.ReadFile(examplePath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("读取配置模板 %s 失败: %w", examplePath, err)
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return false, fmt.Errorf("创建配置目录失败: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return false, fmt.Errorf("生成配置文件 %s 失败: %w", path, err)
	}
	log.Printf("config: 已根据模板生成 %s", path)
	return true, nil
}

func pickString(envKey string, value *string, fallback string) string {
	if env := strings.TrimSpace(os.Getenv(envKey)); env != "" {
		return env
	}
	if value != nil && strings.TrimSpace(*value) != "" {
		return strings.TrimSpace(*value)
	}
	return fallback
}

func pickInt(envKey string, value *int, fallback int) int {
	if raw := strings.TrimSpace(os.Getenv(envKey)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= maxConfigValueLimit {
			return parsed
		}
		return fallback
	}
	if value != nil && *value > 0 && *value <= maxConfigValueLimit {
		return *value
	}
	return fallback
}

// pickIntAllowZero 保留显式配置的 0 和负数，由调用方定义具体语义。
func pickIntAllowZero(envKey string, value *int, fallback int) int {
	if raw := strings.TrimSpace(os.Getenv(envKey)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			return parsed
		}
		return fallback
	}
	if value != nil {
		return *value
	}
	return fallback
}

func pickBool(envKey string, value *bool, fallback bool) bool {
	if raw := strings.TrimSpace(os.Getenv(envKey)); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			return parsed
		}
		return fallback
	}
	if value != nil {
		return *value
	}
	return fallback
}

func pickTools(envKey string, values []string) string {
	if env := strings.TrimSpace(os.Getenv(envKey)); env != "" {
		return env
	}
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return strings.Join(cleaned, ",")
}

// defaultHITLTools 是默认需要人工审批的高风险工具，可被 config.yml 的 hitl.tools 覆盖。
var defaultHITLTools = []string{
	"exec",
	"execute-python-script",
	"install-python-package",
	"metasploit",
	"msfvenom",
	"impacket",
	"netexec",
	"hydra",
	"hashcat",
	"sqlmap",
	"fscan",
	"masscan",
}

// pickHITLTools 区分「未配置」与「显式空列表」：
// tools 未配置（nil）时使用内置高风险清单；显式 tools: [] 仍表示所有工具都需审批。
func pickHITLTools(values []string) string {
	if env := strings.TrimSpace(os.Getenv("SOPHON_HITL_TOOLS")); env != "" {
		return env
	}
	if values == nil {
		return strings.Join(defaultHITLTools, ",")
	}
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return strings.Join(cleaned, ",")
}

// normalizeLLMProvider 归一化接口格式：anthropic/claude → anthropic，其余 → openai_compatible。
func normalizeLLMProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "anthropic", "claude":
		return "anthropic"
	default:
		return "openai_compatible"
	}
}

const (
	maxLLMAPIKeyCount = 20
	maxLLMAPIKeyChars = 4096
)

// ParseLLMAPIKeys 按行解析 Key 列表，兼容 Windows 换行并去除空项和重复项。
func ParseLLMAPIKeys(value string) []string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return NormalizeLLMAPIKeys(strings.Split(value, "\n"))
}

// NormalizeLLMAPIKeys 清理 Key 列表，最多保留 maxLLMAPIKeyCount 个有效项。
func NormalizeLLMAPIKeys(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > maxLLMAPIKeyChars || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
		if len(result) >= maxLLMAPIKeyCount {
			break
		}
	}
	return result
}

func resolveLLMAPIKeys(values []string, legacy *string) []string {
	if raw := strings.TrimSpace(os.Getenv("SOPHON_LLM_API_KEYS")); raw != "" {
		return ParseLLMAPIKeys(raw)
	}
	if raw := strings.TrimSpace(os.Getenv("SOPHON_LLM_API_KEY")); raw != "" {
		return []string{raw}
	}
	if keys := NormalizeLLMAPIKeys(values); len(keys) > 0 {
		return keys
	}
	if legacy != nil {
		if value := strings.TrimSpace(*legacy); value != "" {
			return []string{value}
		}
	}
	return nil
}

func firstLLMAPIKey(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func normalizeSubagentMaxConcurrency(value int) int {
	if value <= 0 {
		return 2
	}
	if value > 16 {
		return 16
	}
	return value
}

func normalizeSubagentMaxToolCalls(value int) int {
	if value <= 0 {
		return 80
	}
	if value > 500 {
		return 500
	}
	return value
}

func normalizeSubagentMaxDuration(value int) int {
	if value <= 0 {
		return 1800
	}
	if value < 60 {
		return 60
	}
	if value > 7200 {
		return 7200
	}
	return value
}

func normalizeSubagentMaxCPUSeconds(value int) int {
	if value <= 0 {
		return 900
	}
	if value < 30 {
		return 30
	}
	if value > 7200 {
		return 7200
	}
	return value
}

func normalizeSubagentMaxProcesses(value int) int {
	if value <= 0 {
		return 8
	}
	if value > 64 {
		return 64
	}
	return value
}

func normalizeAgentMaxHypotheses(value int) int {
	if value <= 0 {
		return 0
	}
	if value > 2000 {
		return 2000
	}
	return value
}

func normalizeAgentMaxConcurrentSessions(value int) int {
	if value <= 0 {
		return 5
	}
	if value > 1000 {
		return 1000
	}
	return value
}
