package mcpclient

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/database"
)

type Manager struct {
	db             *database.DB
	connectTimeout time.Duration
	callTimeout    time.Duration
	recorder       ExecutionRecorder
	perServerLimit int
	totalLimit     int
	mu             sync.Mutex
	clients        map[string]*Client
	toolCounts     map[string]int
	toolInfos      map[string][]*schema.ToolInfo
	lastErrors     map[string]string
	proxyEnv       []string
}

func NewManager(
	db *database.DB,
	connectTimeout time.Duration,
	callTimeout time.Duration,
	perServerLimit int,
	totalLimit int,
) *Manager {
	if connectTimeout <= 0 {
		connectTimeout = 20 * time.Second
	}
	if callTimeout <= 0 {
		callTimeout = 30 * time.Second
	}
	return &Manager{
		db:             db,
		connectTimeout: connectTimeout,
		callTimeout:    callTimeout,
		perServerLimit: perServerLimit,
		totalLimit:     totalLimit,
		clients:        map[string]*Client{},
		toolCounts:     map[string]int{},
		toolInfos:      map[string][]*schema.ToolInfo{},
		lastErrors:     map[string]string{},
	}
}

func (m *Manager) SetExecutionRecorder(recorder ExecutionRecorder) {
	m.recorder = recorder
}

func (m *Manager) SetProxyEnv(env []string) {
	m.mu.Lock()
	m.proxyEnv = append([]string(nil), env...)
	m.mu.Unlock()
}

func (m *Manager) ProxyEnv() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.proxyEnv...)
}

// Start 连接内置服务与所有启用的外部服务，返回合并后的工具列表。
// 内置服务连接失败会返回错误；外部服务失败只记录状态。
func (m *Manager) Start(
	ctx context.Context,
	builtin database.MCPServer,
	servers []database.MCPServer,
) ([]tool.BaseTool, error) {
	all := make([]database.MCPServer, 0, len(servers)+1)
	all = append(all, builtin)
	all = append(all, servers...)

	tools := make([]tool.BaseTool, 0)
	for _, server := range all {
		if !server.Enabled {
			continue
		}
		if transport := server.Transport; transport != "" && transport != "stdio" {
			m.recordStatus(ctx, server, "unsupported", "当前仅支持 stdio 传输", 0)
			continue
		}
		client := New(server.Command, server.Args, m.connectTimeout, m.callTimeout)
		client.SetServerName(server.Name)
		client.SetExecutionRecorder(m.recorder)
		client.SetEnv(mergeEnvironment(m.proxyEnv, server.Env))
		client.SetLimiter(newConcurrencyLimiter(m.perServerLimit, m.totalLimit))
		if err := client.Connect(ctx); err != nil {
			m.recordStatus(ctx, server, "error", err.Error(), 0)
			if server.Builtin {
				return nil, fmt.Errorf("connect builtin MCP server %s: %w", server.Name, err)
			}
			continue
		}
		serverTools, err := client.EinoTools(ctx)
		if err != nil {
			_ = client.Close()
			m.recordStatus(ctx, server, "error", err.Error(), 0)
			if server.Builtin {
				return nil, fmt.Errorf("load builtin MCP tools %s: %w", server.Name, err)
			}
			continue
		}
		m.mu.Lock()
		m.clients[server.ID] = client
		m.toolCounts[server.ID] = len(serverTools)
		m.toolInfos[server.ID] = collectToolInfos(ctx, serverTools)
		delete(m.lastErrors, server.ID)
		m.mu.Unlock()
		m.recordStatus(ctx, server, "connected", "", len(serverTools))
		tools = append(tools, serverTools...)
	}
	return tools, nil
}

// Tools 返回某个 MCP 服务当前暴露的工具明细，用于工具管理页。
func (m *Manager) Tools(serverID string) []*schema.ToolInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	items := m.toolInfos[serverID]
	return append([]*schema.ToolInfo(nil), items...)
}

func collectToolInfos(ctx context.Context, tools []tool.BaseTool) []*schema.ToolInfo {
	infos := make([]*schema.ToolInfo, 0, len(tools))
	for _, item := range tools {
		info, err := item.Info(ctx)
		if err != nil || info == nil {
			continue
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos
}

func (m *Manager) RuntimeStatus(id string) (string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[id]; ok {
		return "connected", m.toolCounts[id]
	}
	if _, ok := m.lastErrors[id]; ok {
		return "error", 0
	}
	return "", 0
}

func (m *Manager) RuntimeError(id string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastErrors[id]
}

func (m *Manager) Close() error {
	m.mu.Lock()
	clients := make([]*Client, 0, len(m.clients))
	for _, client := range m.clients {
		clients = append(clients, client)
	}
	m.clients = map[string]*Client{}
	m.mu.Unlock()

	var firstErr error
	for _, client := range clients {
		if err := client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// TestConnection 连接一个 stdio 服务并返回工具名称，用于管理页的连通性测试。
func TestConnection(
	ctx context.Context,
	server database.MCPServer,
	connectTimeout time.Duration,
	callTimeout time.Duration,
	proxyEnv []string,
) ([]string, error) {
	if transport := server.Transport; transport != "" && transport != "stdio" {
		return nil, fmt.Errorf("当前仅支持 stdio 传输")
	}
	client := New(server.Command, server.Args, connectTimeout, callTimeout)
	client.SetEnv(mergeEnvironment(proxyEnv, server.Env))
	defer func() { _ = client.Close() }()

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	serverTools, err := client.EinoTools(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(serverTools))
	for _, item := range serverTools {
		info, err := item.Info(ctx)
		if err != nil || info == nil {
			continue
		}
		names = append(names, info.Name)
	}
	sort.Strings(names)
	return names, nil
}

func (m *Manager) recordStatus(
	ctx context.Context,
	server database.MCPServer,
	status string,
	lastError string,
	toolCount int,
) {
	if status == "error" {
		m.mu.Lock()
		m.lastErrors[server.ID] = lastError
		m.mu.Unlock()
	}
	if m.db == nil || server.ID == "" {
		return
	}
	_ = m.db.UpdateMCPServerStatus(ctx, server.ID, status, lastError, toolCount)
}

func mergeEnvironment(base []string, override map[string]string) []string {
	values := make(map[string]string, len(base)+len(override))
	for _, item := range base {
		key, value, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		values[key] = value
	}
	for key, value := range override {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

// ConcurrencyLimiter 限制单个 MCP 服务与全局同时执行的工具数。
// 限制值在启动时确定，修改配置后需要重启生效。
type ConcurrencyLimiter struct {
	server chan struct{}
	global chan struct{}
}

func newConcurrencyLimiter(perServer, total int) *ConcurrencyLimiter {
	if perServer == 0 {
		perServer = 2
	}
	if total == 0 {
		total = 16
	}
	limiter := &ConcurrencyLimiter{}
	if perServer > 0 {
		limiter.server = make(chan struct{}, perServer)
	}
	if total > 0 {
		limiter.global = make(chan struct{}, total)
	}
	return limiter
}

func (l *ConcurrencyLimiter) acquire(
	ctx context.Context,
	timeout time.Duration,
) (func(), error) {
	if l == nil {
		return func() {}, nil
	}
	waitCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		waitCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	acquired := make([]chan struct{}, 0, 2)
	release := func() {
		for index := len(acquired) - 1; index >= 0; index-- {
			<-acquired[index]
		}
		cancel()
	}
	for _, slots := range []chan struct{}{l.global, l.server} {
		if slots == nil {
			continue
		}
		select {
		case slots <- struct{}{}:
			acquired = append(acquired, slots)
		case <-waitCtx.Done():
			release()
			return nil, fmt.Errorf("等待 MCP 并发额度超时: %w", waitCtx.Err())
		}
	}
	return release, nil
}
