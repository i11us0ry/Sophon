// Package observability 提供统一的运行事件模型、本地 JSONL 事件流与聚合指标。
// 事件只包含元数据（时间、工具名、策略判定、耗时、结果），默认不写入提示词、
// 命令原文、工具参数、文件路径与凭据，可直接转发给日志/SIEM 系统。
package observability

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultBufferSize = 500
	defaultMaxFileMB  = 64
)

// 事件类型。前三段（run/turn）描述 Agent 生命周期，tool/subagent/compaction 描述内部动作。
const (
	TypeRunStarted        = "run.started"
	TypeRunCompleted      = "run.completed"
	TypeRunFailed         = "run.failed"
	TypeToolDecision      = "tool.decision"
	TypeToolStarted       = "tool.started"
	TypeToolCompleted     = "tool.completed"
	TypeToolFailed        = "tool.failed"
	TypeSubagentStarted   = "subagent.started"
	TypeSubagentCompleted = "subagent.completed"
	TypeSubagentFailed    = "subagent.failed"
	TypeCompactionStarted = "compaction.started"
	TypeCompactionDone    = "compaction.completed"
)

// Config 是事件输出的运行配置。
type Config struct {
	Enabled    bool
	JSONLPath  string
	MaxFileMB  int
	SampleRate float64
}

// Event 是一条可外部导出的运行事件，不包含敏感载荷。
type Event struct {
	EventID        string    `json:"event_id"`
	EventType      string    `json:"event_type"`
	Timestamp      time.Time `json:"timestamp"`
	UserID         string    `json:"user_id,omitempty"`
	ProjectID      string    `json:"project_id,omitempty"`
	ConversationID string    `json:"conversation_id,omitempty"`
	RunID          string    `json:"run_id,omitempty"`
	AgentMode      string    `json:"agent_mode,omitempty"`
	SubagentID     string    `json:"subagent_id,omitempty"`
	SubagentMode   string    `json:"subagent_mode,omitempty"`
	AgentName      string    `json:"agent_name,omitempty"`
	AgentKind      string    `json:"agent_kind,omitempty"`
	ParentAgentID  string    `json:"parent_agent_id,omitempty"`
	IntentID       string    `json:"intent_id,omitempty"`
	HypothesisID   string    `json:"hypothesis_id,omitempty"`
	CapabilityMode string    `json:"capability_mode,omitempty"`
	ToolName       string    `json:"tool_name,omitempty"`
	ServerName     string    `json:"server_name,omitempty"`
	PolicyDecision string    `json:"policy_decision,omitempty"`
	Capability     string    `json:"capability,omitempty"`
	DurationMS     int64     `json:"duration_ms,omitempty"`
	Success        *bool     `json:"success,omitempty"`
	ErrorCategory  string    `json:"error_category,omitempty"`
	Detail         string    `json:"detail,omitempty"`
}

// Metrics 是进程内的聚合指标快照。
type Metrics struct {
	Enabled        bool             `json:"enabled"`
	EventsTotal    int64            `json:"eventsTotal"`
	FailuresTotal  int64            `json:"failuresTotal"`
	DeniedTotal    int64            `json:"deniedTotal"`
	ApprovalsTotal int64            `json:"approvalsTotal"`
	ByType         map[string]int64 `json:"byType"`
	Tools          map[string]int64 `json:"tools"`
	BufferSize     int              `json:"bufferSize"`
	FileBytes      int64            `json:"fileBytes"`
}

// Emitter 串行写入事件：内存环形缓冲供接口读取，JSONL 供外部采集。
type Emitter struct {
	mu       sync.Mutex
	enabled  bool
	path     string
	file     *os.File
	size     int64
	maxBytes int64
	sample   float64

	ring   []Event
	next   int
	filled int

	eventsTotal    int64
	failuresTotal  int64
	deniedTotal    int64
	approvalsTotal int64
	byType         map[string]int64
	tools          map[string]int64
}

// New 创建事件输出器；disabled 时返回一个可安全调用的空实现。
func New(cfg Config) (*Emitter, error) {
	emitter := &Emitter{
		enabled: cfg.Enabled,
		ring:    make([]Event, defaultBufferSize),
		byType:  map[string]int64{},
		tools:   map[string]int64{},
		sample:  1,
	}
	if !cfg.Enabled {
		return emitter, nil
	}
	path := strings.TrimSpace(cfg.JSONLPath)
	if path == "" {
		return nil, fmt.Errorf("事件文件路径不能为空")
	}
	if cfg.SampleRate > 0 && cfg.SampleRate <= 1 {
		emitter.sample = cfg.SampleRate
	}
	maxFileMB := cfg.MaxFileMB
	if maxFileMB <= 0 {
		maxFileMB = defaultMaxFileMB
	}
	emitter.maxBytes = int64(maxFileMB) * 1024 * 1024
	if err := emitter.open(path); err != nil {
		return nil, err
	}
	return emitter, nil
}

func (e *Emitter) open(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建事件目录失败: %w", err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("打开事件文件失败: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("读取事件文件状态失败: %w", err)
	}
	e.path = path
	e.file = file
	e.size = info.Size()
	return nil
}

// Emit 记录一条事件；空事件类型直接忽略。
func (e *Emitter) Emit(event Event) {
	if e == nil || !e.enabled || strings.TrimSpace(event.EventType) == "" {
		return
	}
	if event.EventID == "" {
		event.EventID = newEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.recordLocked(event)
	e.pushRingLocked(event)

	if e.file == nil {
		return
	}
	// 采样只影响落盘，内存指标与最近事件保持完整，避免指标失真。
	if e.sample < 1 && mathrand.Float64() > e.sample {
		return
	}
	line, err := json.Marshal(event)
	if err != nil {
		return
	}
	line = append(line, '\n')
	if e.maxBytes > 0 && e.size+int64(len(line)) > e.maxBytes {
		e.rotateLocked()
	}
	written, err := e.file.Write(line)
	if err == nil {
		e.size += int64(written)
	}
}

func (e *Emitter) recordLocked(event Event) {
	e.eventsTotal++
	e.byType[event.EventType]++
	if event.ToolName != "" {
		e.tools[event.ToolName]++
	}
	switch event.EventType {
	case TypeToolFailed, TypeRunFailed, TypeSubagentFailed:
		e.failuresTotal++
	case TypeToolDecision:
		switch event.PolicyDecision {
		case "deny":
			e.deniedTotal++
		case "require_approval":
			e.approvalsTotal++
		}
	}
}

func (e *Emitter) pushRingLocked(event Event) {
	if len(e.ring) == 0 {
		return
	}
	e.ring[e.next] = event
	e.next = (e.next + 1) % len(e.ring)
	if e.filled < len(e.ring) {
		e.filled++
	}
}

// rotateLocked 在写满上限后滚动为 path.1，保持单个文件大小可控。
func (e *Emitter) rotateLocked() {
	if e.file == nil {
		return
	}
	_ = e.file.Close()
	e.file = nil
	if err := os.Rename(e.path, e.path+".1"); err != nil && !os.IsNotExist(err) {
		_ = e.open(e.path)
		return
	}
	_ = e.open(e.path)
}

// Metrics 返回当前聚合指标快照。
func (e *Emitter) Metrics() Metrics {
	if e == nil {
		return Metrics{ByType: map[string]int64{}, Tools: map[string]int64{}}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	metrics := Metrics{
		Enabled:        e.enabled,
		EventsTotal:    e.eventsTotal,
		FailuresTotal:  e.failuresTotal,
		DeniedTotal:    e.deniedTotal,
		ApprovalsTotal: e.approvalsTotal,
		ByType:         make(map[string]int64, len(e.byType)),
		Tools:          make(map[string]int64, len(e.tools)),
		BufferSize:     e.filled,
		FileBytes:      e.size,
	}
	for key, value := range e.byType {
		metrics.ByType[key] = value
	}
	for key, value := range e.tools {
		metrics.Tools[key] = value
	}
	return metrics
}

// Recent 返回最近的事件（按时间正序），limit<=0 时返回全部缓冲。
func (e *Emitter) Recent(limit int) []Event {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.filled == 0 {
		return nil
	}
	ordered := make([]Event, 0, e.filled)
	start := (e.next - e.filled + len(e.ring)) % len(e.ring)
	for index := 0; index < e.filled; index++ {
		ordered = append(ordered, e.ring[(start+index)%len(e.ring)])
	}
	if limit > 0 && len(ordered) > limit {
		ordered = ordered[len(ordered)-limit:]
	}
	return ordered
}

// Close 关闭事件文件。
func (e *Emitter) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.file == nil {
		return nil
	}
	err := e.file.Close()
	e.file = nil
	return err
}

// EventTypes 返回已定义事件类型，便于文档与接口自描述。
func EventTypes() []string {
	types := []string{
		TypeRunStarted, TypeRunCompleted, TypeRunFailed,
		TypeToolDecision, TypeToolStarted, TypeToolCompleted, TypeToolFailed,
		TypeSubagentStarted, TypeSubagentCompleted, TypeSubagentFailed,
		TypeCompactionStarted, TypeCompactionDone,
	}
	sort.Strings(types)
	return types
}

func newEventID() string {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("evt-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}

// ErrorCategory 把错误归类为稳定标签，便于外部系统聚合告警。
func ErrorCategory(message string) string {
	lower := strings.ToLower(message)
	switch {
	case lower == "":
		return ""
	case strings.Contains(lower, "timeout"), strings.Contains(lower, "deadline exceeded"):
		return "timeout"
	case strings.Contains(lower, "context canceled"), strings.Contains(lower, "取消"):
		return "canceled"
	case strings.Contains(lower, "too many requests"), strings.Contains(lower, "rate limit"),
		strings.Contains(lower, "status code: 429"), strings.Contains(lower, "status code 429"):
		return "rate_limit"
	case strings.Contains(lower, "connection refused"), strings.Contains(lower, "connection reset"),
		strings.Contains(lower, "temporary network"), strings.Contains(lower, "temporary failure"),
		strings.Contains(lower, "no route to host"), strings.Contains(lower, "network is unreachable"):
		return "transient_network"
	case strings.Contains(lower, "policy engine"), strings.Contains(lower, "拒绝"):
		return "policy_denied"
	case strings.Contains(lower, "permission"), strings.Contains(lower, "审批"):
		return "approval"
	case strings.Contains(lower, "credential"), strings.Contains(lower, "unauthorized"),
		strings.Contains(lower, "status code: 401"), strings.Contains(lower, "status code 401"):
		return "credential_missing"
	case strings.Contains(lower, "not found"), strings.Contains(lower, "不存在"):
		return "not_found"
	case strings.Contains(lower, "status code: 5"), strings.Contains(lower, "bad gateway"):
		return "gateway"
	default:
		return "tool_error"
	}
}

// Bool 返回布尔指针，用于事件里的可选 success 字段。
func Bool(value bool) *bool {
	return &value
}
