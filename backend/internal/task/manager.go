package task

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type Status string

const (
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

const defaultMaxRunningPerUser = 5

var (
	ErrConversationBusy = errors.New("该对话已有任务在运行")
	ErrUserTaskLimit    = errors.New("当前用户运行中的任务已达上限")
)

type Event struct {
	Type      string                 `json:"type"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

type Snapshot struct {
	ID             string    `json:"id"`
	ConversationID string    `json:"conversationId"`
	UserID         string    `json:"userId"`
	Status         Status    `json:"status"`
	Error          string    `json:"error,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type Task struct {
	mu             sync.Mutex
	id             string
	conversationID string
	userID         string
	status         Status
	errText        string
	createdAt      time.Time
	updatedAt      time.Time
	ctx            context.Context
	cancel         context.CancelFunc
	events         chan Event
	done           chan struct{}
	closed         bool
	detached       bool
}

type Manager struct {
	mu         sync.RWMutex
	tasks      map[string]*Task
	maxPerUser int
}

func NewManager() *Manager {
	return NewManagerWithLimit(defaultMaxRunningPerUser)
}

func NewManagerWithLimit(maxPerUser int) *Manager {
	if maxPerUser <= 0 {
		maxPerUser = defaultMaxRunningPerUser
	}
	return &Manager{
		tasks:      make(map[string]*Task),
		maxPerUser: maxPerUser,
	}
}

func (m *Manager) MaxPerUser() int {
	if m == nil {
		return defaultMaxRunningPerUser
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.maxPerUser
}

func (m *Manager) SetMaxPerUser(maxPerUser int) {
	if m == nil || maxPerUser <= 0 {
		return
	}
	m.mu.Lock()
	m.maxPerUser = maxPerUser
	m.mu.Unlock()
}

// CreateIfIdle 在会话和用户并发额度均可用时创建任务。
func (m *Manager) CreateIfIdle(conversationID, userID string) (*Task, string, error) {
	m.mu.Lock()
	runningForUser := 0
	for id, existing := range m.tasks {
		snapshot := existing.Snapshot()
		if snapshot.ConversationID == conversationID && snapshot.Status == StatusRunning {
			m.mu.Unlock()
			return nil, id, ErrConversationBusy
		}
		if snapshot.UserID == userID && snapshot.Status == StatusRunning {
			runningForUser++
		}
	}
	if runningForUser >= m.maxPerUser {
		m.mu.Unlock()
		return nil, "", ErrUserTaskLimit
	}
	item := newTask(conversationID, userID)
	m.tasks[item.id] = item
	m.mu.Unlock()

	m.cleanup()
	return item, "", nil
}

// ActiveConversations 返回用户当前仍在运行的会话状态。
func (m *Manager) ActiveConversations(userID string) map[string]Status {
	m.mu.RLock()
	items := make([]*Task, 0, len(m.tasks))
	for _, item := range m.tasks {
		items = append(items, item)
	}
	m.mu.RUnlock()

	result := make(map[string]Status)
	for _, item := range items {
		snapshot := item.Snapshot()
		if snapshot.UserID == userID && snapshot.Status == StatusRunning {
			result[snapshot.ConversationID] = snapshot.Status
		}
	}
	return result
}

// CancelConversation 取消指定用户某个会话下正在运行的任务。
func (m *Manager) CancelConversation(conversationID, userID string) int {
	m.mu.RLock()
	items := make([]*Task, 0, len(m.tasks))
	for _, item := range m.tasks {
		items = append(items, item)
	}
	m.mu.RUnlock()

	cancelled := 0
	for _, item := range items {
		snapshot := item.Snapshot()
		if snapshot.ConversationID != conversationID ||
			snapshot.UserID != userID ||
			snapshot.Status != StatusRunning {
			continue
		}
		item.Cancel()
		cancelled++
	}
	return cancelled
}

func (m *Manager) WaitForIdle(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		m.mu.RLock()
		running := 0
		for _, item := range m.tasks {
			if item.Snapshot().Status == StatusRunning {
				running++
			}
		}
		m.mu.RUnlock()
		if running == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *Manager) CancelAll() int {
	m.mu.RLock()
	items := make([]*Task, 0, len(m.tasks))
	for _, item := range m.tasks {
		items = append(items, item)
	}
	m.mu.RUnlock()
	cancelled := 0
	for _, item := range items {
		if item.Snapshot().Status != StatusRunning {
			continue
		}
		item.Cancel()
		cancelled++
	}
	return cancelled
}

// newTask 构造运行态任务，由调用方负责注册进 Manager。
func newTask(conversationID, userID string) *Task {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now().UTC()
	return &Task{
		id:             randomID(),
		conversationID: conversationID,
		userID:         userID,
		status:         StatusRunning,
		createdAt:      now,
		updatedAt:      now,
		ctx:            ctx,
		cancel:         cancel,
		events:         make(chan Event, 256),
		done:           make(chan struct{}),
	}
}

func (m *Manager) Get(id, userID string) (Snapshot, bool) {
	m.mu.RLock()
	item := m.tasks[id]
	m.mu.RUnlock()
	if item == nil || item.userID != userID {
		return Snapshot{}, false
	}
	return item.Snapshot(), true
}

func (m *Manager) Cancel(id, userID string) bool {
	m.mu.RLock()
	item := m.tasks[id]
	m.mu.RUnlock()
	if item == nil || item.userID != userID {
		return false
	}
	item.Cancel()
	return true
}

func (t *Task) ID() string {
	return t.id
}

func (t *Task) Context() context.Context {
	return t.ctx
}

func (t *Task) Events() <-chan Event {
	return t.events
}

// Detach 表示 SSE 客户端已断开：任务继续在后台执行，事件转入后台排空，
// 避免 Publish 因无人消费而阻塞，也避免把页面刷新误判为用户取消。
func (t *Task) Detach() {
	t.mu.Lock()
	if t.detached {
		t.mu.Unlock()
		return
	}
	t.detached = true
	t.mu.Unlock()
	go func() {
		for {
			select {
			case <-t.done:
				return
			case <-t.events:
			}
		}
	}()
}

func (t *Task) Done() <-chan struct{} {
	return t.done
}

func (t *Task) Publish(event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	select {
	case <-t.done:
		return
	default:
	}
	select {
	case t.events <- event:
	case <-t.done:
	}
}

func (t *Task) Complete() {
	t.finish(StatusCompleted, "")
}

func (t *Task) Fail(err error) {
	message := ""
	if err != nil {
		message = err.Error()
	}
	t.finish(StatusFailed, message)
}

func (t *Task) Cancel() {
	t.mu.Lock()
	if t.status == StatusRunning {
		t.status = StatusCancelled
		t.updatedAt = time.Now().UTC()
	}
	cancel := t.cancel
	if !t.closed {
		t.closed = true
		close(t.done)
	}
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (t *Task) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Snapshot{
		ID:             t.id,
		ConversationID: t.conversationID,
		UserID:         t.userID,
		Status:         t.status,
		Error:          t.errText,
		CreatedAt:      t.createdAt,
		UpdatedAt:      t.updatedAt,
	}
}

func (t *Task) finish(status Status, errText string) {
	t.mu.Lock()
	if t.status == StatusRunning {
		t.status = status
		t.errText = errText
		t.updatedAt = time.Now().UTC()
	}
	cancel := t.cancel
	if !t.closed {
		t.closed = true
		close(t.done)
	}
	t.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (m *Manager) cleanup() {
	const maxTasks = 500

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.tasks) <= maxTasks {
		return
	}

	cutoff := time.Now().UTC().Add(-1 * time.Hour)
	for id, item := range m.tasks {
		snapshot := item.Snapshot()
		if snapshot.Status != StatusRunning && snapshot.UpdatedAt.Before(cutoff) {
			delete(m.tasks, id)
		}
		if len(m.tasks) <= maxTasks {
			return
		}
	}
}

func randomID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(buffer)
}
