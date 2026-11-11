package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/execctx"
)

const (
	turnToolCacheTTL     = 30 * time.Minute
	skillToolCacheTTL    = 12 * time.Hour
	turnToolCacheMaxSize = 500
	probeReplayTTL       = 45 * time.Minute
)

// turnToolCacheKey 以助手消息作为轮次边界：用户在 UI 点“继续”会创建新的助手消息，
// 因此跨轮不会被误判为重复调用。
func turnToolCacheKey(ctx context.Context, toolName, cacheKind string) string {
	messageID := strings.TrimSpace(execctx.MessageID(ctx))
	if messageID == "" {
		return ""
	}
	if strings.TrimSpace(toolName) == readSkillToolName {
		scope := "main"
		if info, ok := execctx.Subagent(ctx); ok {
			subagentID := strings.TrimSpace(info.ID)
			if subagentID == "" {
				return ""
			}
			scope = "sub:" + subagentID
		}
		return messageID + "|skill-scope:" + scope + "|" + toolName + "|" + cacheKind
	}
	return messageID + "|" + toolName + "|" + cacheKind
}

func normalizedToolArguments(raw string) string {
	var value interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &value); err != nil {
		return strings.TrimSpace(raw)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	return string(encoded)
}

func hashedToolArguments(raw string) string {
	sum := sha256.Sum256([]byte(normalizedToolArguments(raw)))
	return hex.EncodeToString(sum[:])
}

// semanticWriteKey 把重复写回归一为业务主键：模型重试时即使补充了证据文本，
// 同一假设/同一测试也只会执行一次。
func semanticWriteKey(toolName, raw string) string {
	var request map[string]interface{}
	_ = json.Unmarshal([]byte(strings.TrimSpace(raw)), &request)
	value := func(keys ...string) string {
		for _, key := range keys {
			if item, ok := request[key]; ok {
				if text := strings.TrimSpace(toStringValue(item)); text != "" {
					return text
				}
			}
		}
		return ""
	}
	switch toolName {
	case "project_record_test":
		parts := []string{
			value("asset_id"),
			value("dimension"),
			value("technique"),
			value("intent_id"),
			value("status"),
			value("result"),
			value("finding_id"),
		}
		return strings.Join(parts, "\x00")
	case "project_complete_hypothesis":
		return strings.Join([]string{
			value("hypothesis_id"),
			value("status"),
			value("result"),
			value("finding_id"),
		}, "\x00")
	case "project_start_hypothesis":
		return value("hypothesis_id")
	case "project_record_fact":
		parts := []string{
			value("asset_id"),
			value("subject_type"),
			value("subject_key"),
			value("predicate"),
			value("key"),
		}
		if parts[1] != "" && parts[2] != "" && parts[3] != "" {
			return strings.Join(parts, "\x00")
		}
		return ""
	default:
		return ""
	}
}

func toStringValue(value interface{}) string {
	switch item := value.(type) {
	case string:
		return item
	case float64:
		return strconv.FormatFloat(item, 'f', -1, 64)
	case bool:
		if item {
			return "true"
		}
		return "false"
	default:
		encoded, _ := json.Marshal(item)
		return string(encoded)
	}
}

func (s *Service) lookupTurnToolCache(ctx context.Context, toolName, cacheKind string) (string, bool) {
	if s == nil || strings.TrimSpace(cacheKind) == "" {
		return "", false
	}
	key := turnToolCacheKey(ctx, toolName, cacheKind)
	if key == "" {
		return "", false
	}
	s.toolCacheMu.Lock()
	defer s.toolCacheMu.Unlock()
	entry, ok := s.toolCache[key]
	ttl := turnToolCacheTTL
	if strings.TrimSpace(toolName) == readSkillToolName {
		ttl = skillToolCacheTTL
	}
	if !ok || time.Since(entry.createdAt) > ttl {
		if ok {
			delete(s.toolCache, key)
		}
		return "", false
	}
	if strings.TrimSpace(toolName) == readSkillToolName {
		entry.createdAt = time.Now()
		s.toolCache[key] = entry
	}
	return entry.result, true
}

func (s *Service) storeTurnToolCache(ctx context.Context, toolName, cacheKind, result string) {
	if s == nil || strings.TrimSpace(cacheKind) == "" || result == "" {
		return
	}
	key := turnToolCacheKey(ctx, toolName, cacheKind)
	if key == "" {
		return
	}
	s.toolCacheMu.Lock()
	defer s.toolCacheMu.Unlock()
	if s.toolCache == nil {
		s.toolCache = make(map[string]toolCacheEntry)
	}
	if len(s.toolCache) >= turnToolCacheMaxSize {
		oldestKey := ""
		var oldest time.Time
		for candidate, entry := range s.toolCache {
			if oldestKey == "" || entry.createdAt.Before(oldest) {
				oldestKey = candidate
				oldest = entry.createdAt
			}
		}
		if oldestKey != "" {
			delete(s.toolCache, oldestKey)
		}
	}
	s.toolCache[key] = toolCacheEntry{
		result:    result,
		messageID: strings.TrimSpace(execctx.MessageID(ctx)),
		createdAt: time.Now(),
	}
}

// invalidateTurnReadCache 在写操作成功后清除本轮读缓存，避免模型读到写回前的旧态势。
func (s *Service) invalidateTurnReadCache(ctx context.Context) {
	if s == nil {
		return
	}
	messageID := strings.TrimSpace(execctx.MessageID(ctx))
	if messageID == "" {
		return
	}
	prefix := messageID + "|"
	s.toolCacheMu.Lock()
	defer s.toolCacheMu.Unlock()
	for key := range s.toolCache {
		if strings.HasPrefix(key, prefix) && strings.Contains(key, "|args:") {
			delete(s.toolCache, key)
		}
	}
}

func isProbeReplayTool(toolName string) bool {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "exec", "execute-python-script":
		return true
	default:
		return false
	}
}

func (s *Service) lookupRecentProbeExecution(
	ctx context.Context,
	toolName string,
	rawArguments string,
) (*database.ToolExecution, bool) {
	if s == nil || s.db == nil || !isProbeReplayTool(toolName) {
		return nil, false
	}
	conversationID := strings.TrimSpace(execctx.ConversationID(ctx))
	fingerprint := database.ToolExecutionFingerprintFromJSON(rawArguments)
	if conversationID == "" || fingerprint == "" {
		return nil, false
	}
	item, err := s.db.FindRecentCompletedToolExecution(
		ctx,
		conversationID,
		toolName,
		fingerprint,
		time.Now().Add(-probeReplayTTL),
	)
	if err != nil || item == nil {
		return nil, false
	}
	return item, true
}

func isTurnWriteTool(toolName string) bool {
	switch toolName {
	case "project_record_test", "project_complete_hypothesis", "project_start_hypothesis",
		"project_record_fact", "project_report_finding", "project_update_finding",
		"project_retest_finding", "project_verify_finding", "project_insert_assets",
		"project_upsert_entity", "project_link_entities", "project_add_intent",
		"project_add_hint", "project_update_goal", "project_update_intent",
		"project_sync_graph":
		return true
	default:
		return false
	}
}

func invalidatesTurnReadCache(toolName string) bool {
	return isTurnWriteTool(toolName) || isProbeReplayTool(toolName)
}

// turnToolCacheKind 返回可用于去重的键类型：读工具按完整参数，写工具按业务主键。
func turnToolCacheKind(toolName, raw string) string {
	switch toolName {
	case readSkillToolName:
		return "skill:" + hashedToolArguments(raw)
	case "project_list", "project_get", "project_list_assets", "project_list_facts", "project_list_findings", "project_get_finding",
		"project_list_hypotheses", "project_next_targets", "project_graph_overview",
		"project_graph_node", "project_query_memory", "project_memory_graph":
		return "args:" + hashedToolArguments(raw)
	}
	if key := semanticWriteKey(toolName, raw); key != "" {
		return "write:" + key
	}
	return ""
}

func pruneTurnToolCacheForTest(entries map[string]toolCacheEntry) {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if time.Since(entries[key].createdAt) > turnToolCacheTTL {
			delete(entries, key)
		}
	}
}
