// Package redact 提供日志与审计落库前的敏感字段脱敏。
package redact

import (
	"encoding/json"
	"regexp"
	"strings"
)

// FieldLimit 是单个字符串字段的最大保留长度。
const FieldLimit = 200

var sensitiveMarkers = []string{
	"password",
	"token",
	"secret",
	"apikey",
	"authorization",
	"credential",
	"privatekey",
}

var (
	sensitiveTextPattern = regexp.MustCompile(
		`(?i)(password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|credential|密码|令牌|密钥)\s*[:=：]\s*(?:Bearer\s+)?["']?([^\s,;，；]{4,})`,
	)
	bearerTokenPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`)
)

// SensitiveKey 判断键名是否属于敏感字段（忽略大小写与下划线）。
func SensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "_", ""))
	if normalized == "" {
		return false
	}
	for _, marker := range sensitiveMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

// Value 递归脱敏并截断 JSON 可序列化值；key 为当前字段名。
func Value(value any, key string) any {
	if SensitiveKey(key) {
		return "***"
	}
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for childKey, childValue := range typed {
			out[childKey] = Value(childValue, childKey)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(typed))
		for childKey, childValue := range typed {
			out[childKey] = Value(childValue, childKey)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, Value(item, key))
		}
		return out
	case string:
		runes := []rune(typed)
		if len(runes) > FieldLimit {
			return string(runes[:FieldLimit]) + "..."
		}
		return typed
	default:
		return value
	}
}

// JSON 解析 JSON 文本并返回脱敏后的紧凑 JSON；解析失败返回 ok=false。
func JSON(raw []byte) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", false
	}
	encoded, err := json.Marshal(Value(payload, ""))
	if err != nil {
		return "", false
	}
	return string(encoded), true
}

// Text 对任意日志、命令输出或进度文本做保守的密钥值脱敏。
func Text(value string) string {
	if strings.TrimSpace(value) == "" {
		return value
	}
	value = sensitiveTextPattern.ReplaceAllString(value, "$1=***")
	return bearerTokenPattern.ReplaceAllString(value, "Bearer ***")
}
