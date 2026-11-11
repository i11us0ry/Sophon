package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var allowedFactCategories = map[string]bool{
	"target":   true,
	"auth":     true,
	"infra":    true,
	"business": true,
	"chain":    true,
	"exploit":  true,
	"poc":      true,
	"note":     true,
}

var factDateSuffix = regexp.MustCompile(`[\(\[]?20\d{6}[\)\]]?$`)

// normalizeProjectFactKey 将自由文本 key 规范为稳定的 category/slug：
// - 统一小写与分隔符
// - 去掉日期后缀，避免同一事实每天生成新 key
// - 没有分类时按事实类型推断，默认归入 note/
func normalizeProjectFactKey(raw string, factType string, memoryKind string) (string, error) {
	original := strings.TrimSpace(raw)
	normalized := strings.ToLower(original)
	normalized = strings.ReplaceAll(normalized, "_", "-")
	normalized = strings.ReplaceAll(normalized, " ", "-")
	for strings.HasSuffix(normalized, "-") {
		normalized = strings.TrimSuffix(normalized, "-")
	}
	withoutDate := strings.TrimSpace(factDateSuffix.ReplaceAllString(normalized, ""))
	value := withoutDate
	for strings.HasSuffix(value, "-") || strings.HasSuffix(value, "(") || strings.HasSuffix(value, "[") {
		value = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(value, "-"), "("), "[")
	}
	if value == "" {
		return "", fmt.Errorf("事实 key 不能为空")
	}

	hasCategory := strings.Contains(value, "/")
	inferredCategory := inferFactCategory(value, factType, memoryKind)
	explicitKind := factType == "credential" || memoryKind == "credential" ||
		factType == "scope" || memoryKind == "scope" ||
		factType == "constraint" || memoryKind == "constraint"
	if !hasCategory && withoutDate == normalized && !explicitKind {
		// 兼容历史自由 key：没有显式分类且没有日期后缀时保留原 key，
		// 避免重命名已存在的引用；新事实仍推荐 category/slug。
		return original, nil
	}

	category := ""
	slug := ""
	if index := strings.Index(value, "/"); index >= 0 {
		category = strings.TrimSpace(value[:index])
		slug = strings.TrimSpace(value[index+1:])
	} else {
		category = inferredCategory
		slug = withoutDate
	}
	if !allowedFactCategories[category] {
		return "", fmt.Errorf(
			"事实 key 分类 %q 不合法，只允许 target/auth/infra/business/chain/exploit/poc/note",
			category,
		)
	}
	slug = normalizeFactSlug(slug)
	if slug == "" {
		return "", fmt.Errorf("事实 key 缺少 slug")
	}
	if runes := []rune(slug); len(runes) > 80 {
		slug = string(runes[:80])
	}
	return category + "/" + slug, nil
}

func inferFactCategory(text string, factType string, memoryKind string) string {
	joined := strings.ToLower(strings.Join([]string{text, factType, memoryKind}, " "))
	switch {
	case strings.Contains(joined, "credential"),
		strings.Contains(joined, "password"),
		strings.Contains(joined, "凭据"),
		strings.Contains(joined, "密码"),
		strings.Contains(joined, "token"):
		return "auth"
	case strings.Contains(joined, "scope"),
		strings.Contains(joined, "domain"),
		strings.Contains(joined, "url"),
		strings.Contains(joined, "asset"),
		strings.Contains(joined, ".com"),
		strings.Contains(joined, ".net"),
		strings.Contains(joined, ".org"),
		strings.Contains(joined, ".cn"),
		strings.Contains(joined, "qq.com"),
		strings.Contains(joined, "端口"),
		strings.Contains(joined, "资产"):
		return "target"
	case strings.Contains(joined, "topology"),
		strings.Contains(joined, "service"),
		strings.Contains(joined, "infra"),
		strings.Contains(joined, "指纹"),
		strings.Contains(joined, "服务"):
		return "infra"
	case strings.Contains(joined, "constraint"),
		strings.Contains(joined, "business"),
		strings.Contains(joined, "业务"),
		strings.Contains(joined, "约束"):
		return "business"
	default:
		return "note"
	}
}

func normalizeFactSlug(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.Join(strings.Fields(value), "-")
	for strings.Contains(value, "--") {
		value = strings.ReplaceAll(value, "--", "-")
	}
	value = strings.Trim(value, "-/.")
	return value
}

func factFingerprint(projectID string, assetID string, key string, subjectKey string, predicate string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(projectID),
		strings.TrimSpace(assetID),
		strings.ToLower(strings.TrimSpace(key)),
		strings.ToLower(strings.TrimSpace(subjectKey)),
		strings.ToLower(strings.TrimSpace(predicate)),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}
