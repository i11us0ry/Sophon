package agent

import (
	"regexp"
	"strings"
)

const (
	maxActiveIntentsPerAsset   = 10
	maxActiveHintsPerAsset     = 10
	maxActiveIntentsPerProject = 100
	maxActiveHintsPerProject   = 100
)

var graphNodeDateSuffix = regexp.MustCompile(`[\(\[]?20\d{6}[\)\]]?$`)

func normalizeGraphNodeTitle(title string) string {
	value := strings.TrimSpace(title)
	value = graphNodeDateSuffix.ReplaceAllString(value, "")
	value = strings.Join(strings.Fields(value), " ")
	value = strings.Trim(value, " -_()[]")
	if runes := []rune(value); len(runes) > 120 {
		value = string(runes[:120])
	}
	return value
}

func activeGraphNodeLimit(kind string) int {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "intent":
		return maxActiveIntentsPerAsset
	case "hint":
		return maxActiveHintsPerAsset
	default:
		return 0
	}
}

func activeProjectGraphNodeLimit(kind string) int {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "intent":
		return maxActiveIntentsPerProject
	case "hint":
		return maxActiveHintsPerProject
	default:
		return 0
	}
}
