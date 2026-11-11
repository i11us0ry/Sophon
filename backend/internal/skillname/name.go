package skillname

import (
	"regexp"
	"strings"
)

const MaxRunes = 64

var pattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func Valid(value string) bool {
	return pattern.MatchString(strings.TrimSpace(value))
}
