package agent

import (
	"errors"
	"testing"
)

func TestIsContextOverflowError(t *testing.T) {
	cases := []struct {
		message string
		want    bool
	}{
		{"This model's maximum context length is 8192 tokens", true},
		{"Error code: 400 - prompt is too long", true},
		{"request too large for model", true},
		{"超过最大上下文长度", true},
		{"upstream returned 401 unauthorized", false},
	}
	for _, item := range cases {
		if got := isContextOverflowError(errors.New(item.message)); got != item.want {
			t.Fatalf("%q 判定应为 %v，实际 %v", item.message, item.want, got)
		}
	}
	if isContextOverflowError(nil) {
		t.Fatal("nil 错误不应判定为溢出")
	}
}
