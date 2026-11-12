package config

import (
	"reflect"
	"testing"
)

func TestParseLLMAPIKeysTrimsDeduplicatesAndCaps(t *testing.T) {
	got := ParseLLMAPIKeys(" key-a \r\nkey-b\n\nkey-a\n")
	want := []string{"key-a", "key-b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("解析结果错误: got=%v want=%v", got, want)
	}

	values := make([]string, 0, maxLLMAPIKeyCount+3)
	for index := 0; index < maxLLMAPIKeyCount+3; index++ {
		values = append(values, string(rune('a'+index)))
	}
	if got := NormalizeLLMAPIKeys(values); len(got) != maxLLMAPIKeyCount {
		t.Fatalf("Key 数量应限制为 %d，实际 %d", maxLLMAPIKeyCount, len(got))
	}
}
