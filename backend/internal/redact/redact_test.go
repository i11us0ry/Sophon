package redact

import (
	"strings"
	"testing"
)

func TestJSONRedactsSecretsAndKeepsNormalFields(t *testing.T) {
	summary, ok := JSON([]byte(
		`{"username":"alice","password":"plain-secret","api_key":"sk-1","nested":{"token":"t"},"note":"ok"}`,
	))
	if !ok {
		t.Fatalf("合法 JSON 应解析成功")
	}
	for _, secret := range []string{"plain-secret", "sk-1", `"token":"t"`} {
		if strings.Contains(summary, secret) {
			t.Fatalf("敏感值未脱敏：%s", summary)
		}
	}
	if !strings.Contains(summary, "alice") || !strings.Contains(summary, `"note":"ok"`) {
		t.Fatalf("普通字段应保留：%s", summary)
	}
	if strings.Count(summary, "***") != 3 {
		t.Fatalf("三个敏感字段都应替换：%s", summary)
	}
}

func TestSensitiveKeyMatching(t *testing.T) {
	for _, key := range []string{"password", "newPassword", "api_key", "apiKey", "Token", "authorization", "credential", "privateKey"} {
		if !SensitiveKey(key) {
			t.Fatalf("%s 应被视为敏感字段", key)
		}
	}
	for _, key := range []string{"keywords", "title", "value", "factType", "name"} {
		if SensitiveKey(key) {
			t.Fatalf("%s 不应被脱敏", key)
		}
	}
}

func TestTextMasksSensitiveValues(t *testing.T) {
	input := "Authorization: Bearer abc.def.ghi\npassword=plain-secret\napi_key: sk-123456\nnote=ok"
	output := Text(input)
	for _, secret := range []string{"abc.def.ghi", "plain-secret", "sk-123456"} {
		if strings.Contains(output, secret) {
			t.Fatalf("文本脱敏后仍包含 %s: %s", secret, output)
		}
	}
	if !strings.Contains(output, "note=ok") {
		t.Fatalf("普通内容不应被删除: %s", output)
	}
}

func TestValueTruncatesLongStringsAndArrays(t *testing.T) {
	long := strings.Repeat("a", FieldLimit+50)
	redacted, ok := Value(long, "note").(string)
	if !ok || !strings.HasSuffix(redacted, "...") {
		t.Fatalf("超长字符串应被截断：%v", redacted)
	}

	// 敏感键对应的整个值（含数组）直接替换为 ***
	if masked, ok := Value([]any{"short", "secret-value"}, "password").(string); !ok || masked != "***" {
		t.Fatalf("敏感键的值应整体脱敏：%v", masked)
	}

	// 非敏感键的数组逐项处理，长字符串仍被截断
	items, ok := Value([]any{"short", long}, "notes").([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("数组应逐项处理：%v", items)
	}
	if items[0] != "short" {
		t.Fatalf("普通项应保留：%v", items[0])
	}
	if text, ok := items[1].(string); !ok || !strings.HasSuffix(text, "...") {
		t.Fatalf("数组内超长字符串应截断：%v", items[1])
	}
}

func TestJSONRejectsInvalidInput(t *testing.T) {
	if _, ok := JSON([]byte("not-json")); ok {
		t.Fatalf("非 JSON 应返回 false")
	}
	if _, ok := JSON(nil); ok {
		t.Fatalf("空输入应返回 false")
	}
}
