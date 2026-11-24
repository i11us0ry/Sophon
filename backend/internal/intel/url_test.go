package intel

import (
	"strings"
	"testing"
)

func TestNormalizeProviderURLRejectsUnsafeValues(t *testing.T) {
	cases := []string{
		"javascript:alert(1)",
		"ftp://example.com/file",
		"https://user:pass@example.com/",
		"https://example.com/\nheader",
		"https://example.com/" + strings.Repeat("a", maxProviderURL),
	}
	for _, value := range cases {
		if got := normalizeProviderURL(value, "http", "example.com", "", 443); got != "" {
			t.Fatalf("不安全 URL 应被拒绝: value=%q got=%q", value, got)
		}
	}
	if got := normalizeProviderURL(
		"HTTPS://Example.COM:8443/login#fragment",
		"https",
		"example.com",
		"10.0.0.8",
		8443,
	); got != "https://example.com:8443/login" {
		t.Fatalf("合法 URL 规范化错误: %q", got)
	}
}
