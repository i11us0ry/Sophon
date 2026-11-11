package outbound

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateURLBlocksProtectedNetworksByDefault(t *testing.T) {
	ctx := context.Background()
	for _, rawURL := range []string{
		"file:///etc/passwd",
		"http://127.0.0.1:8080",
		"http://10.0.0.1",
		"http://169.254.169.254/latest/meta-data",
		"http://metadata.google.internal",
		"http://[::1]",
	} {
		if _, err := ValidateURL(ctx, rawURL, Policy{}); err == nil {
			t.Fatalf("地址 %s 应被默认策略拒绝", rawURL)
		}
	}
}

func TestValidateURLAllowsPrivateButNeverMetadata(t *testing.T) {
	ctx := context.Background()
	if _, err := ValidateURL(ctx, "http://127.0.0.1:8080", Policy{
		AllowPrivate: true,
	}); err != nil {
		t.Fatalf("开启私网访问后 loopback 应允许: %v", err)
	}
	for _, rawURL := range []string{
		"http://169.254.169.254/latest/meta-data",
		"http://metadata.google.internal",
		"http://100.100.100.200/latest/meta-data",
	} {
		if _, err := ValidateURL(ctx, rawURL, Policy{AllowPrivate: true}); err == nil {
			t.Fatalf("元数据地址 %s 应始终拒绝", rawURL)
		}
	}
}

func TestHTTPClientRevalidatesRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		http.Redirect(writer, request, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer server.Close()

	base := &http.Client{
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
		Timeout:   time.Second,
	}
	client, err := NewHTTPClient(base, Policy{AllowPrivate: true})
	if err != nil {
		t.Fatalf("创建安全 HTTP 客户端失败: %v", err)
	}
	_, err = client.Get(server.URL)
	if err == nil ||
		(!strings.Contains(err.Error(), "元数据") &&
			!strings.Contains(err.Error(), "内网地址")) {
		t.Fatalf("重定向到元数据地址应被拒绝，实际 err=%v", err)
	}
}

func TestHTTPClientBlocksPrivateTargetBeforeDial(t *testing.T) {
	base := &http.Client{
		Transport: http.DefaultTransport.(*http.Transport).Clone(),
		Timeout:   time.Second,
	}
	client, err := NewHTTPClient(base, Policy{})
	if err != nil {
		t.Fatalf("创建安全 HTTP 客户端失败: %v", err)
	}
	_, err = client.Get("http://127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "内网地址") {
		t.Fatalf("私网目标应在连接前被拒绝，实际 err=%v", err)
	}
}
