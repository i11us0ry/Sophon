package config

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProxyConfigBuildsAuthenticatedURLAndEnvironment(t *testing.T) {
	proxy := ProxyConfig{
		Enabled:  true,
		Type:     "http",
		Host:     "127.0.0.1",
		Port:     7890,
		Username: "proxy-user",
		Password: "proxy-pass",
		NoProxy:  "localhost,127.0.0.1",
	}
	proxyURL, err := proxy.URL()
	if err != nil {
		t.Fatalf("构建代理地址失败: %v", err)
	}
	if proxyURL.String() != "http://proxy-user:proxy-pass@127.0.0.1:7890" {
		t.Fatalf("代理地址错误: %s", proxyURL)
	}
	env := strings.Join(proxy.Environment(), "\n")
	if !strings.Contains(env, "HTTP_PROXY=http://proxy-user:proxy-pass@127.0.0.1:7890") ||
		!strings.Contains(env, "NO_PROXY=localhost,127.0.0.1") {
		t.Fatalf("代理环境变量错误: %s", env)
	}
}

func TestProxyHTTPClientUsesConfiguredProxy(t *testing.T) {
	proxy := ProxyConfig{
		Enabled: true,
		Type:    "socks5",
		Host:    "127.0.0.1",
		Port:    1080,
	}
	client, err := proxy.HTTPClient(time.Second)
	if err != nil {
		t.Fatalf("创建代理客户端失败: %v", err)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	proxyURL, err := client.Transport.(*http.Transport).Proxy(request)
	if err != nil || proxyURL == nil || proxyURL.String() != "socks5://127.0.0.1:1080" {
		t.Fatalf("HTTP 客户端未使用代理: url=%v err=%v", proxyURL, err)
	}
}

func TestProxyConfigValidation(t *testing.T) {
	if err := (ProxyConfig{Enabled: true, Type: "ftp", Host: "x", Port: 1}).Validate(); err == nil {
		t.Fatalf("非法代理类型应被拒绝")
	}
	if err := (ProxyConfig{Enabled: true, Type: "http", Host: "x", Port: 70000}).Validate(); err == nil {
		t.Fatalf("非法端口应被拒绝")
	}
	if err := (ProxyConfig{Enabled: true, Type: "http", Host: "x", Port: 1, Password: "secret"}).Validate(); err == nil {
		t.Fatalf("密码缺少用户名应被拒绝")
	}
}
