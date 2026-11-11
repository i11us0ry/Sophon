package config

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ProxyConfig struct {
	Enabled  bool
	Type     string
	Host     string
	Port     int
	Username string
	Password string
	NoProxy  string
}

func normalizeProxyType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "https":
		return "https"
	case "socks5", "socks5h":
		return "socks5"
	default:
		return "http"
	}
}

func (p ProxyConfig) Validate() error {
	if !p.Enabled {
		return nil
	}
	rawType := strings.ToLower(strings.TrimSpace(p.Type))
	if rawType != "http" && rawType != "https" &&
		rawType != "socks5" && rawType != "socks5h" {
		return fmt.Errorf("代理类型仅支持 http、https、socks5")
	}
	if strings.TrimSpace(p.Host) == "" {
		return fmt.Errorf("代理主机不能为空")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("代理端口需在 1-65535 之间")
	}
	if strings.TrimSpace(p.Password) != "" && strings.TrimSpace(p.Username) == "" {
		return fmt.Errorf("配置代理密码时必须填写用户名")
	}
	return nil
}

func (p ProxyConfig) URL() (*url.URL, error) {
	if !p.Enabled {
		return nil, nil
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	proxyURL := &url.URL{
		Scheme: normalizeProxyType(p.Type),
		Host:   net.JoinHostPort(strings.TrimSpace(p.Host), strconv.Itoa(p.Port)),
	}
	if username := strings.TrimSpace(p.Username); username != "" {
		proxyURL.User = url.UserPassword(username, p.Password)
	}
	return proxyURL, nil
}

func (p ProxyConfig) HTTPClient(timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxyURL, err := p.URL()
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		transport.Proxy = nil
	} else {
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

func (p ProxyConfig) Environment() []string {
	proxyURL, err := p.URL()
	if err != nil || proxyURL == nil {
		return []string{}
	}
	value := proxyURL.String()
	env := []string{
		"HTTP_PROXY=" + value,
		"HTTPS_PROXY=" + value,
		"ALL_PROXY=" + value,
		"http_proxy=" + value,
		"https_proxy=" + value,
		"all_proxy=" + value,
	}
	if noProxy := strings.TrimSpace(p.NoProxy); noProxy != "" {
		env = append(
			env,
			"NO_PROXY="+noProxy,
			"no_proxy="+noProxy,
		)
	}
	return env
}
