package outbound

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

const maxRedirects = 3

type Policy struct {
	AllowPrivate bool
	ProxyHost    string
	ProxyPort    int
}

// ValidateURL 校验出站 URL 及其解析结果。
func ValidateURL(ctx context.Context, rawURL string, policy Policy) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("URL 不合法")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("仅支持 http/https 地址")
	}
	host := strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), ".")
	if host == "" {
		return nil, fmt.Errorf("地址缺少主机名")
	}
	if isMetadataHost(host) {
		return nil, fmt.Errorf("不允许访问云元数据地址")
	}
	if err := validateHost(ctx, host, policy); err != nil {
		return nil, err
	}
	return parsed, nil
}

// NewHTTPClient 在现有代理客户端上增加 DNS/重定向/出站地址校验。
func NewHTTPClient(base *http.Client, policy Policy) (*http.Client, error) {
	if base == nil {
		return nil, fmt.Errorf("HTTP 客户端不能为空")
	}
	transport, ok := base.Transport.(*http.Transport)
	if !ok || transport == nil {
		return nil, fmt.Errorf("HTTP Transport 不支持安全校验")
	}
	clonedTransport := transport.Clone()
	originalDial := clonedTransport.DialContext
	if originalDial == nil {
		dialer := &net.Dialer{Timeout: base.Timeout}
		originalDial = dialer.DialContext
	}
	clonedTransport.DialContext = func(
		ctx context.Context,
		network string,
		address string,
	) (net.Conn, error) {
		host, port := splitHostPort(address)
		if !policy.isProxyAddress(host, port) {
			if err := validateHost(ctx, host, policy); err != nil {
				return nil, err
			}
		}
		return originalDial(ctx, network, address)
	}

	cloned := *base
	cloned.Transport = &validatingTransport{
		base:   clonedTransport,
		policy: policy,
	}
	cloned.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("重定向次数超过 %d 次", maxRedirects)
		}
		_, err := ValidateURL(request.Context(), request.URL.String(), policy)
		return err
	}
	return &cloned, nil
}

type validatingTransport struct {
	base   http.RoundTripper
	policy Policy
}

func (t *validatingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil {
		return nil, fmt.Errorf("请求地址不能为空")
	}
	if _, err := ValidateURL(request.Context(), request.URL.String(), t.policy); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(request)
}

func validateHost(ctx context.Context, host string, policy Policy) error {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return fmt.Errorf("地址缺少主机名")
	}
	if isMetadataHost(host) {
		return fmt.Errorf("不允许访问云元数据地址")
	}
	if ip := parseHostIP(host); ip != nil {
		if isForbiddenIP(ip, policy.AllowPrivate) {
			return fmt.Errorf("不允许访问受保护的内网地址")
		}
		return nil
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return fmt.Errorf("无法解析目标主机")
	}
	for _, address := range addresses {
		if isForbiddenIP(address.IP, policy.AllowPrivate) {
			return fmt.Errorf("目标主机解析到受保护的内网地址")
		}
	}
	return nil
}

func (p Policy) isProxyAddress(host string, port string) bool {
	proxyHost := strings.TrimSuffix(strings.TrimSpace(p.ProxyHost), ".")
	if proxyHost == "" || !strings.EqualFold(strings.TrimSuffix(host, "."), proxyHost) {
		return false
	}
	if p.ProxyPort <= 0 || port == "" {
		return true
	}
	return port == fmt.Sprintf("%d", p.ProxyPort)
}

func splitHostPort(address string) (string, string) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(address))
	if err == nil {
		return host, port
	}
	return strings.Trim(address, "[]"), ""
}

func parseHostIP(host string) net.IP {
	if zone := strings.LastIndex(host, "%"); zone >= 0 {
		host = host[:zone]
	}
	return net.ParseIP(host)
}

func isMetadataHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "metadata.google.internal", "metadata", "instance-data":
		return true
	default:
		return false
	}
}

func isForbiddenIP(ip net.IP, allowPrivate bool) bool {
	if ip == nil {
		return true
	}
	if ip.IsUnspecified() ||
		ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.Equal(net.ParseIP("100.100.100.200")) ||
		ip.Equal(net.ParseIP("192.0.0.192")) ||
		ip.Equal(net.ParseIP("fd00:ec2::254")) {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || isCGNAT(ip) {
		return !allowPrivate
	}
	return false
}

func isCGNAT(ip net.IP) bool {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return false
	}
	return ipv4[0] == 100 && ipv4[1] >= 64 && ipv4[1] <= 127
}
