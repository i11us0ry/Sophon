package policy

import (
	"net"
	"net/url"
	"strings"

	"sophon/internal/database"
)

type Scope struct {
	hosts map[string]bool
	cidrs []*net.IPNet
}

func newScope(assets []database.Asset) Scope {
	scope := Scope{hosts: map[string]bool{}}
	for _, asset := range assets {
		value := strings.TrimSpace(asset.Value)
		if value == "" {
			value = strings.TrimSpace(asset.Name)
		}
		value = normalizeAssetHost(value)
		if value == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(value); err == nil {
			scope.cidrs = append(scope.cidrs, network)
			continue
		}
		scope.hosts[strings.ToLower(value)] = true
	}
	return scope
}

func (s Scope) Allows(target string) bool {
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if target == "" {
		return false
	}
	if ip := net.ParseIP(target); ip != nil {
		for _, network := range s.cidrs {
			if network.Contains(ip) {
				return true
			}
		}
	}
	for host := range s.hosts {
		if hostAllows(host, target) {
			return true
		}
	}
	return false
}

func normalizeAssetHost(value string) string {
	value = strings.ToLower(strings.Trim(strings.TrimSpace(value), "<>"))
	// 兼容用户手写的 *example.com，统一成通配符形式，避免存进去后永远匹配不到。
	if strings.HasPrefix(value, "*") && !strings.HasPrefix(value, "*.") {
		value = "*." + strings.TrimPrefix(value, "*")
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		host := strings.ToLower(parsed.Hostname())
		if strings.HasPrefix(value, "*.") {
			return "*." + host
		}
		return host
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		host = strings.ToLower(strings.Trim(host, "[]"))
		if strings.HasPrefix(value, "*.") {
			return "*." + host
		}
		return host
	}
	return strings.ToLower(strings.Trim(value, "[]"))
}

func hostAllows(pattern, target string) bool {
	if pattern == target {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(target, suffix) && len(target) > len(suffix)
	}
	if !strings.Contains(pattern, ".") {
		return false
	}
	// 裸域名同时覆盖其子域，但要求点边界，避免 evilexample.com 误匹配 example.com。
	return strings.HasSuffix(target, "."+pattern)
}
