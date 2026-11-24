package intel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"sophon/internal/config"
	"sophon/internal/outbound"
)

const (
	FOFAEndpoint      = "https://fofa.info/api/v1/search/all"
	FOFAInfoEndpoint  = "https://fofa.info/api/v1/info/my"
	HunterEndpoint    = "https://hunter.qianxin.com/openApi/search"
	maxResponseBytes  = 2 << 20
	maxProviderDetail = 300
	maxProviderURL    = 2048
)

type Settings struct {
	FOFAEmail string
	FOFAKey   string
	HunterKey string
}

type SearchOptions struct {
	Page      int
	PageSize  int
	StartTime string
}

type Result struct {
	Source     string   `json:"source"`
	URL        string   `json:"url"`
	Domain     string   `json:"domain"`
	IP         string   `json:"ip"`
	Port       int      `json:"port"`
	Title      string   `json:"title"`
	Protocol   string   `json:"protocol"`
	Server     string   `json:"server"`
	Org        string   `json:"org"`
	Location   string   `json:"location"`
	UpdatedAt  string   `json:"updatedAt"`
	Components []string `json:"components"`
	Sources    []string `json:"sources"`
}

type Client struct {
	HTTP             *http.Client
	FOFAEndpoint     string
	FOFAInfoEndpoint string
	HunterEndpoint   string
}

func NewClient(client *http.Client) Client {
	return Client{
		HTTP:             client,
		FOFAEndpoint:     FOFAEndpoint,
		FOFAInfoEndpoint: FOFAInfoEndpoint,
		HunterEndpoint:   HunterEndpoint,
	}
}

func NewHTTPClient(proxy config.ProxyConfig, timeout time.Duration) (*http.Client, error) {
	base, err := proxy.HTTPClient(timeout)
	if err != nil {
		return nil, err
	}
	transport, ok := base.Transport.(*http.Transport)
	if !ok || transport == nil {
		return nil, fmt.Errorf("情报 HTTP Transport 不可用")
	}
	transport = transport.Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 15 * time.Second
	base.Transport = transport
	client, err := outbound.NewHTTPClient(base, outbound.Policy{
		AllowPrivate: false,
		ProxyHost:    proxy.Host,
		ProxyPort:    proxy.Port,
	})
	if err != nil {
		return nil, err
	}
	return client, nil
}

func (c Client) SearchFOFA(
	ctx context.Context,
	settings Settings,
	query string,
	options SearchOptions,
) ([]Result, error) {
	if strings.TrimSpace(settings.FOFAEmail) == "" || strings.TrimSpace(settings.FOFAKey) == "" {
		return nil, fmt.Errorf("FOFA Email 或 Key 未配置")
	}
	endpoint := c.FOFAEndpoint
	if endpoint == "" {
		endpoint = FOFAEndpoint
	}
	params := url.Values{}
	params.Set("email", strings.TrimSpace(settings.FOFAEmail))
	params.Set("key", strings.TrimSpace(settings.FOFAKey))
	params.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(query)))
	params.Set("page", strconv.Itoa(options.Page))
	params.Set("size", strconv.Itoa(options.PageSize))
	params.Set(
		"fields",
		"ip,port,host,domain,title,city,server,protocol,certs_subject_org",
	)
	var response struct {
		Error   bool       `json:"error"`
		ErrMsg  string     `json:"errmsg"`
		Results [][]string `json:"results"`
	}
	if err := c.getJSON(ctx, endpoint, params, &response); err != nil {
		return nil, err
	}
	if response.Error {
		return nil, fmt.Errorf("FOFA: %s", providerDetail(response.ErrMsg, settings.FOFAKey))
	}
	results := make([]Result, 0, len(response.Results))
	for _, row := range response.Results {
		if len(row) < 8 {
			continue
		}
		port, _ := strconv.Atoi(strings.TrimSpace(row[1]))
		results = append(results, Result{
			Source:   "fofa",
			IP:       strings.TrimSpace(row[0]),
			Port:     port,
			URL:      normalizeProviderURL(row[2], row[7], row[3], row[0], port),
			Domain:   strings.TrimSpace(row[3]),
			Title:    strings.TrimSpace(row[4]),
			Location: strings.TrimSpace(row[5]),
			Server:   strings.TrimSpace(row[6]),
			Protocol: strings.TrimSpace(row[7]),
			Org:      firstRowValue(row, 8),
			Sources:  []string{"fofa"},
		})
	}
	return results, nil
}

func (c Client) SearchHunter(
	ctx context.Context,
	settings Settings,
	query string,
	options SearchOptions,
) ([]Result, error) {
	if strings.TrimSpace(settings.HunterKey) == "" {
		return nil, fmt.Errorf("Hunter Key 未配置")
	}
	endpoint := c.HunterEndpoint
	if endpoint == "" {
		endpoint = HunterEndpoint
	}
	params := url.Values{}
	params.Set("api-key", strings.TrimSpace(settings.HunterKey))
	params.Set("search", base64.URLEncoding.EncodeToString([]byte(query)))
	params.Set("page", strconv.Itoa(options.Page))
	params.Set("page_size", strconv.Itoa(options.PageSize))
	params.Set("is_web", "3")
	params.Set("port_filter", "false")
	if start := strings.TrimSpace(options.StartTime); start != "" {
		params.Set("start_time", start)
	}
	var response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Arr []struct {
				URL        string `json:"url"`
				IP         string `json:"ip"`
				Port       int    `json:"port"`
				WebTitle   string `json:"web_title"`
				Domain     string `json:"domain"`
				Protocol   string `json:"protocol"`
				Company    string `json:"company"`
				City       string `json:"city"`
				UpdatedAt  string `json:"updated_at"`
				Components []struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"component"`
			} `json:"arr"`
		} `json:"data"`
	}
	if err := c.getJSON(ctx, endpoint, params, &response); err != nil {
		return nil, err
	}
	if response.Code != http.StatusOK {
		return nil, fmt.Errorf("Hunter: %s", providerDetail(response.Message, settings.HunterKey))
	}
	results := make([]Result, 0, len(response.Data.Arr))
	for _, row := range response.Data.Arr {
		components := make([]string, 0, len(row.Components))
		for _, component := range row.Components {
			value := strings.TrimSpace(component.Name)
			if version := strings.TrimSpace(component.Version); version != "" {
				value = strings.TrimSpace(value + " " + version)
			}
			if value != "" {
				components = append(components, value)
			}
		}
		results = append(results, Result{
			Source:     "hunter",
			URL:        normalizeProviderURL(row.URL, row.Protocol, row.Domain, row.IP, row.Port),
			Domain:     strings.TrimSpace(row.Domain),
			IP:         strings.TrimSpace(row.IP),
			Port:       row.Port,
			Title:      strings.TrimSpace(row.WebTitle),
			Protocol:   strings.TrimSpace(row.Protocol),
			Org:        strings.TrimSpace(row.Company),
			Location:   strings.TrimSpace(row.City),
			UpdatedAt:  strings.TrimSpace(row.UpdatedAt),
			Components: components,
			Sources:    []string{"hunter"},
		})
	}
	return results, nil
}

func (c Client) TestFOFA(ctx context.Context, settings Settings) error {
	if strings.TrimSpace(settings.FOFAEmail) == "" || strings.TrimSpace(settings.FOFAKey) == "" {
		return fmt.Errorf("FOFA Email 或 Key 未配置")
	}
	endpoint := c.FOFAInfoEndpoint
	if endpoint == "" {
		endpoint = FOFAInfoEndpoint
	}
	params := url.Values{}
	params.Set("email", strings.TrimSpace(settings.FOFAEmail))
	params.Set("key", strings.TrimSpace(settings.FOFAKey))
	var response struct {
		Error  bool   `json:"error"`
		ErrMsg string `json:"errmsg"`
	}
	if err := c.getJSON(ctx, endpoint, params, &response); err != nil {
		return err
	}
	if response.Error {
		return fmt.Errorf("FOFA: %s", providerDetail(response.ErrMsg, settings.FOFAKey))
	}
	return nil
}

func (c Client) TestHunter(ctx context.Context, settings Settings) error {
	start := time.Now().UTC().AddDate(0, 0, -30).Format("2006-01-02")
	_, err := c.SearchHunter(ctx, settings, `ip="8.8.8.8"`, SearchOptions{
		Page:      1,
		PageSize:  1,
		StartTime: start,
	})
	return err
}

func (c Client) getJSON(
	ctx context.Context,
	endpoint string,
	params url.Values,
	target interface{},
) error {
	if c.HTTP == nil {
		return fmt.Errorf("情报 HTTP 客户端不可用")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
		if err != nil {
			return fmt.Errorf("创建情报请求失败: %w", err)
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "Sophon/0.1")
		response, err := c.HTTP.Do(request)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			lastErr = fmt.Errorf("情报接口请求失败")
			if attempt < 2 && ctx.Err() == nil {
				if err := waitRetry(ctx, attempt); err != nil {
					return err
				}
				continue
			}
			return lastErr
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
		_ = response.Body.Close()
		if readErr != nil {
			return fmt.Errorf("读取情报响应失败: %w", readErr)
		}
		if len(body) > maxResponseBytes {
			return fmt.Errorf("情报响应超过 2 MB 限制")
		}
		if retryableStatus(response.StatusCode) && attempt < 2 {
			lastErr = fmt.Errorf("情报接口返回 HTTP %d", response.StatusCode)
			if err := waitRetry(ctx, attempt); err != nil {
				return err
			}
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return fmt.Errorf("情报接口返回 HTTP %d", response.StatusCode)
		}
		if err := json.Unmarshal(body, target); err != nil {
			return fmt.Errorf("解析情报响应失败: %w", err)
		}
		return nil
	}
	return lastErr
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func waitRetry(ctx context.Context, attempt int) error {
	delay := time.Duration(attempt+1) * 500 * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func normalizeProviderURL(rawURL, protocol, domain, ip string, port int) string {
	rawURL = strings.TrimSpace(rawURL)
	if len([]rune(rawURL)) > maxProviderURL || containsControlCharacter(rawURL) {
		return ""
	}
	parsedURL, parseErr := url.Parse(rawURL)
	if parseErr == nil {
		scheme := strings.ToLower(strings.TrimSpace(parsedURL.Scheme))
		if scheme == "http" || scheme == "https" {
			if parsedURL.Hostname() == "" || parsedURL.User != nil {
				return ""
			}
			parsedURL.Scheme = scheme
			parsedURL.Host = strings.ToLower(parsedURL.Host)
			parsedURL.Fragment = ""
			parsedURL.RawFragment = ""
			return parsedURL.String()
		}
		if scheme != "" && (parsedURL.Opaque != "" || parsedURL.Host != "") {
			_, portValue, err := net.SplitHostPort(rawURL)
			if err != nil {
				return ""
			}
			portNumber, err := strconv.Atoi(portValue)
			if err != nil || portNumber < 1 || portNumber > 65535 {
				return ""
			}
		}
	} else if strings.Contains(rawURL, "://") {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(protocol))
	switch scheme {
	case "https", "tls":
		scheme = "https"
	case "http":
	default:
		return ""
	}
	host := strings.TrimSpace(domain)
	if host == "" {
		host = strings.TrimSpace(ip)
	}
	if host == "" {
		return ""
	}
	if port > 0 {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	value := scheme + "://" + host
	if len([]rune(value)) > maxProviderURL || containsControlCharacter(value) {
		return ""
	}
	return value
}

func containsControlCharacter(value string) bool {
	for _, char := range value {
		if unicode.IsControl(char) {
			return true
		}
	}
	return false
}

func providerDetail(value string, secrets ...string) string {
	value = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value))
	for _, secret := range secrets {
		if secret = strings.TrimSpace(secret); secret != "" {
			value = strings.ReplaceAll(value, secret, "****")
		}
	}
	if value == "" {
		value = "接口返回异常"
	}
	runes := []rune(value)
	if len(runes) > maxProviderDetail {
		value = string(runes[:maxProviderDetail]) + "..."
	}
	return value
}

func firstRowValue(row []string, index int) string {
	if index < 0 || index >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[index])
}

func Deduplicate(results []Result, limit int) []Result {
	merged := make([]Result, 0, len(results))
	indexByKey := make(map[string]int, len(results))
	for _, result := range results {
		key := resultKey(result)
		if key == "" {
			continue
		}
		if index, ok := indexByKey[key]; ok {
			merged[index] = mergeResult(merged[index], result)
			continue
		}
		if limit > 0 && len(merged) >= limit {
			continue
		}
		indexByKey[key] = len(merged)
		merged = append(merged, result)
	}
	return merged
}

func resultKey(result Result) string {
	if value := strings.ToLower(strings.TrimSpace(result.URL)); value != "" {
		return "url|" + value
	}
	protocol := strings.ToLower(strings.TrimSpace(result.Protocol))
	if value := strings.ToLower(strings.TrimSpace(result.Domain)); value != "" {
		return fmt.Sprintf("domain|%s|%d|%s", value, result.Port, protocol)
	}
	if value := strings.ToLower(strings.TrimSpace(result.IP)); value != "" {
		return fmt.Sprintf("ip|%s|%d|%s", value, result.Port, protocol)
	}
	return ""
}

func mergeResult(left, right Result) Result {
	if left.URL == "" {
		left.URL = right.URL
	}
	if left.Domain == "" {
		left.Domain = right.Domain
	}
	if left.IP == "" {
		left.IP = right.IP
	}
	if left.Port == 0 {
		left.Port = right.Port
	}
	if left.Title == "" {
		left.Title = right.Title
	}
	if left.Protocol == "" {
		left.Protocol = right.Protocol
	}
	if left.Server == "" {
		left.Server = right.Server
	}
	if left.Org == "" {
		left.Org = right.Org
	}
	if left.Location == "" {
		left.Location = right.Location
	}
	if left.UpdatedAt == "" {
		left.UpdatedAt = right.UpdatedAt
	}
	if len(left.Components) == 0 {
		left.Components = append([]string(nil), right.Components...)
	}
	seenSources := make(map[string]bool, len(left.Sources)+len(right.Sources))
	sources := make([]string, 0, len(left.Sources)+len(right.Sources))
	for _, source := range append(append([]string(nil), left.Sources...), right.Sources...) {
		source = strings.ToLower(strings.TrimSpace(source))
		if source == "" || seenSources[source] {
			continue
		}
		seenSources[source] = true
		sources = append(sources, source)
	}
	left.Sources = sources
	return left
}
