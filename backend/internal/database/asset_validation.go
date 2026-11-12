package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrInvalidAsset   = errors.New("invalid asset")
	ErrAssetDuplicate = errors.New("asset already exists")
	ErrAssetInUse     = errors.New("asset is referenced")
)

var assetStatuses = map[string]bool{
	"unknown":  true,
	"active":   true,
	"inactive": true,
	"retired":  true,
}

var assetCriticalities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

var supportedAssetKinds = map[string]bool{
	"ip":     true,
	"domain": true,
	"url":    true,
	"port":   true,
	"host":   true,
}

const (
	assetNameMaxRunes  = 120
	assetValueMaxRunes = 4096
)

func IsSupportedAssetKind(kind string) bool {
	return supportedAssetKinds[strings.ToLower(strings.TrimSpace(kind))]
}

func NormalizeAssetValue(kind string, value string) (string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = strings.TrimSpace(value)
	switch kind {
	case "domain":
		return normalizeDomainAssetValue(value)
	case "ip":
		ip := net.ParseIP(strings.Trim(value, "[]"))
		if ip == nil {
			return "", fmt.Errorf("IP 资产值不是有效 IP 地址")
		}
		return ip.String(), nil
	case "url":
		return normalizeURLAssetValue(value)
	case "port":
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("端口资产值必须在 1-65535 之间")
		}
		return strconv.Itoa(port), nil
	case "host":
		return normalizeHostAssetValue(value)
	default:
		return "", fmt.Errorf("资产类型只能是 ip、domain、url、port 或 host")
	}
}

func normalizeDomainAssetValue(value string) (string, error) {
	value = strings.TrimSpace(strings.TrimSuffix(value, "."))
	if value == "" || strings.Contains(value, "://") ||
		strings.ContainsAny(value, " \t\r\n/\\@?#") {
		return "", fmt.Errorf("域名资产值格式不合法")
	}
	wildcard := strings.HasPrefix(value, "*.")
	hostValue := value
	if wildcard {
		hostValue = strings.TrimPrefix(hostValue, "*.")
	}
	host, port, err := splitAssetHostPort(hostValue)
	if err != nil {
		return "", err
	}
	if wildcard && port != "" {
		return "", fmt.Errorf("通配域名不能包含端口")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return "", fmt.Errorf("IP 地址必须使用 ip 类型")
	}
	asciiHost, err := idna.Lookup.ToASCII(host)
	if err != nil || !validHostLabels(asciiHost, false) {
		return "", fmt.Errorf("域名资产值包含非法标签")
	}
	suffix, icann := publicsuffix.PublicSuffix(asciiHost)
	if suffix == "" || suffix == asciiHost {
		return "", fmt.Errorf("域名资产值不能是公共后缀本身")
	}
	if !icann && !strings.Contains(suffix, ".") {
		return "", fmt.Errorf("域名资产值没有可注册后缀")
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(asciiHost); err != nil {
		return "", fmt.Errorf("域名资产值没有有效注册域")
	}
	normalized := asciiHost
	if wildcard {
		normalized = "*." + normalized
	}
	if port != "" {
		normalized = net.JoinHostPort(normalized, port)
	}
	return strings.ToLower(normalized), nil
}

func normalizeURLAssetValue(value string) (string, error) {
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return "", fmt.Errorf("URL 资产值格式不合法")
	}
	parsed, err := url.Parse(value)
	if err != nil ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Hostname() == "" ||
		parsed.User != nil {
		return "", fmt.Errorf("URL 资产值必须是有效的 HTTP/HTTPS 地址")
	}
	host := parsed.Hostname()
	if net.ParseIP(strings.Trim(host, "[]")) == nil && !validHostLabels(host, true) {
		return "", fmt.Errorf("URL 资产值主机名不合法")
	}
	if port := parsed.Port(); port != "" {
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return "", fmt.Errorf("URL 资产值端口不合法")
		}
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	return parsed.String(), nil
}

func normalizeHostAssetValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("主机资产值格式不合法")
	}
	if _, network, err := net.ParseCIDR(value); err == nil {
		return network.String(), nil
	}
	if strings.ContainsAny(value, " \t\r\n/\\@?#") {
		return "", fmt.Errorf("主机资产值格式不合法")
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String(), nil
	}
	host, port, err := splitAssetHostPort(value)
	if err != nil {
		return "", err
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		host = ip.String()
	} else {
		asciiHost, err := idna.Lookup.ToASCII(host)
		if err != nil || !validHostLabels(asciiHost, true) {
			return "", fmt.Errorf("主机资产值格式不合法")
		}
		host = asciiHost
	}
	if port != "" {
		return net.JoinHostPort(host, port), nil
	}
	return host, nil
}

func splitAssetHostPort(value string) (string, string, error) {
	if strings.Count(value, ":") == 0 {
		return value, "", nil
	}
	if strings.HasPrefix(value, "[") {
		host, port, err := net.SplitHostPort(value)
		if err != nil || !validAssetPort(port) {
			return "", "", fmt.Errorf("资产值端口不合法")
		}
		return host, port, nil
	}
	if strings.Count(value, ":") != 1 {
		return "", "", fmt.Errorf("资产值主机格式不合法")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || !validAssetPort(port) {
		return "", "", fmt.Errorf("资产值端口不合法")
	}
	return host, port, nil
}

func validAssetPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}

func validHostLabels(host string, allowUnderscore bool) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/\\@?#:") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char >= 'a' && char <= 'z') ||
				(char >= '0' && char <= '9') ||
				char == '-' ||
				(allowUnderscore && char == '_') {
				continue
			}
			return false
		}
	}
	return true
}

func normalizeAssetRecord(item *Asset) error {
	item.ID = strings.TrimSpace(item.ID)
	item.ProjectID = strings.TrimSpace(item.ProjectID)
	item.OwnerUserID = strings.TrimSpace(item.OwnerUserID)
	item.Name = strings.TrimSpace(item.Name)
	item.Kind = strings.ToLower(strings.TrimSpace(item.Kind))
	item.Value = strings.TrimSpace(item.Value)
	item.Status = strings.ToLower(strings.TrimSpace(item.Status))
	item.Criticality = strings.ToLower(strings.TrimSpace(item.Criticality))

	if item.ID == "" || item.OwnerUserID == "" {
		return fmt.Errorf("%w: 资产 ID 和所有者不能为空", ErrInvalidAsset)
	}
	if item.Name == "" || len([]rune(item.Name)) > assetNameMaxRunes {
		return fmt.Errorf("%w: 资产名称不能为空且不能超过 %d 个字符", ErrInvalidAsset, assetNameMaxRunes)
	}
	if !IsSupportedAssetKind(item.Kind) {
		return fmt.Errorf("%w: 资产类型只能是 ip、domain、url、port 或 host", ErrInvalidAsset)
	}
	if item.Value == "" || len([]rune(item.Value)) > assetValueMaxRunes {
		return fmt.Errorf("%w: 资产值不能为空且不能超过 %d 个字符", ErrInvalidAsset, assetValueMaxRunes)
	}
	normalizedValue, err := NormalizeAssetValue(item.Kind, item.Value)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidAsset, err.Error())
	}
	item.Value = normalizedValue
	if item.Status == "" {
		item.Status = "unknown"
	}
	if !assetStatuses[item.Status] {
		return fmt.Errorf("%w: 资产状态不合法", ErrInvalidAsset)
	}
	if item.Criticality == "" {
		item.Criticality = "medium"
	}
	if !assetCriticalities[item.Criticality] {
		return fmt.Errorf("%w: 资产关键度不合法", ErrInvalidAsset)
	}
	if item.RiskScore < 0 || item.RiskScore > 100 {
		return fmt.Errorf("%w: 风险分必须在 0 到 100 之间", ErrInvalidAsset)
	}
	return nil
}

func assetDuplicateExists(
	ctx context.Context,
	tx *sql.Tx,
	item Asset,
	excludeID string,
) (bool, error) {
	query := `SELECT COUNT(*) FROM assets
		WHERE owner_user_id = ? AND project_id = ?
		  AND LOWER(TRIM(kind)) = LOWER(TRIM(?))
		  AND LOWER(TRIM(value)) = LOWER(TRIM(?))`
	args := []interface{}{item.OwnerUserID, item.ProjectID, item.Kind, item.Value}
	if excludeID != "" {
		query += ` AND id <> ?`
		args = append(args, excludeID)
	}
	var count int
	if err := tx.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func assetRelationMatches(assetID, name, value string) []string {
	assetID = strings.ToLower(strings.TrimSpace(assetID))
	name = strings.ToLower(strings.TrimSpace(name))
	value = strings.ToLower(strings.TrimSpace(value))
	patterns := []string{"asset_id:" + assetID, "asset:" + assetID}
	if value != "" {
		patterns = append(patterns, "asset:"+value)
	}
	if name != "" {
		patterns = append(patterns, "asset:"+name)
	}
	return patterns
}

func assetHasReferences(
	ctx context.Context,
	tx *sql.Tx,
	item Asset,
	oldProjectID string,
	oldName string,
	oldValue string,
) (bool, error) {
	for _, query := range []string{
		`SELECT COUNT(*) FROM vulnerabilities WHERE asset_id = ?`,
		`SELECT COUNT(*) FROM project_graph_nodes WHERE asset_id = ?`,
	} {
		var count int
		if err := tx.QueryRowContext(ctx, query, item.ID).Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return true, nil
		}
	}

	patterns := assetRelationMatches(item.ID, oldName, oldValue)
	args := make([]interface{}, 0, len(patterns)+1)
	args = append(args, oldProjectID)
	for _, pattern := range patterns {
		args = append(args, pattern)
	}
	var count int
	if err := tx.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM project_facts
		 WHERE project_id = ? AND LOWER(TRIM(relation)) IN (`+placeholders(len(patterns))+`)`,
		args...,
	).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func clearAssetFactRelations(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	assetID string,
	name string,
	value string,
) error {
	patterns := assetRelationMatches(assetID, name, value)
	args := make([]interface{}, 0, len(patterns)+1)
	args = append(args, projectID)
	for _, pattern := range patterns {
		args = append(args, pattern)
	}
	_, err := tx.ExecContext(
		ctx,
		`UPDATE project_facts SET relation = ''
		 WHERE project_id = ? AND LOWER(TRIM(relation)) IN (`+placeholders(len(patterns))+`)`,
		args...,
	)
	return err
}

func canonicalizeAssetFactRelations(
	ctx context.Context,
	tx *sql.Tx,
	projectID string,
	assetID string,
	name string,
	value string,
) error {
	patterns := assetRelationMatches(assetID, name, value)
	args := []interface{}{"asset_id:" + assetID, projectID}
	for _, pattern := range patterns {
		args = append(args, pattern)
	}
	_, err := tx.ExecContext(
		ctx,
		`UPDATE project_facts SET relation = ?
		 WHERE project_id = ? AND LOWER(TRIM(relation)) IN (`+placeholders(len(patterns))+`)`,
		args...,
	)
	return err
}
