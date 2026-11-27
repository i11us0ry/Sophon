package database

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type ProjectScopeAsset struct {
	Value       string
	Description string
}

type ProjectScopeSyncResult struct {
	Parsed  int `json:"parsed"`
	Created int `json:"created"`
	Skipped int `json:"skipped"`
}

var (
	scopeURLPattern  = regexp.MustCompile(`(?i)https?://[^\s,，;；、"'<>]+`)
	scopeIPv4Pattern = regexp.MustCompile(
		`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`,
	)
	scopeHostPattern = regexp.MustCompile(
		`(?i)((?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+` +
			`(?:[a-z]{2,63}|[a-z0-9-]{2,63}))`,
	)
)

// ParseProjectScopeAssets 从项目「资产范围」自由文本中提取可执行的授权资产。
// 支持域名、*.通配域名、IP、CIDR 和 URL；同时保留行内说明作为资产名称。
func ParseProjectScopeAssets(scope string) []ProjectScopeAsset {
	seen := map[string]bool{}
	items := make([]ProjectScopeAsset, 0)
	add := func(value, description string) {
		value = normalizeScopeAssetValue(value)
		if value == "" || seen[strings.ToLower(value)] {
			return
		}
		seen[strings.ToLower(value)] = true
		items = append(items, ProjectScopeAsset{
			Value:       value,
			Description: strings.TrimSpace(description),
		})
	}

	for _, rawLine := range strings.Split(scope, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		added := 0
		for _, match := range scopeURLPattern.FindAllString(line, -1) {
			rawURL := strings.TrimSpace(strings.Trim(match, `"'<>()[]{}（）【】`))
			if rawURL == "" {
				continue
			}
			// URL 原样保留，方便资产页展示用户实际填写的入口。
			if !seen[strings.ToLower(rawURL)] {
				seen[strings.ToLower(rawURL)] = true
				items = append(items, ProjectScopeAsset{
					Value:       rawURL,
					Description: strings.TrimSpace(line),
				})
			}
			added++
		}
		if added > 0 {
			continue
		}
		for _, match := range scopeIPv4Pattern.FindAllString(line, -1) {
			if normalizeScopeAssetValue(match) != "" {
				add(match, line)
				added++
			}
		}
		if added > 0 && len(strings.Fields(line)) == 1 {
			continue
		}
		for _, sub := range scopeHostPattern.FindAllStringSubmatchIndex(line, -1) {
			start, end := sub[2], sub[3]
			if start < 0 || end <= start {
				continue
			}
			token := line[start:end]
			if start > 0 && line[start-1] == '*' {
				token = "*." + strings.TrimPrefix(token, "*")
			}
			if isHostnameCandidate(token) {
				add(token, line)
				added++
			}
		}
		if added > 0 {
			continue
		}
		token := strings.Trim(line, `,，;；、"'<>()[]{}（）【】`)
		if isHostnameCandidate(token) {
			add(token, line)
		}
	}
	return items
}

// SyncProjectScopeAssets 把资产范围中的条目幂等写入 assets 表。
// 只新增缺失项，不删除用户手工维护的资产，避免影响已有事实、漏洞和战役引用。
func (db *DB) SyncProjectScopeAssets(
	ctx context.Context,
	projectID string,
	ownerUserID string,
	scope string,
) (ProjectScopeSyncResult, error) {
	parsed := ParseProjectScopeAssets(scope)
	result := ProjectScopeSyncResult{Parsed: len(parsed)}
	if len(parsed) == 0 {
		return result, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	for _, item := range parsed {
		var existingID string
		err := tx.QueryRowContext(
			ctx,
			`SELECT id FROM assets
			 WHERE project_id = ? AND owner_user_id = ? AND LOWER(TRIM(value)) = LOWER(TRIM(?))
			 LIMIT 1`,
			projectID,
			ownerUserID,
			item.Value,
		).Scan(&existingID)
		if err == nil {
			result.Skipped++
			continue
		}
		if !NoRows(err) {
			return result, err
		}
		name := item.Description
		if name == "" {
			name = item.Value
		}
		kind := inferAssetKind(item.Value)
		if kind == "" {
			result.Skipped++
			continue
		}
		asset := Asset{
			ID:          newID(),
			ProjectID:   projectID,
			OwnerUserID: ownerUserID,
			Name:        name,
			Kind:        kind,
			Value:       item.Value,
			Status:      "active",
			Source:      AssetSourceScope,
			Criticality: "medium",
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := normalizeAssetRecord(&asset); err != nil {
			result.Skipped++
			continue
		}
		duplicate, err := assetDuplicateExists(ctx, tx, asset, "")
		if err != nil {
			return result, err
		}
		if duplicate {
			result.Skipped++
			continue
		}
		if err := markCrossTypeAssetQuality(ctx, tx, &asset); err != nil {
			return result, err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO assets (
				id, project_id, owner_user_id, name, kind, value, normalized_value, quality_status, status, source,
				criticality, risk_score, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			asset.ID,
			asset.ProjectID,
			asset.OwnerUserID,
			asset.Name,
			asset.Kind,
			asset.Value,
			asset.NormalizedValue,
			asset.QualityStatus,
			asset.Status,
			asset.Source,
			asset.Criticality,
			asset.RiskScore,
			asset.CreatedAt.Unix(),
			asset.UpdatedAt.Unix(),
		); err != nil {
			return result, fmt.Errorf("同步授权资产失败: %w", err)
		}
		result.Created++
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

// backfillProjectScopeAssets 让升级前已保存的资产范围立即生效，
// 避免用户必须重新保存一次项目才会同步到 Policy Engine。
func (db *DB) backfillProjectScopeAssets(ctx context.Context) error {
	rows, err := db.QueryContext(
		ctx,
		`SELECT id, owner_user_id, scope FROM projects
		 WHERE TRIM(scope) <> ''`,
	)
	if err != nil {
		return err
	}
	type projectScope struct {
		id    string
		owner string
		scope string
	}
	items := make([]projectScope, 0)
	for rows.Next() {
		var item projectScope
		if err := rows.Scan(&item.id, &item.owner, &item.scope); err != nil {
			_ = rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := db.SyncProjectScopeAssets(ctx, item.id, item.owner, item.scope); err != nil {
			return err
		}
	}
	return nil
}

// markProjectScopeDerivedAssets 标记旧版范围同步产生的 Host 重复资产。
// 这些记录可能已被事实、漏洞或攻击路径引用，因此只降级质量状态，不删除数据。
func (db *DB) markProjectScopeDerivedAssets(ctx context.Context) error {
	rows, err := db.QueryContext(
		ctx,
		`SELECT project_id, owner_user_id, normalized_value
		 FROM assets
		 WHERE LOWER(TRIM(source)) = ?
		   AND LOWER(TRIM(kind)) = 'url'
		   AND TRIM(normalized_value) <> ''`,
		AssetSourceScope,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	urlHosts := make(map[string]bool)
	for rows.Next() {
		var projectID, ownerUserID, value string
		if err := rows.Scan(&projectID, &ownerUserID, &value); err != nil {
			return err
		}
		parsed, err := url.Parse(value)
		if err != nil {
			continue
		}
		host := normalizeScopeAssetValue(parsed.Hostname())
		if host == "" {
			continue
		}
		urlHosts[scopeAssetKey(projectID, ownerUserID, host)] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(urlHosts) == 0 {
		return nil
	}

	hostRows, err := db.QueryContext(
		ctx,
		`SELECT id, project_id, owner_user_id, normalized_value
		 FROM assets
		 WHERE LOWER(TRIM(source)) = ?
		   AND LOWER(TRIM(kind)) IN ('ip', 'domain')
		   AND TRIM(normalized_value) <> ''`,
		AssetSourceScope,
	)
	if err != nil {
		return err
	}
	defer hostRows.Close()

	for hostRows.Next() {
		var id, projectID, ownerUserID, value string
		if err := hostRows.Scan(&id, &projectID, &ownerUserID, &value); err != nil {
			return err
		}
		if !urlHosts[scopeAssetKey(projectID, ownerUserID, value)] {
			continue
		}
		if _, err := db.ExecContext(
			ctx,
			`UPDATE assets
			 SET quality_status = ?
			 WHERE id = ? AND quality_status <> ?`,
			AssetQualityCrossTypeDuplicate,
			id,
			AssetQualityCrossTypeDuplicate,
		); err != nil {
			return err
		}
	}
	return hostRows.Err()
}

func scopeAssetKey(projectID, ownerUserID, value string) string {
	return strings.Join([]string{
		strings.TrimSpace(projectID),
		strings.TrimSpace(ownerUserID),
		strings.ToLower(strings.TrimSpace(value)),
	}, "\x00")
}

func normalizeScopeAssetValue(value string) string {
	value = strings.TrimSpace(strings.Trim(value, `"'<>()[]{}（）【】`))
	if value == "" || strings.ContainsAny(value, " \t") {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Hostname() == "" {
			return ""
		}
		return strings.ToLower(parsed.Hostname())
	}
	if _, network, err := net.ParseCIDR(value); err == nil {
		return network.String()
	}
	if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
		return ip.String()
	}
	if strings.HasPrefix(lower, "*.") {
		value = "*." + strings.TrimPrefix(lower, "*.")
	}
	return strings.ToLower(value)
}

func isHostnameCandidate(value string) bool {
	value = normalizeScopeAssetValue(value)
	if value == "" || net.ParseIP(strings.Trim(value, "[]")) != nil {
		return false
	}
	if _, _, err := net.ParseCIDR(value); err == nil {
		return false
	}
	_, err := NormalizeAssetValue("domain", value)
	return err == nil
}
