package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"sophon/internal/database"
	"sophon/internal/intel"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
)

const (
	intelSearchToolName        = "intel_search"
	intelSearchTimeout         = 20 * time.Second
	intelSearchDefaultPageSize = 20
	intelSearchMaxPageSize     = 100
	intelSearchDisplayLimit    = 25
	intelFOFAMinInterval       = 3 * time.Second
	intelHunterMinInterval     = 5 * time.Second
	intelFailureThreshold      = 5
	intelFailureCooldown       = 60 * time.Second
)

type intelProviderRuntime struct {
	sem           chan struct{}
	mu            sync.Mutex
	minInterval   time.Duration
	lastRequest   time.Time
	failures      int
	cooldownUntil time.Time
}

type intelSearchRuntime struct {
	fixed  *intel.Client
	fofa   *intelProviderRuntime
	hunter *intelProviderRuntime
}

type IntelSearchRequest struct {
	Provider  string
	Query     string
	Page      int
	PageSize  int
	StartTime string
}

type IntelCapabilities struct {
	Enabled          bool
	FOFAConfigured   bool
	HunterConfigured bool
}

type IntelAssetImportSummary struct {
	Created  int      `json:"created"`
	Existing int      `json:"existing"`
	Skipped  int      `json:"skippedInvalid"`
	Failed   int      `json:"failed"`
	AssetIDs []string `json:"assetIds"`
}

func newIntelSearchRuntime() *intelSearchRuntime {
	return &intelSearchRuntime{
		fofa: &intelProviderRuntime{
			sem:         make(chan struct{}, 1),
			minInterval: intelFOFAMinInterval,
		},
		hunter: &intelProviderRuntime{
			sem:         make(chan struct{}, 1),
			minInterval: intelHunterMinInterval,
		},
	}
}

func newIntelSearchTool(service *Service) tool.BaseTool {
	return newIntelSearchToolWithRuntime(service, service.ensureIntelRuntime())
}

func (s *Service) ensureIntelRuntime() *intelSearchRuntime {
	if s == nil {
		return newIntelSearchRuntime()
	}
	s.intelRuntimeMu.Lock()
	defer s.intelRuntimeMu.Unlock()
	if s.intelRuntime == nil {
		s.intelRuntime = newIntelSearchRuntime()
	}
	return s.intelRuntime
}

func newIntelSearchToolWithRuntime(service *Service, runtime *intelSearchRuntime) tool.BaseTool {
	if runtime == nil {
		runtime = service.ensureIntelRuntime()
	}
	return &jsonTool{
		name: intelSearchToolName,
		desc: "通过 FOFA 与 Hunter 查询授权项目的外部资产情报。只有用户明确要求保存到资产管理时，才传 save_assets=true。",
		params: map[string]*schema.ParameterInfo{
			"query":       stringParam("FOFA/Hunter 测绘语法，例如 domain=\"example.com\" 或 ip=\"10.0.0.1\"", true),
			"provider":    stringParam("查询来源：all、fofa、hunter，默认 all"),
			"page":        integerParam("页码，默认 1"),
			"page_size":   integerParam("每页数量，默认 20，最大 100"),
			"start_time":  stringParam("Hunter 起始日期，格式 YYYY-MM-DD，可选"),
			"save_assets": booleanParam("是否将当前页结果写入当前会话绑定项目的资产管理，默认 false"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Query      string  `json:"query"`
				Provider   string  `json:"provider"`
				Page       flexInt `json:"page"`
				PageSize   flexInt `json:"page_size"`
				StartTime  string  `json:"start_time"`
				SaveAssets bool    `json:"save_assets"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			input, err := normalizeIntelSearchRequest(IntelSearchRequest{
				Provider:  request.Provider,
				Query:     request.Query,
				Page:      int(request.Page),
				PageSize:  int(request.PageSize),
				StartTime: request.StartTime,
			})
			if err != nil {
				return "", err
			}
			results, providerErrors, err := service.searchIntelWithRuntime(ctx, input, runtime)
			if err != nil {
				return "", err
			}
			if len(results) == 0 && len(providerErrors) > 0 {
				return "", fmt.Errorf("情报查询失败：%s", strings.Join(providerErrors, "；"))
			}

			var importSummary *IntelAssetImportSummary
			if request.SaveAssets {
				_, userID, projectID, projectErr := service.currentProject(ctx)
				if projectErr != nil {
					providerErrors = append(providerErrors, "未保存资产："+projectErr.Error())
				} else {
					summary, importErr := service.ImportIntelAssets(ctx, userID, projectID, results)
					importSummary = &summary
					if importErr != nil {
						providerErrors = append(providerErrors, "资产导入存在错误："+importErr.Error())
					}
				}
			}
			return formatIntelSearchOutput(
				input.Query,
				input.Provider,
				results,
				providerErrors,
				importSummary,
			), nil
		},
	}
}

func normalizeIntelSearchRequest(request IntelSearchRequest) (IntelSearchRequest, error) {
	request.Query = strings.TrimSpace(request.Query)
	if request.Query == "" || len([]rune(request.Query)) > 1000 {
		return request, fmt.Errorf("query 不能为空且不能超过 1000 个字符")
	}
	for _, char := range request.Query {
		if unicode.IsControl(char) {
			return request, fmt.Errorf("query 不能包含控制字符")
		}
	}
	request.Provider = strings.ToLower(strings.TrimSpace(request.Provider))
	if request.Provider == "" {
		request.Provider = "all"
	}
	if request.Provider != "all" && request.Provider != "fofa" && request.Provider != "hunter" {
		return request, fmt.Errorf("provider 只能是 all、fofa 或 hunter")
	}
	if request.Page <= 0 {
		request.Page = 1
	}
	if request.Page > 100 {
		return request, fmt.Errorf("page 不能超过 100")
	}
	if request.PageSize <= 0 {
		request.PageSize = intelSearchDefaultPageSize
	}
	if request.PageSize > intelSearchMaxPageSize {
		return request, fmt.Errorf("page_size 不能超过 %d", intelSearchMaxPageSize)
	}
	startTime, err := normalizeIntelStartTime(request.StartTime)
	if err != nil {
		return request, err
	}
	request.StartTime = startTime
	return request, nil
}

func (s *Service) SearchIntel(
	ctx context.Context,
	request IntelSearchRequest,
) ([]intel.Result, []string, error) {
	normalized, err := normalizeIntelSearchRequest(request)
	if err != nil {
		return nil, nil, err
	}
	return s.searchIntelWithRuntime(ctx, normalized, s.ensureIntelRuntime())
}

func (s *Service) searchIntelWithRuntime(
	ctx context.Context,
	request IntelSearchRequest,
	runtime *intelSearchRuntime,
) ([]intel.Result, []string, error) {
	if s == nil || s.db == nil {
		return nil, nil, fmt.Errorf("情报设置不可用")
	}
	savedSettings, err := s.db.GetIntelSettings(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("读取情报设置失败: %w", err)
	}
	if !savedSettings.Enabled {
		return nil, nil, fmt.Errorf("情报能力未启用，请先在设置-信息设置中配置")
	}
	settings := intel.Settings{
		FOFAEmail: savedSettings.FOFAEmail,
		FOFAKey:   savedSettings.FOFAKey,
		HunterKey: savedSettings.HunterKey,
	}
	results, providerErrors := runtime.search(
		ctx,
		s,
		settings,
		request.Provider,
		request.Query,
		intel.SearchOptions{
			Page:      request.Page,
			PageSize:  request.PageSize,
			StartTime: request.StartTime,
		},
	)
	return results, providerErrors, nil
}

func (s *Service) IntelCapabilities(ctx context.Context) (IntelCapabilities, error) {
	if s == nil || s.db == nil {
		return IntelCapabilities{}, fmt.Errorf("情报设置不可用")
	}
	settings, err := s.db.GetIntelSettings(ctx)
	if err != nil {
		return IntelCapabilities{}, err
	}
	return IntelCapabilities{
		Enabled:          settings.Enabled,
		FOFAConfigured:   settings.FOFAEmail != "" && settings.FOFAKey != "",
		HunterConfigured: settings.HunterKey != "",
	}, nil
}

func (runtime *intelSearchRuntime) search(
	ctx context.Context,
	service *Service,
	settings intel.Settings,
	provider string,
	query string,
	options intel.SearchOptions,
) ([]intel.Result, []string) {
	if runtime == nil {
		return nil, []string{"情报查询运行时不可用"}
	}
	searchCtx, cancel := context.WithTimeout(ctx, intelSearchTimeout)
	defer cancel()
	client := runtime.fixed
	if client == nil {
		httpClient, err := intel.NewHTTPClient(service.configSnapshot().Proxy, intelSearchTimeout)
		if err != nil {
			return nil, []string{"创建情报 HTTP 客户端失败"}
		}
		value := intel.NewClient(httpClient)
		client = &value
	}

	type outcome struct {
		provider string
		results  []intel.Result
		err      error
	}
	selected := make([]string, 0, 2)
	if provider == "all" || provider == "fofa" {
		selected = append(selected, "fofa")
	}
	if provider == "all" || provider == "hunter" {
		selected = append(selected, "hunter")
	}
	channel := make(chan outcome, len(selected))
	for _, name := range selected {
		name := name
		go func() {
			var results []intel.Result
			var err error
			switch name {
			case "fofa":
				err = runtime.fofa.run(searchCtx, func() error {
					results, err = client.SearchFOFA(searchCtx, settings, query, options)
					return err
				})
			case "hunter":
				err = runtime.hunter.run(searchCtx, func() error {
					results, err = client.SearchHunter(searchCtx, settings, query, options)
					return err
				})
			}
			channel <- outcome{provider: name, results: results, err: err}
		}()
	}

	all := make([]intel.Result, 0, options.PageSize*len(selected))
	providerErrors := make([]string, 0, len(selected))
	for range selected {
		item := <-channel
		all = append(all, item.results...)
		if item.err != nil {
			providerErrors = append(providerErrors, strings.ToUpper(item.provider)+": "+item.err.Error())
		}
	}
	return intel.Deduplicate(all, intelSearchMaxPageSize), providerErrors
}

func (runtime *intelProviderRuntime) run(ctx context.Context, action func() error) error {
	if runtime == nil {
		return fmt.Errorf("Provider 运行时不可用")
	}
	if runtime.sem == nil {
		runtime.sem = make(chan struct{}, 1)
	}
	select {
	case runtime.sem <- struct{}{}:
		defer func() { <-runtime.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}

	runtime.mu.Lock()
	if wait := time.Until(runtime.cooldownUntil); wait > 0 {
		runtime.mu.Unlock()
		return fmt.Errorf("连续失败后暂停查询，请 %s 后重试", wait.Round(time.Second))
	}
	wait := runtime.minInterval - time.Since(runtime.lastRequest)
	runtime.mu.Unlock()
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	runtime.mu.Lock()
	runtime.lastRequest = time.Now()
	runtime.mu.Unlock()

	err := action()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if err == nil {
		runtime.failures = 0
		runtime.cooldownUntil = time.Time{}
		return nil
	}
	runtime.failures++
	if runtime.failures >= intelFailureThreshold {
		runtime.cooldownUntil = time.Now().Add(intelFailureCooldown)
		runtime.failures = 0
	}
	return err
}

func normalizeIntelStartTime(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return "", fmt.Errorf("start_time 必须是 YYYY-MM-DD")
	}
	today := time.Now().UTC().Truncate(24 * time.Hour)
	if parsed.After(today) {
		return "", fmt.Errorf("start_time 不能晚于今天")
	}
	return parsed.Format("2006-01-02"), nil
}

func (s *Service) ImportIntelAssets(
	ctx context.Context,
	userID string,
	projectID string,
	results []intel.Result,
) (IntelAssetImportSummary, error) {
	summary := IntelAssetImportSummary{}
	existing, err := s.db.ListProjectAssets(ctx, projectID, userID)
	if err != nil {
		return summary, err
	}
	seen := make(map[string]bool, len(existing))
	for _, asset := range existing {
		seen[assetKey(asset.Kind, asset.Value)] = true
	}
	now := time.Now().UTC()
	var failures []string
	for _, result := range results {
		kind, value, err := intelAssetTarget(result)
		if err != nil {
			summary.Skipped++
			continue
		}
		key := assetKey(kind, value)
		if seen[key] {
			summary.Existing++
			continue
		}
		name := intelAssetName(result, value)
		item := database.Asset{
			ID:          randomID(),
			ProjectID:   projectID,
			OwnerUserID: userID,
			Name:        name,
			Kind:        kind,
			Value:       value,
			Status:      "unknown",
			Source:      intelAssetSource(result),
			Criticality: "info",
			RiskScore:   0,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.db.CreateAsset(ctx, item); err != nil {
			if errors.Is(err, database.ErrAssetDuplicate) {
				summary.Existing++
				seen[key] = true
				continue
			}
			summary.Failed++
			failures = append(failures, value)
			continue
		}
		seen[key] = true
		summary.Created++
		summary.AssetIDs = append(summary.AssetIDs, item.ID)
	}
	if summary.Created > 0 {
		s.syncProjectGraph(ctx, projectID, userID)
	}
	if len(failures) > 0 {
		return summary, fmt.Errorf("%d 个资产写入失败", len(failures))
	}
	return summary, nil
}

func intelAssetSource(result intel.Result) string {
	hasFOFA := false
	hasHunter := false
	for _, source := range result.Sources {
		switch strings.ToLower(strings.TrimSpace(source)) {
		case database.AssetSourceFOFA:
			hasFOFA = true
		case database.AssetSourceHunter:
			hasHunter = true
		}
	}
	switch {
	case hasFOFA && hasHunter:
		return database.AssetSourceFOFAHunter
	case hasFOFA:
		return database.AssetSourceFOFA
	case hasHunter:
		return database.AssetSourceHunter
	default:
		return database.AssetSourceOther
	}
}

func intelAssetTarget(result intel.Result) (string, string, error) {
	candidates := make([]struct {
		kind  string
		value string
	}, 0, 6)
	if value := strings.TrimSpace(result.URL); value != "" {
		candidates = append(candidates, struct {
			kind  string
			value string
		}{kind: "url", value: value})
	}
	if domain := strings.TrimSpace(result.Domain); domain != "" {
		value := domain
		if result.Port > 0 {
			value = net.JoinHostPort(domain, strconv.Itoa(result.Port))
		}
		candidates = append(candidates,
			struct {
				kind  string
				value string
			}{kind: "domain", value: value},
			struct {
				kind  string
				value string
			}{kind: "host", value: value},
		)
	}
	if ip := strings.TrimSpace(result.IP); ip != "" {
		if result.Port > 0 {
			candidates = append(candidates, struct {
				kind  string
				value string
			}{kind: "host", value: net.JoinHostPort(ip, strconv.Itoa(result.Port))})
		}
		candidates = append(candidates, struct {
			kind  string
			value string
		}{kind: "ip", value: ip})
	}
	for _, candidate := range candidates {
		value, err := database.NormalizeAssetValue(candidate.kind, candidate.value)
		if err == nil {
			return candidate.kind, value, nil
		}
	}
	return "", "", fmt.Errorf("结果无法映射为资产")
}

func intelAssetName(result intel.Result, fallback string) string {
	name := strings.TrimSpace(result.Title)
	if name == "" {
		name = fallback
	}
	name = strings.Join(strings.Fields(name), " ")
	runes := []rune(name)
	if len(runes) > 120 {
		name = string(runes[:120])
	}
	if name == "" {
		return fallback
	}
	return name
}

func formatIntelSearchOutput(
	query string,
	provider string,
	results []intel.Result,
	providerErrors []string,
	importSummary *IntelAssetImportSummary,
) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf(
		"情报查询：provider=%s，query=%s，去重后结果=%d\n",
		provider,
		query,
		len(results),
	))
	for index, result := range results {
		if index >= intelSearchDisplayLimit {
			builder.WriteString(fmt.Sprintf("- 另有 %d 条结果未展开\n", len(results)-intelSearchDisplayLimit))
			break
		}
		target := firstNonEmptyString(result.URL, result.Domain, result.IP)
		if target != "" && result.Port > 0 && !strings.Contains(target, "://") {
			if _, _, err := net.SplitHostPort(target); err != nil {
				target = net.JoinHostPort(strings.Trim(target, "[]"), strconv.Itoa(result.Port))
			}
		}
		details := make([]string, 0, 5)
		if result.Title != "" {
			details = append(details, "title="+truncateProjectText(result.Title, 120))
		}
		if result.Org != "" {
			details = append(details, "org="+truncateProjectText(result.Org, 80))
		}
		if len(result.Components) > 0 {
			details = append(details, "components="+truncateProjectText(strings.Join(result.Components, ", "), 160))
		}
		builder.WriteString(fmt.Sprintf(
			"- [%s] %s%s\n",
			strings.Join(result.Sources, ","),
			firstNonEmptyString(target, "无可用目标"),
			formatIntelDetails(details),
		))
	}
	for _, providerErr := range providerErrors {
		builder.WriteString("- 来源错误：" + providerErr + "\n")
	}
	if importSummary != nil {
		builder.WriteString(fmt.Sprintf(
			"资产导入：created=%d existing=%d skipped_invalid=%d failed=%d",
			importSummary.Created,
			importSummary.Existing,
			importSummary.Skipped,
			importSummary.Failed,
		))
		if len(importSummary.AssetIDs) > 0 {
			builder.WriteString(" ids=" + strings.Join(importSummary.AssetIDs, ","))
		}
		builder.WriteString("\n")
	}
	return capProjectOutput(&builder)
}

func formatIntelDetails(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return " " + strings.Join(values, " ")
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

var _ tool.BaseTool = (*jsonTool)(nil)
