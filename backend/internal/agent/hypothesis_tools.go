package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"

	"sophon/internal/database"
)

const (
	defaultMaxProjectHypotheses = 200
	maxHypothesesPerPlan        = 20
	maxFollowUpPerFinding       = 5
)

type hypothesisInput struct {
	AssetID          string `json:"asset_id"`
	Dimension        string `json:"dimension"`
	Technique        string `json:"technique"`
	Rationale        string `json:"rationale"`
	ExpectedEvidence string `json:"expected_evidence"`
	Priority         int    `json:"priority"`
	Required         *bool  `json:"required"`
}

var highRiskUploadEntryAliases = []struct {
	name    string
	markers []string
}{
	{name: "ScpSupRegHandler", markers: []string{"scpsupreghandler", "supregattach"}},
	{name: "FileUpload.ashx", markers: []string{"fileupload.ashx", "fileupload.processrequest"}},
	{name: "MOBFileUpload", markers: []string{"mobfileupload"}},
	{name: "KDFileProxyHandler", markers: []string{"kdfileproxyhandler", "*.kdfile"}},
	{name: "UEditor up.ashx", markers: []string{"ueditor", "up.ashx"}},
	{name: "MobileUpload", markers: []string{"mobileupload"}},
	{name: "SaveHttpRequestFile", markers: []string{"savehttprequestfile"}},
}

var uploadEvidenceLocatorPattern = regexp.MustCompile(
	`(?i)(?:IL_[0-9A-F]{4}|rva\s*=\s*0x[0-9A-F]+|\.(?:cs|ashx|aspx|config)\s*:\s*\d+|line\s+\d+)`,
)

func (s *Service) planHypothesesTool() tool.BaseTool {
	return &jsonTool{
		name: "project_plan_hypotheses",
		desc: "批量规划结构化安全测试假设。每个假设包含资产、测试维度、技术、依据、预期证据和优先级。",
		params: map[string]*schema.ParameterInfo{
			"hypotheses_json": stringParam(
				`JSON 数组，例如 [{"asset_id":"asset-1","dimension":"SQL注入","technique":"time-based","rationale":"数据库参数未参数化","expected_evidence":"可重复延时响应","priority":80}]`,
				true,
			),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				HypothesesJSON string `json:"hypotheses_json"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			var inputs []hypothesisInput
			if err := json.Unmarshal([]byte(strings.TrimSpace(request.HypothesesJSON)), &inputs); err != nil {
				return "", fmt.Errorf("hypotheses_json 解析失败: %w", err)
			}
			if len(inputs) == 0 || len(inputs) > maxHypothesesPerPlan {
				return "", fmt.Errorf("单次必须规划 1-%d 个假设", maxHypothesesPerPlan)
			}
			maxHypotheses := s.configSnapshot().AgentMaxHypotheses
			if maxHypotheses <= 0 {
				maxHypotheses = defaultMaxProjectHypotheses
			}
			total, err := s.db.CountProjectHypotheses(ctx, projectID)
			if err != nil {
				return "", fmt.Errorf("读取假设数量失败: %w", err)
			}
			if total >= maxHypotheses {
				return fmt.Sprintf(
					"活跃假设已达到上限 %d。不要再新增假设；请直接执行并用 project_record_fact 写回事实，"+
						"用 project_record_test 写回 tested_clean/blocked/suspicious/confirmed 测试结果。",
					maxHypotheses,
				), nil
			}
			skipped := 0
			if remaining := maxHypotheses - total; remaining < len(inputs) {
				skipped += len(inputs) - remaining
				inputs = inputs[:remaining]
			}
			planned := 0
			for _, input := range inputs {
				assetID, err := s.validateProjectAsset(ctx, projectID, userID, input.AssetID)
				if err != nil {
					return "", err
				}
				if assetID == "" {
					skipped++
					continue
				}
				dimension := truncateProjectText(input.Dimension, projectToolShortText)
				technique := truncateProjectText(input.Technique, projectToolShortText)
				if dimension == "" {
					skipped++
					continue
				}
				entries := highRiskUploadEntries(dimension + "\n" + technique + "\n" + input.Rationale)
				if len(entries) > 1 {
					return "", fmt.Errorf(
						"上传假设包含多个高风险入口（%s）。必须为每个入口单独建立假设，分别验证鉴权、文件名、路径、扩展名和落盘影响",
						strings.Join(entries, "、"),
					)
				}
				priority := input.Priority
				if priority <= 0 {
					priority = 60
				}
				if priority > 100 {
					priority = 100
				}
				required := true
				if input.Required != nil {
					required = *input.Required
				}
				if _, err := s.db.UpsertProjectTestResult(ctx, database.ProjectTestResult{
					ProjectID: projectID,
					AssetID:   assetID,
					Dimension: dimension,
					Technique: technique,
					Status:    "untested",
					Rationale: truncateProjectText(input.Rationale, projectToolLongText),
					Expected:  truncateProjectText(input.ExpectedEvidence, projectToolLongText),
					Priority:  priority,
					Required:  required,
					CreatedAt: time.Now().UTC(),
				}); err != nil {
					return "", fmt.Errorf("写入测试假设失败: %w", err)
				}
				planned++
			}
			message := fmt.Sprintf("测试假设已规划：写入 %d 个，跳过 %d 个。", planned, skipped)
			if total+planned >= maxHypotheses {
				message += fmt.Sprintf(
					" 活跃假设已达到上限 %d；后续不要继续新增假设，直接使用 project_record_fact 和 project_record_test 写回事实与测试结果。",
					maxHypotheses,
				)
			}
			return message, nil
		},
	}
}

func highRiskUploadEntries(value string) []string {
	lower := strings.ToLower(value)
	found := make([]string, 0, 2)
	for _, entry := range highRiskUploadEntryAliases {
		for _, marker := range entry.markers {
			if strings.Contains(lower, marker) {
				found = append(found, entry.name)
				break
			}
		}
	}
	return found
}

func (s *Service) listHypothesesTool() tool.BaseTool {
	return &jsonTool{
		name: "project_list_hypotheses",
		desc: "查看当前项目的待验证、运行中或可疑测试假设，按优先级排序。",
		params: map[string]*schema.ParameterInfo{
			"status": stringParam("可选：untested/running/suspicious"),
			"query":  stringParam("按维度、技术、依据或预期证据搜索"),
			"limit":  integerParam("返回条数，默认 20，最大 100"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				Status string  `json:"status"`
				Query  string  `json:"query"`
				Limit  flexInt `json:"limit"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, _, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			limit := int(request.Limit)
			if limit <= 0 || limit > 100 {
				limit = 20
			}
			query := strings.ToLower(strings.TrimSpace(request.Query))
			fetchLimit := limit
			if query != "" {
				fetchLimit = 100
			}
			items, err := s.db.ListProjectHypotheses(ctx, projectID, request.Status, fetchLimit)
			if err != nil {
				return "", fmt.Errorf("读取测试假设失败: %w", err)
			}
			if len(items) == 0 {
				return "当前项目没有待处理的测试假设。", nil
			}
			var builder strings.Builder
			matched := 0
			for _, item := range items {
				if query != "" && !projectTextMatches(query, item.Dimension, item.Technique, item.Rationale, item.Expected, item.AssetID, item.ID) {
					continue
				}
				if matched >= limit {
					break
				}
				matched++
				builder.WriteString(fmt.Sprintf(
					"- [%s] %s/%s（asset=%s，required=%t，priority=%d，attempts=%d，id=%s）\n",
					item.Status,
					item.Dimension,
					orDefaultProjectToolValue(item.Technique, "-"),
					item.AssetID,
					item.Required,
					item.Priority,
					item.Attempts,
					item.ID,
				))
				if item.Rationale != "" {
					builder.WriteString("  依据: " + truncateProjectText(item.Rationale, projectToolShortText) + "\n")
				}
				if item.Expected != "" {
					builder.WriteString("  预期证据: " + truncateProjectText(item.Expected, projectToolShortText) + "\n")
				}
			}
			return capProjectOutput(&builder), nil
		},
	}
}

func (s *Service) startHypothesisTool() tool.BaseTool {
	return &jsonTool{
		name: "project_start_hypothesis",
		desc: "Worker 领取并开始一个测试假设，状态更新为 running 并增加尝试次数。",
		params: map[string]*schema.ParameterInfo{
			"hypothesis_id": stringParam("测试假设 id", true),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				HypothesisID string `json:"hypothesis_id"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, _, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			item, err := s.db.StartProjectHypothesis(ctx, projectID, request.HypothesisID)
			if err != nil {
				return "", fmt.Errorf("开始测试假设失败: %w", err)
			}
			return fmt.Sprintf(
				"测试假设已开始：%s/%s（attempts=%d，id=%s）",
				item.Dimension,
				orDefaultProjectToolValue(item.Technique, "-"),
				item.Attempts,
				item.ID,
			), nil
		},
	}
}

func (s *Service) completeHypothesisTool() tool.BaseTool {
	return &jsonTool{
		name: "project_complete_hypothesis",
		desc: "完成一个测试假设并写入结论、证据、置信度及关联漏洞。",
		params: map[string]*schema.ParameterInfo{
			"hypothesis_id": stringParam("测试假设 id", true),
			"status":        stringParam("完成状态：tested_clean/blocked/suspicious/confirmed", true),
			"result":        stringParam("测试结论"),
			"evidence":      stringParam("证据摘要"),
			"evidence_refs": stringArrayParam("证据引用数组；" + evidenceReferenceFormatHint),
			"confidence":    integerParam("置信度 0-100"),
			"finding_id":    stringParam("confirmed 时关联漏洞 id"),
		},
		run: func(ctx context.Context, raw string) (string, error) {
			var request struct {
				HypothesisID string   `json:"hypothesis_id"`
				Status       string   `json:"status"`
				Result       string   `json:"result"`
				Evidence     string   `json:"evidence"`
				EvidenceRefs []string `json:"evidence_refs"`
				Confidence   flexInt  `json:"confidence"`
				FindingID    string   `json:"finding_id"`
			}
			if err := decodeToolArgs(raw, &request); err != nil {
				return "", err
			}
			_, userID, projectID, err := s.currentProject(ctx)
			if err != nil {
				return "", err
			}
			item, err := s.db.GetProjectTestResultByID(ctx, projectID, request.HypothesisID)
			if err != nil {
				return "", fmt.Errorf("测试假设不存在: %w", err)
			}
			status, ok := database.NormalizeProjectTestResultStatus(request.Status)
			if !ok || !database.IsProjectTestResultTerminal(status) {
				return "", fmt.Errorf("完成状态必须是 tested_clean/blocked/suspicious/confirmed")
			}
			result := truncateProjectText(request.Result, projectToolLongText)
			evidence := truncateProjectText(request.Evidence, projectToolLongText)
			evidenceRefs := append([]string(nil), request.EvidenceRefs...)
			switch status {
			case "tested_clean":
				if result == "" || (evidence == "" && len(evidenceRefs) == 0) {
					return "", fmt.Errorf("tested_clean 必须提供测试结论和证据")
				}
				if isUploadAuditHypothesis(*item) {
					if err := validateUploadCleanEvidence(result, evidence, evidenceRefs); err != nil {
						return "", err
					}
				}
			case "blocked":
				if result == "" {
					return "", fmt.Errorf("blocked 必须说明阻断原因")
				}
			case "suspicious":
				if result == "" {
					return "", fmt.Errorf("suspicious 必须提供测试结论")
				}
			case "confirmed":
				if strings.TrimSpace(request.FindingID) == "" {
					return "", fmt.Errorf("confirmed 必须关联 finding_id")
				}
				if evidence == "" && len(evidenceRefs) == 0 {
					return "", fmt.Errorf("confirmed 必须提供证据")
				}
				if _, err := s.validateProjectFindingID(ctx, projectID, userID, request.FindingID); err != nil {
					return "", err
				}
				if err := s.validateEvidenceReferences(ctx, projectID, userID, evidenceRefs, "high"); err != nil {
					return "", err
				}
			}
			item.Status = status
			item.Result = result
			item.Evidence = evidence
			item.EvidenceRefs = evidenceRefs
			item.Confidence = clampInt(int(request.Confidence), 0, 100)
			item.FindingID = strings.TrimSpace(request.FindingID)
			item.UpdatedAt = time.Now().UTC()
			saved, err := s.db.UpsertProjectTestResult(ctx, *item)
			if err != nil {
				return "", fmt.Errorf("完成测试假设失败: %w", err)
			}
			return fmt.Sprintf(
				"测试假设已完成：%s/%s，status=%s，confidence=%d（id=%s）",
				saved.Dimension,
				orDefaultProjectToolValue(saved.Technique, "-"),
				saved.Status,
				saved.Confidence,
				saved.ID,
			), nil
		},
	}
}

func isUploadAuditHypothesis(item database.ProjectTestResult) bool {
	dimension := strings.ToLower(strings.TrimSpace(item.Dimension))
	technique := strings.ToLower(strings.TrimSpace(item.Technique))
	if strings.Contains(dimension, "上传") || strings.Contains(dimension, "upload") {
		return true
	}
	if strings.Contains(technique, "文件上传") || strings.Contains(technique, "file upload") {
		return true
	}
	return len(highRiskUploadEntries(item.Dimension+"\n"+item.Technique)) > 0
}

func validateUploadCleanEvidence(
	result string,
	evidence string,
	refs []string,
) error {
	text := strings.ToLower(strings.TrimSpace(result + "\n" + evidence))
	checks := []struct {
		label   string
		markers []string
	}{
		{
			label:   "Sink（SaveAs/FileStream/File.Move/File.Copy/WriteAllBytes）",
			markers: []string{"saveas", "filestream", "file.move", "file.copy", "writeallbytes", "appendalltext"},
		},
		{
			label:   "Source（Request.Files/HttpPostedFile/FileName）",
			markers: []string{"request.files", "httppostedfile", "get_filename", "filename", "iformfile"},
		},
		{
			label:   "鉴权判断（鉴权/认证/Token/Session/未授权/匿名）",
			markers: []string{"鉴权", "认证", "token", "session", "未授权", "匿名", "登录"},
		},
		{
			label:   "路径与根目录约束（路径/目录/文件名/GetFullPath/Path.Combine/MapPath）",
			markers: []string{"路径", "根目录", "文件名", "目录", "getfullpath", "path.combine", "mappath"},
		},
		{
			label:   "扩展名或内容校验（扩展名/白名单/Content-Type/magic）",
			markers: []string{"扩展名", "白名单", "content-type", "magic", "后缀"},
		},
	}
	missing := make([]string, 0, len(checks)+2)
	for _, check := range checks {
		found := false
		for _, marker := range check.markers {
			if strings.Contains(text, marker) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, check.label)
		}
	}
	if !uploadEvidenceLocatorPattern.MatchString(text) {
		missing = append(missing, "方法级定位（IL_xxxx、rva=0x...、文件:行号）")
	}
	hasStrongRef := false
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if strings.HasPrefix(ref, "artifact:") || strings.HasPrefix(ref, "tool:") {
			hasStrongRef = true
			break
		}
	}
	if !hasStrongRef {
		missing = append(missing, "artifact/tool 证据引用")
	}
	authRisk := containsAnyMarker(text,
		"未发现鉴权", "未发现认证", "未发现 token", "未发现 session",
		"无鉴权", "无认证", "无 token", "没有鉴权", "缺少鉴权", "未授权", "匿名访问", "auth_check_found=false",
	)
	fileWrite := containsAnyMarker(text, "saveas", "filestream", "file.move", "file.copy", "writeallbytes")
	clientName := containsAnyMarker(text, "request.files.filename", "httppostedfile.filename", "原始文件名", "get_filename")
	if authRisk && fileWrite && clientName {
		missing = append(missing, "证据已显示未授权文件写入，应改为 suspicious/confirmed，不能 tested_clean")
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"上传类 tested_clean 证据不足，缺少：%s。请在未完成方法级取证时使用 suspicious 或 blocked",
			strings.Join(missing, "、"),
		)
	}
	return nil
}

func containsAnyMarker(text string, markers ...string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// RequalifyLegacyUploadCleanHypotheses 对历史上传类 tested_clean 重新执行证据门禁。
func (s *Service) RequalifyLegacyUploadCleanHypotheses(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	items, err := s.db.ListProjectTestResultsByStatus(ctx, "tested_clean", 10000)
	if err != nil {
		return 0, err
	}
	requalified := 0
	for index := range items {
		item := items[index]
		if !isUploadAuditHypothesis(item) {
			continue
		}
		if err := validateUploadCleanEvidence(item.Result, item.Evidence, item.EvidenceRefs); err == nil {
			continue
		} else {
			notice := "[证据门禁复核] " + err.Error()
			item.Status = "suspicious"
			item.Result = truncateProjectText(strings.TrimSpace(item.Result+"\n\n"+notice), projectToolLongText)
			item.Evidence = truncateProjectText(strings.TrimSpace(item.Evidence+"\n\n"+notice), projectToolLongText)
			if item.Confidence > 60 {
				item.Confidence = 60
			}
			item.UpdatedAt = time.Now().UTC()
			if _, err := s.db.UpsertProjectTestResult(ctx, item); err != nil {
				return requalified, err
			}
			requalified++
		}
	}
	return requalified, nil
}

func (s *Service) seedFollowUpHypotheses(
	ctx context.Context,
	projectID string,
	finding database.Vulnerability,
) {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(finding.ID) == "" {
		return
	}
	maxHypotheses := s.configSnapshot().AgentMaxHypotheses
	if maxHypotheses <= 0 {
		maxHypotheses = defaultMaxProjectHypotheses
	}
	total, err := s.db.CountProjectHypotheses(ctx, projectID)
	if err != nil || total >= maxHypotheses {
		return
	}
	remaining := maxHypotheses - total
	items := buildFollowUpHypotheses(finding)
	if len(items) > remaining {
		items = items[:remaining]
	}
	for index := range items {
		items[index].ProjectID = projectID
		_, _ = s.db.UpsertProjectTestResult(ctx, items[index])
	}
}

func buildFollowUpHypotheses(finding database.Vulnerability) []database.ProjectTestResult {
	now := time.Now().UTC()
	assetID := strings.TrimSpace(finding.AssetID)
	if assetID == "" {
		return nil
	}
	vulnType := strings.ToLower(strings.TrimSpace(finding.VulnerabilityType + " " + finding.Title))
	type candidate struct {
		dimension string
		technique string
		reason    string
		expected  string
		priority  int
	}
	candidates := make([]candidate, 0, maxFollowUpPerFinding)
	switch {
	case strings.Contains(vulnType, "sql"):
		candidates = []candidate{
			{"SQL注入", "time-based", "验证时间盲注，补充 boolean/error 之外的可利用路径", "可重复的响应延时差异", 88},
			{"SQL注入", "stacked-query", "确认数据库驱动是否允许多语句执行", "第二条 SQL 语句产生可观测副作用", 78},
			{"SQL注入", "out-of-band", "验证带外读取或 DNS/HTTP 回连能力", "目标发起可识别的带外请求", 74},
			{"参数变体", "adjacent-parameter", "检查同一接口的其他参数是否存在同类缺陷", "其他参数出现 SQL 差异回显", 82},
			{"权限上下文", "auth-context", "比较匿名、低权限和管理员身份的注入表现", "不同权限下出现稳定差异", 76},
		}
	case strings.Contains(vulnType, "xss"):
		candidates = []candidate{
			{"XSS", "stored", "确认输入是否在其他页面持久化执行", "二次访问触发脚本执行", 88},
			{"XSS", "dom", "检查前端 JavaScript 是否消费危险参数", "DOM 节点执行可控内容", 82},
			{"XSS", "encoding-bypass", "验证 HTML、URL、JS 多层编码绕过", "绕过现有过滤并执行脚本", 80},
			{"权限上下文", "auth-context", "检查不同角色和登录状态下的输出差异", "不同权限下出现稳定 XSS 差异", 74},
		}
	case strings.Contains(vulnType, "ssrf"):
		candidates = []candidate{
			{"SSRF", "dns", "验证 DNS 回连能力", "目标产生可识别的 DNS 查询", 88},
			{"SSRF", "file", "检查本地文件读取协议", "返回本地文件内容或错误特征", 84},
			{"SSRF", "internal-network", "探测可达的内网服务和云元数据", "内网服务或元数据端点返回响应", 90},
			{"编码绕过", "encoding-bypass", "测试协议和地址编码绕过", "绕过 URL 校验并触发请求", 80},
		}
	default:
		candidates = []candidate{
			{"参数变体", "adjacent-parameter", "检查相邻参数和同接口其他入口", "发现同类或更强缺陷", 75},
			{"权限上下文", "auth-context", "验证匿名、普通用户和管理员身份差异", "权限边界被绕过", 78},
			{"编码绕过", "encoding-bypass", "测试过滤器与 WAF 绕过变体", "过滤规则被稳定绕过", 74},
			{"链式利用", "exploit-chain", "评估与现有凭据、上传或 SSRF 的联动", "形成可验证的攻击链", 82},
		}
	}
	items := make([]database.ProjectTestResult, 0, len(candidates))
	for _, item := range candidates {
		if strings.EqualFold(strings.TrimSpace(item.technique), strings.TrimSpace(finding.TestTechnique)) {
			continue
		}
		items = append(items, database.ProjectTestResult{
			ProjectID: finding.ProjectID,
			AssetID:   assetID,
			Dimension: item.dimension,
			Technique: item.technique,
			Status:    "untested",
			Rationale: item.reason,
			Expected:  item.expected,
			Priority:  item.priority,
			ParentID:  finding.ID,
			Required:  false,
			CreatedAt: now,
		})
		if len(items) >= maxFollowUpPerFinding {
			break
		}
	}
	return items
}

func clampInt(value, minimum, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}
