package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	htmlstd "html"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"sophon/internal/database"
	"sophon/internal/middleware"
	"sophon/internal/procwrap"

	"github.com/gin-gonic/gin"
)

const (
	reportMarkdownContentType = "text/markdown; charset=utf-8"
	reportCSVContentType      = "text/csv; charset=utf-8"
	reportPDFContentType      = "application/pdf"
	reportZipContentType      = "application/zip"
	reportAuthorizationNotice = "本报告仅用于已获得合法授权的安全测试环境。报告中的测试方法、结果和证据不得用于任何未授权系统；因超出授权范围使用本报告而产生的风险与责任由使用者自行承担。"
)

type projectReportPreviewResponse struct {
	ProjectName            string `json:"projectName"`
	Markdown               string `json:"markdown"`
	MarkdownName           string `json:"markdownName"`
	AssetsCSVName          string `json:"assetsCsvName"`
	VulnerabilitiesCSVName string `json:"vulnerabilitiesCsvName"`
}

type projectReportExportRequest struct {
	Format   string `json:"format"`
	Markdown string `json:"markdown"`
}

type projectReportManifest struct {
	ProjectID           string    `json:"projectId"`
	ProjectName         string    `json:"projectName"`
	GeneratedAt         time.Time `json:"generatedAt"`
	Assets              int       `json:"assets"`
	Vulnerabilities     int       `json:"vulnerabilities"`
	MarkdownFile        string    `json:"markdownFile"`
	PDFFile             string    `json:"pdfFile"`
	AssetsFile          string    `json:"assetsFile"`
	VulnerabilitiesFile string    `json:"vulnerabilitiesFile"`
	Classification      string    `json:"classification"`
	Renderer            string    `json:"renderer"`
}

func (h *ProjectHandler) ReportPreview(c *gin.Context) {
	project, assets, findings, coverage, ok := h.projectReportData(c)
	if !ok {
		return
	}
	markdown := buildProjectReportMarkdown(project, assets, findings, coverage, time.Now().UTC())
	base := sanitizeProjectExportName(project.Name) + "-风险评估报告"
	c.JSON(http.StatusOK, projectReportPreviewResponse{
		ProjectName:            project.Name,
		Markdown:               markdown,
		MarkdownName:           base + ".md",
		AssetsCSVName:          "assets.csv",
		VulnerabilitiesCSVName: "vulnerabilities.csv",
	})
}

func (h *ProjectHandler) ExportReport(c *gin.Context) {
	project, assets, findings, coverage, ok := h.projectReportData(c)
	if !ok {
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8<<20)
	var request projectReportExportRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		badRequest(c, "invalid_report_export", "报告导出请求格式错误")
		return
	}
	format := strings.ToLower(strings.TrimSpace(request.Format))
	if format == "" {
		format = "package"
	}
	markdown := strings.TrimSpace(request.Markdown)
	if markdown == "" {
		markdown = buildProjectReportMarkdown(project, assets, findings, coverage, time.Now().UTC())
	}
	if err := h.writeProjectReportExport(c, project, assets, findings, format, markdown); err != nil {
		internalError(c, "project_report_export_failed", err.Error())
		return
	}
	user := middleware.UserFromContext(c)
	_ = h.db.AddAuditLog(c.Request.Context(), database.AuditLog{
		UserID:       user.ID,
		Username:     user.Username,
		Action:       "project.report_export",
		ResourceType: "project",
		ResourceID:   project.ID,
		Result:       "success",
		Detail:       fmt.Sprintf("format=%s assets=%d vulnerabilities=%d", format, len(assets), len(findings)),
	})
}

func (h *ProjectHandler) projectReportData(
	c *gin.Context,
) (*database.Project, []database.Asset, []database.Vulnerability, *database.ProjectCoverage, bool) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return nil, nil, nil, nil, false
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return nil, nil, nil, nil, false
	}
	assets, err := h.db.ListProjectAssets(c.Request.Context(), project.ID, user.ID)
	if err != nil {
		internalError(c, "project_report_failed", "读取项目资产失败")
		return nil, nil, nil, nil, false
	}
	findings, err := h.exportVulnerabilities(c.Request.Context(), project.ID, user.ID)
	if err != nil {
		internalError(c, "project_report_failed", "读取项目漏洞失败")
		return nil, nil, nil, nil, false
	}
	findings = confirmedReportFindings(findings)
	coverage, err := h.db.ProjectCoverage(c.Request.Context(), project.ID, user.ID)
	if err != nil {
		internalError(c, "project_report_failed", "读取项目覆盖数据失败")
		return nil, nil, nil, nil, false
	}
	return project, assets, findings, coverage, true
}

func confirmedReportFindings(findings []database.Vulnerability) []database.Vulnerability {
	result := make([]database.Vulnerability, 0, len(findings))
	for _, item := range findings {
		if strings.EqualFold(strings.TrimSpace(item.Status), "confirmed") {
			result = append(result, item)
		}
	}
	return result
}

func (h *ProjectHandler) writeProjectReportExport(
	c *gin.Context,
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
	format string,
	markdown string,
) error {
	generatedAt := time.Now().UTC()
	base := sanitizeProjectExportName(project.Name) + "-风险评估报告"
	switch format {
	case "md", "markdown":
		setProjectExportHeaders(c, base+".md", "report.md")
		c.Data(http.StatusOK, reportMarkdownContentType, []byte(markdown))
		return nil
	case "csv":
		data, err := buildProjectAssetsCSV(project, assets, findings)
		if err != nil {
			return fmt.Errorf("生成资产清单失败: %w", err)
		}
		setProjectExportHeaders(c, base+"-assets.csv", "assets.csv")
		c.Data(http.StatusOK, reportCSVContentType, data)
		return nil
	case "vulnerabilities", "findings":
		data, err := buildProjectVulnerabilitiesCSV(findings)
		if err != nil {
			return fmt.Errorf("生成漏洞清单失败: %w", err)
		}
		setProjectExportHeaders(c, base+"-vulnerabilities.csv", "vulnerabilities.csv")
		c.Data(http.StatusOK, reportCSVContentType, data)
		return nil
	case "pdf":
		pdfMarkdown := h.inlineVulnerabilityReportImages(c.Request.Context(), c, markdown)
		data, err := renderProjectReportPDF(c.Request.Context(), project, pdfMarkdown, findings, generatedAt)
		if err != nil {
			return fmt.Errorf("生成 PDF 报告失败: %w", err)
		}
		setProjectExportHeaders(c, base+".pdf", "report.pdf")
		c.Data(http.StatusOK, reportPDFContentType, data)
		return nil
	case "package", "zip":
		pdfMarkdown := h.inlineVulnerabilityReportImages(c.Request.Context(), c, markdown)
		data, err := buildProjectReportPackage(project, assets, findings, markdown, pdfMarkdown, generatedAt)
		if err != nil {
			return fmt.Errorf("生成报告包失败: %w", err)
		}
		setProjectExportHeaders(c, base+"-report.zip", "report.zip")
		c.Data(http.StatusOK, reportZipContentType, data)
		return nil
	default:
		return fmt.Errorf("不支持的报告格式 %q", format)
	}
}

func buildProjectReportMarkdown(
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
	coverage *database.ProjectCoverage,
	generatedAt time.Time,
) string {
	if project == nil {
		return ""
	}
	title := project.Name + "风险评估报告"
	sortedFindings := append([]database.Vulnerability(nil), findings...)
	sort.SliceStable(sortedFindings, func(i, j int) bool {
		left, right := docxSeverityRank(sortedFindings[i].Severity), docxSeverityRank(sortedFindings[j].Severity)
		if left != right {
			return left > right
		}
		return sortedFindings[i].UpdatedAt.After(sortedFindings[j].UpdatedAt)
	})
	severityCounts := reportSeverityCounts(findings)
	statusCounts := map[string]int{}
	for _, item := range findings {
		statusCounts[strings.ToLower(strings.TrimSpace(item.Status))]++
	}

	var builder strings.Builder
	builder.WriteString("---\n")
	builder.WriteString("title: " + strconv.Quote(title) + "\n")
	builder.WriteString("project: " + strconv.Quote(project.Name) + "\n")
	builder.WriteString("project_id: " + strconv.Quote(project.ID) + "\n")
	builder.WriteString("report_no: " + strconv.Quote(projectReportNumber(project.ID, generatedAt)) + "\n")
	builder.WriteString("generated_at: " + strconv.Quote(generatedAt.Format(time.RFC3339)) + "\n")
	builder.WriteString("classification: \"内部\"\n")
	builder.WriteString("---\n\n")
	builder.WriteString("# " + escapeMarkdownLine(title) + "\n\n")
	scopeSummary := reportScopeSummary(project.Scope)

	builder.WriteString("## 1. 决策摘要\n\n")
	builder.WriteString("### 1.1 总体结论\n\n")
	builder.WriteString(fmt.Sprintf(
		"当前项目已记录漏洞中的最高风险等级为“%s”。该结论仅代表当前平台记录和证据范围，不等同于未测试资产或未验证区域的安全结论。\n\n",
		reportOverallSeverity(findings),
	))
	builder.WriteString("### 1.2 优先处置\n\n")
	criticalIndex := 0
	for _, item := range sortedFindings {
		if normalizeDocxSeverity(item.Severity) != "critical" {
			continue
		}
		criticalIndex++
		builder.WriteString(fmt.Sprintf(
			"%d. **%s** %s | 目标：%s | 漏洞编号：`%s`\n",
			criticalIndex,
			docxSeverityLabel(item.Severity),
			escapeMarkdownLine(docxValue(item.Title, item.VulnerabilityType)),
			escapeMarkdownLine(docxValue(item.Target, "未记录")),
			markdownCell(item.ID),
		))
	}
	if criticalIndex == 0 {
		builder.WriteString("当前项目未记录严重漏洞，高危及以下问题见第 3 章。\n\n")
	} else {
		builder.WriteString("\n")
	}
	builder.WriteString("### 1.3 处置建议\n\n")
	builder.WriteString("- 严重问题建议优先在 24 小时内完成处置，高危问题建议在 7 天内完成修复并安排复测。\n")
	builder.WriteString("- 未测试、阻塞和证据不足区域不能判定为安全，应在下一轮评估中继续验证。\n")
	builder.WriteString("- 完整漏洞等级、状态和证据位置见第 3 章及第 4 章。\n\n")

	builder.WriteString("## 目录\n\n")
	for _, entry := range []string{
		"1. 决策摘要",
		"2. 报告信息与评估范围",
		"3. 漏洞统计",
		"4. 漏洞详情",
		"5. 修复计划与复测要求",
		"6. 附录与数据说明",
	} {
		builder.WriteString("- [" + entry + "](#" + markdownHeadingID(entry) + ")\n")
	}
	builder.WriteString("\n")

	builder.WriteString("## 2. 报告信息与评估范围\n\n")
	builder.WriteString("### 2.1 资产覆盖\n\n")
	if coverage == nil {
		builder.WriteString("覆盖数据不可用，本轮报告不能给出资产测试覆盖结论。\n\n")
	} else {
		builder.WriteString("| 指标 | 数量 | 说明 |\n|---|---:|---|\n")
		builder.WriteString(fmt.Sprintf("| 授权范围条目 | %d | 按项目授权范围字段统计 |\n", reportScopeEntryCount(project.Scope)))
		builder.WriteString(fmt.Sprintf("| 平台资产记录 | %d | 当前项目中记录的资产总数 |\n", len(assets)))
		builder.WriteString(fmt.Sprintf("| 已测试资产 | %d | 已关联漏洞、事实或攻击路径证据的资产 |\n", coverage.AssetsTested))
		builder.WriteString(fmt.Sprintf("| 完整覆盖 | %d | 必测项已完成且无未处理缺口的资产 |\n", coverage.AssetsCovered))
		builder.WriteString(fmt.Sprintf("| 部分覆盖 | %d | 已测试但仍存在覆盖缺口的资产 |\n", coverage.AssetsPartial))
		builder.WriteString(fmt.Sprintf("| 阻塞资产 | %d | 受权限、WAF 或人工核验限制的资产 |\n", coverage.AssetsBlocked))
		builder.WriteString(fmt.Sprintf("| 未测试资产 | %d | 当前没有测试记录的资产 |\n", coverage.AssetsUntested))
		builder.WriteString(fmt.Sprintf(
			"| 测试项覆盖率 | %.1f%% | 已覆盖 %d / 共 %d 个测试项 |\n",
			coverage.TestCoverageRatio*100,
			coverage.TestsCovered,
			coverage.TestsTotal,
		))
		builder.WriteString(fmt.Sprintf("| 已确认漏洞 | %d | 平台当前确认可利用或存在的漏洞 |\n", coverage.FindingsConfirmed))
		builder.WriteString(fmt.Sprintf("| 缺少证据的漏洞 | %d | 需要补充证据或继续验证的漏洞 |\n\n", coverage.FindingsWithoutEvidence))
	}
	builder.WriteString("### 2.2 项目目标\n\n")
	builder.WriteString(markdownParagraph(project.Goals, "项目未填写目标。") + "\n\n")
	builder.WriteString("### 2.3 授权与免责声明\n\n")
	builder.WriteString(scopeSummary + "\n\n")
	builder.WriteString(reportAuthorizationNotice + "\n\n")
	builder.WriteString("### 2.4 评估方法与限制\n\n")
	builder.WriteString("- 报告依据项目授权范围、资产记录、测试记录、漏洞证据和复测记录生成。\n")
	builder.WriteString("- 风险等级沿用平台漏洞记录，当前报告不将平台等级声明为 CVSS 评分。\n")
	builder.WriteString("- 覆盖状态依赖平台的测试记录、事实和证据关联；未测试或阻塞不代表目标不存在漏洞。\n")
	builder.WriteString("- 报告结论以生成时数据为准，后续新增测试或证据应更新报告并重新导出。\n\n")

	builder.WriteString("## 3. 漏洞统计\n\n")
	builder.WriteString("### 3.1 状态统计\n\n")
	builder.WriteString("| 状态 | 数量 |\n|---|---:|\n")
	statuses := make([]string, 0, len(statusCounts))
	for status := range statusCounts {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	for _, status := range statuses {
		builder.WriteString(fmt.Sprintf("| %s | %d |\n", docxStatusLabel(status), statusCounts[status]))
	}
	builder.WriteString("\n")
	builder.WriteString("### 3.2 漏洞清单\n\n")
	if len(sortedFindings) == 0 {
		builder.WriteString("当前项目未记录漏洞。\n\n")
	} else {
		builder.WriteString("| 漏洞地址 | 漏洞类型 | 危害等级 |\n")
		builder.WriteString("|---|---|---|\n")
		for _, item := range sortedFindings {
			builder.WriteString(fmt.Sprintf(
				"| %s | %s | %s |\n",
				markdownCell(docxValue(item.Target, item.Title)),
				markdownCell(docxValue(item.VulnerabilityType, "未分类")),
				docxSeverityLabel(item.Severity),
			))
		}
		builder.WriteString("\n")
	}

	builder.WriteString("## 4. 漏洞详情\n\n")
	if len(sortedFindings) == 0 {
		builder.WriteString("当前项目未记录漏洞。\n\n")
	} else {
		for index, item := range sortedFindings {
			builder.WriteString(fmt.Sprintf("### 4.%d %s\n\n", index+1, escapeMarkdownLine(docxValue(item.Title, item.VulnerabilityType))))
			builder.WriteString("| 字段 | 内容 |\n|---|---|\n")
			builder.WriteString(fmt.Sprintf("| 漏洞编号 | `%s` |\n", markdownCell(item.ID)))
			builder.WriteString(fmt.Sprintf("| 风险等级 | %s |\n", docxSeverityLabel(item.Severity)))
			builder.WriteString(fmt.Sprintf("| 状态 | %s |\n", docxStatusLabel(item.Status)))
			builder.WriteString(fmt.Sprintf("| 漏洞类型 | %s |\n", markdownCell(docxValue(item.VulnerabilityType, "未分类"))))
			builder.WriteString(fmt.Sprintf("| 目标 | %s |\n", markdownCell(docxValue(item.Target, "未记录"))))
			builder.WriteString(fmt.Sprintf("| 验证状态 | %s |\n\n", markdownCell(docxValue(item.VerificationState, "未记录"))))
			builder.WriteString("#### 漏洞概述\n\n" + markdownParagraph(item.Description, "未填写。") + "\n\n")
			builder.WriteString("#### 前置条件\n\n" + markdownParagraph(item.Preconditions, "否") + "\n\n")
			builder.WriteString("#### 复现步骤\n\n" + markdownParagraph(item.ReproductionSteps, "未记录。") + "\n\n")
			builder.WriteString("#### 证据\n\n" + markdownParagraph(item.Evidence, "无") + "\n\n")
			builder.WriteString("#### 影响\n\n" + markdownParagraph(item.Impact, "未记录。") + "\n\n")
			builder.WriteString("#### 修复建议\n\n" + markdownParagraph(item.Recommendation, "未记录。") + "\n\n")
			builder.WriteString("#### 复测备注\n\n" + markdownParagraph(item.RetestNotes, "无法复测") + "\n\n")
		}
	}

	builder.WriteString("## 5. 修复计划与复测要求\n\n")
	builder.WriteString("| 优先级 | 风险等级 | 数量 | 建议时限 | 建议责任角色 | 复测要求 |\n")
	builder.WriteString("|---|---|---:|---|---|---|\n")
	for _, priority := range []struct {
		key      string
		severity string
	}{
		{key: "P0", severity: "critical"},
		{key: "P1", severity: "high"},
		{key: "P2", severity: "medium"},
		{key: "P3", severity: "low"},
		{key: "P3", severity: "info"},
		{key: "待定", severity: "unknown"},
	} {
		builder.WriteString(fmt.Sprintf(
			"| %s | %s | %d | %s | %s | %s |\n",
			priority.key,
			docxSeverityLabel(priority.severity),
			severityCounts[priority.severity],
			reportRemediationDeadline(priority.severity),
			reportRemediationOwner(priority.severity),
			reportRetestRequirement(priority.severity),
		))
	}
	builder.WriteString("\n具体责任人和修复期限应由客户根据系统归属、业务窗口和风险接受流程确认。复测结论必须绑定实际证据，不以状态修改代替验证。\n\n")
	builder.WriteString("## 6. 附录与数据说明\n\n")
	builder.WriteString("- 完整资产清单：`assets.csv`\n")
	builder.WriteString("- 漏洞列表：`vulnerabilities.csv`\n")
	builder.WriteString("- 漏洞证据原文：见各漏洞“证据”章节\n")
	builder.WriteString("- 本报告由 Sophon 根据项目数据库记录生成\n")
	return builder.String()
}

func buildProjectAssetsCSV(
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
) ([]byte, error) {
	byAsset := map[string][]database.Vulnerability{}
	for _, item := range findings {
		byAsset[item.AssetID] = append(byAsset[item.AssetID], item)
	}
	var buffer bytes.Buffer
	buffer.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(&buffer)
	headers := []string{
		"资产 ID", "资产名称", "资产类型", "资产值", "状态", "重要度", "风险分",
		"关联漏洞数", "最高漏洞等级", "已确认漏洞数", "项目名称", "更新时间",
	}
	if err := writer.Write(headers); err != nil {
		return nil, err
	}
	for _, asset := range assets {
		items := byAsset[asset.ID]
		highest := "unknown"
		confirmed := 0
		for _, item := range items {
			if docxSeverityRank(item.Severity) < docxSeverityRank(highest) {
				highest = item.Severity
			}
			if strings.EqualFold(strings.TrimSpace(item.Status), "confirmed") {
				confirmed++
			}
		}
		row := []string{
			asset.ID,
			asset.Name,
			docxAssetKindLabel(asset.Kind),
			asset.Value,
			docxAssetStatusLabel(asset.Status),
			docxCriticalityLabel(asset.Criticality),
			strconv.Itoa(asset.RiskScore),
			strconv.Itoa(len(items)),
			docxSeverityLabel(highest),
			strconv.Itoa(confirmed),
			project.Name,
			asset.UpdatedAt.Format("2006-01-02 15:04:05"),
		}
		for index := range row {
			row[index] = csvSafeCell(row[index])
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

func buildProjectVulnerabilitiesCSV(findings []database.Vulnerability) ([]byte, error) {
	sortedFindings := append([]database.Vulnerability(nil), findings...)
	sort.SliceStable(sortedFindings, func(i, j int) bool {
		left, right := docxSeverityRank(sortedFindings[i].Severity), docxSeverityRank(sortedFindings[j].Severity)
		if left != right {
			return left < right
		}
		return sortedFindings[i].UpdatedAt.After(sortedFindings[j].UpdatedAt)
	})
	var buffer bytes.Buffer
	buffer.Write([]byte{0xEF, 0xBB, 0xBF})
	writer := csv.NewWriter(&buffer)
	headers := []string{"漏洞地址", "漏洞类型", "危害等级", "验证状态"}
	if err := writer.Write(headers); err != nil {
		return nil, err
	}
	for _, item := range sortedFindings {
		row := []string{
			item.Target,
			docxValue(item.VulnerabilityType, "未分类"),
			docxSeverityLabel(item.Severity),
			docxValue(item.VerificationState, "未记录"),
		}
		for index := range row {
			row[index] = csvSafeCell(row[index])
		}
		if err := writer.Write(row); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	return buffer.Bytes(), writer.Error()
}

func buildProjectReportPackage(
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
	markdown string,
	pdfMarkdown string,
	generatedAt time.Time,
) ([]byte, error) {
	pdf, err := renderProjectReportPDF(context.Background(), project, pdfMarkdown, findings, generatedAt)
	if err != nil {
		return nil, err
	}
	assetsCSV, err := buildProjectAssetsCSV(project, assets, findings)
	if err != nil {
		return nil, err
	}
	vulnerabilitiesCSV, err := buildProjectVulnerabilitiesCSV(findings)
	if err != nil {
		return nil, err
	}
	base := sanitizeProjectExportName(project.Name) + "-风险评估报告"
	manifest, err := json.MarshalIndent(projectReportManifest{
		ProjectID:           project.ID,
		ProjectName:         project.Name,
		GeneratedAt:         generatedAt,
		Assets:              len(assets),
		Vulnerabilities:     len(findings),
		MarkdownFile:        base + ".md",
		PDFFile:             base + ".pdf",
		AssetsFile:          "assets.csv",
		VulnerabilitiesFile: "vulnerabilities.csv",
		Classification:      "内部",
		Renderer:            "chromium",
	}, "", "  ")
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	archive := zip.NewWriter(&buffer)
	for name, data := range map[string][]byte{
		base + ".md":          []byte(markdown),
		base + ".pdf":         pdf,
		"assets.csv":          assetsCSV,
		"vulnerabilities.csv": vulnerabilitiesCSV,
		"manifest.json":       manifest,
	} {
		entry, err := archive.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := entry.Write(data); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (h *ProjectHandler) inlineVulnerabilityReportImages(
	ctx context.Context,
	c *gin.Context,
	markdown string,
) string {
	if h == nil || h.db == nil {
		return markdown
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		return markdown
	}
	imageCount := 0
	totalBytes := 0
	const (
		maxReportImages = 20
		maxReportBytes  = 20 << 20
	)
	return reportVulnerabilityImagePattern.ReplaceAllStringFunc(markdown, func(match string) string {
		parts := reportVulnerabilityImagePattern.FindStringSubmatch(match)
		if len(parts) != 5 {
			return match
		}
		if imageCount >= maxReportImages || totalBytes >= maxReportBytes {
			return "![图片超出报告配额](sophon-image-limit)"
		}
		item, err := h.db.GetVulnerabilityImage(ctx, parts[4], parts[3], user.ID)
		if err != nil || item.SizeBytes <= 0 || item.SizeBytes > int64(maxReportBytes-totalBytes) {
			return "![图片不可用](sophon-image-missing)"
		}
		imageCount++
		totalBytes += len(item.Data)
		return "![" + parts[1] + "](data:" + item.MimeType + ";base64," +
			base64.StdEncoding.EncodeToString(item.Data) + ")"
	})
}

func renderProjectReportPDF(
	ctx context.Context,
	project *database.Project,
	markdown string,
	findings []database.Vulnerability,
	generatedAt time.Time,
) ([]byte, error) {
	if project == nil {
		return nil, fmt.Errorf("项目不能为空")
	}
	chromium, err := exec.LookPath("chromium")
	if err != nil {
		return nil, fmt.Errorf("未安装 Chromium PDF 渲染器")
	}
	tempDir, err := os.MkdirTemp("", "sophon-report-*")
	if err != nil {
		return nil, fmt.Errorf("创建 PDF 临时目录失败")
	}
	defer os.RemoveAll(tempDir)
	htmlPath := filepath.Join(tempDir, "report.html")
	pdfPath := filepath.Join(tempDir, "report.pdf")
	profilePath := filepath.Join(tempDir, "chromium-profile")
	if err := os.WriteFile(htmlPath, []byte(reportHTMLDocument(project, markdown, findings, generatedAt)), 0o600); err != nil {
		return nil, fmt.Errorf("写入报告 HTML 失败")
	}
	renderCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	command := procwrap.CommandContext(
		renderCtx,
		chromium,
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--disable-background-networking",
		"--disable-breakpad",
		"--host-resolver-rules=MAP * ~NOTFOUND",
		"--user-data-dir="+profilePath,
		"--no-pdf-header-footer",
		"--print-to-pdf="+pdfPath,
		(&url.URL{Scheme: "file", Path: htmlPath}).String(),
	)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Chromium 生成 PDF 失败: %v: %s", err, truncateRunes(string(output), 500))
	}
	data, err := os.ReadFile(pdfPath)
	if err != nil || !bytes.HasPrefix(data, []byte("%PDF-")) {
		return nil, fmt.Errorf("Chromium 未生成有效 PDF")
	}
	return data, nil
}

func reportSeverityCounts(findings []database.Vulnerability) map[string]int {
	counts := make(map[string]int, len(docxSeverityOrder))
	for _, item := range findings {
		counts[normalizeDocxSeverity(item.Severity)]++
	}
	return counts
}

func reportOverallSeverity(findings []database.Vulnerability) string {
	counts := reportSeverityCounts(findings)
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		if counts[severity] > 0 {
			return docxSeverityLabel(severity)
		}
	}
	if counts["unknown"] > 0 {
		return "未评级"
	}
	return "未发现已记录风险"
}

func projectReportNumber(projectID string, generatedAt time.Time) string {
	compact := strings.ReplaceAll(strings.TrimSpace(projectID), "-", "")
	if len(compact) > 8 {
		compact = compact[:8]
	}
	if compact == "" {
		compact = "REPORT"
	}
	return fmt.Sprintf("SPH-%s-%s", strings.ToUpper(compact), projectReportTime(generatedAt)[:10])
}

func projectReportTime(value time.Time) string {
	location := time.FixedZone("UTC+8", 8*60*60)
	return value.In(location).Format("2006-01-02 15:04")
}

func reportScopeEntryCount(scope string) int {
	return len(strings.Fields(strings.TrimSpace(scope)))
}

func reportRemediationDeadline(severity string) string {
	switch normalizeDocxSeverity(severity) {
	case "critical":
		return "24 小时"
	case "high":
		return "7 天"
	case "medium":
		return "30 天"
	case "low", "info":
		return "下一迭代"
	default:
		return "完成评级后确定"
	}
}

func reportRemediationOwner(severity string) string {
	switch normalizeDocxSeverity(severity) {
	case "critical", "high":
		return "应用/系统负责人、安全团队"
	default:
		return "应用/系统负责人"
	}
}

func reportRetestRequirement(severity string) string {
	switch normalizeDocxSeverity(severity) {
	case "critical", "high":
		return "原入口与影响链不可复现，并记录修复后证据"
	case "medium", "low", "info":
		return "原触发条件不再成立，并记录回归结果"
	default:
		return "先完成风险评级和证据确认"
	}
}

func reportSeverityChartHTML(findings []database.Vulnerability) string {
	counts := reportSeverityCounts(findings)
	total := len(findings)
	criticalHigh := counts["critical"] + counts["high"]
	rows := []struct {
		key   string
		label string
	}{
		{key: "critical", label: docxSeverityLabel("critical")},
		{key: "high", label: docxSeverityLabel("high")},
		{key: "medium", label: docxSeverityLabel("medium")},
		{key: "low", label: docxSeverityLabel("low")},
		{key: "info", label: docxSeverityLabel("info")},
		{key: "unknown", label: docxSeverityLabel("unknown")},
	}
	var builder strings.Builder
	builder.WriteString(`<section class="severity-chart" aria-label="漏洞严重程度分布">
<header class="severity-chart-head"><div><span>OUT-03 / SEVERITY</span><strong>漏洞严重程度分布</strong></div><div class="severity-chart-kpis"><div><small>风险总数</small><strong>`)
	builder.WriteString(strconv.Itoa(total))
	builder.WriteString(`</strong></div><div><small>严重 + 高危</small><strong>`)
	builder.WriteString(strconv.Itoa(criticalHigh))
	builder.WriteString(`</strong></div></div></header>
<div class="severity-chart-rows">`)
	rendered := 0
	for _, row := range rows {
		count := counts[row.key]
		if row.key == "unknown" && count == 0 {
			continue
		}
		width := "0%"
		percent := "0%"
		if total > 0 && count > 0 {
			ratio := float64(count) * 100 / float64(total)
			if ratio < 2 {
				ratio = 2
			}
			width = fmt.Sprintf("%.1f%%", ratio)
			percent = fmt.Sprintf("%.0f%%", float64(count)*100/float64(total))
		}
		builder.WriteString(fmt.Sprintf(
			`<div class="severity-chart-row tone-%s"><span class="severity-dot"></span><span class="severity-label">%s</span><span class="severity-track"><i style="width:%s"></i></span><strong>%d</strong><span class="severity-percent">%s</span></div>`,
			row.key,
			row.label,
			width,
			count,
			percent,
		))
		rendered++
	}
	if rendered == 0 {
		builder.WriteString(`<p class="severity-empty">当前项目未记录漏洞。</p>`)
	}
	builder.WriteString(`</div></section>`)
	return builder.String()
}

func reportHTMLDocument(
	project *database.Project,
	markdown string,
	findings []database.Vulnerability,
	generatedAt time.Time,
) string {
	if project == nil {
		project = &database.Project{}
	}
	body := renderReportMarkdownHTML(markdown)
	body = strings.Replace(
		body,
		`<h2 id="4-漏洞详情">`,
		reportSeverityChartHTML(findings)+`<h2 id="4-漏洞详情">`,
		1,
	)
	logo := reportSophonLogoDataURL()
	projectName := htmlstd.EscapeString(docxValue(project.Name, "未命名项目"))
	disclaimer := htmlstd.EscapeString(reportAuthorizationNotice)
	reportNo := htmlstd.EscapeString(projectReportNumber(project.ID, generatedAt))
	generatedText := htmlstd.EscapeString(projectReportTime(generatedAt))
	return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data: file:">
<title>` + projectName + `风险评估报告</title>
<style>
@page { size: A4; margin: 14mm; }
* { box-sizing: border-box; }
body { margin: 0; color: #202027; background: #ffffff; font-family: "Droid Sans Fallback", "DejaVu Sans", sans-serif; font-size: 10.8pt; line-height: 1.8; letter-spacing: 0.015em; }
.cover { display: flex; height: 100vh; min-height: 100vh; flex-direction: column; overflow: hidden; border: 1px solid #dce3e9; color: #202027; background: #f7f9fb; page-break-after: always; }
.cover-top { display: flex; align-items: center; justify-content: space-between; gap: 18px; padding: 11mm 15mm; border-bottom: 1px solid #dce3e9; background: #ffffff; }
.cover-brand { display: flex; align-items: center; gap: 12px; min-width: 0; }
.brand-logo { width: 44px; height: 44px; flex: 0 0 auto; border: 1px solid #dce3e9; border-radius: 6px; object-fit: cover; }
.brand-name { color: #202027; font-size: 17pt; font-weight: 750; line-height: 1.1; letter-spacing: 0.01em; }
.brand-caption { margin-top: 4px; color: #7b8794; font-size: 7.2pt; letter-spacing: 0.1em; }
.cover-topline { color: #7b8794; font-family: "DejaVu Sans Mono", monospace; font-size: 7.2pt; letter-spacing: 0.1em; text-align: right; }
.cover-hero { display: flex; flex: 1; flex-direction: column; align-items: center; justify-content: center; padding: 20mm 17mm 12mm; text-align: center; }
.cover-title { max-width: 162mm; margin: 0 auto; color: #202027; font-size: 30pt; font-weight: 760; line-height: 1.24; letter-spacing: 0.005em; text-align: center; overflow-wrap: anywhere; }
.cover-title::after { display: block; width: 36mm; height: 2px; margin: 8mm auto 7mm; content: ""; background: #03c3ec; }
.cover-subtitle { margin: 0; color: #40505e; font-size: 18pt; font-weight: 650; line-height: 1.3; text-align: center; }
.cover-description { margin: 7mm 0 0; color: #7b8794; font-size: 9.5pt; text-align: center; }
.cover-facts { display: grid; width: 100%; max-width: 162mm; grid-template-columns: minmax(0, 1fr); margin: 13mm auto 0; border: 1px solid #dce3e9; background: #ffffff; text-align: left; }
.cover-facts > div { display: grid; min-width: 0; grid-template-columns: 34mm minmax(0, 1fr); gap: 6mm; align-items: center; padding: 4mm 5mm; border-bottom: 1px solid #dce3e9; text-align: left; }
.cover-facts > div:last-child { border-bottom: 0; }
.cover-facts small { display: block; color: #7b8794; font-family: "DejaVu Sans Mono", monospace; font-size: 7.2pt; letter-spacing: 0.08em; }
.cover-facts strong { display: block; margin: 0; color: #202027; font-size: 9.5pt; line-height: 1.45; text-align: left; overflow-wrap: anywhere; }
.cover-bottom { margin-top: auto; padding: 0 15mm 10mm; }
.authorization { padding: 4mm 5mm; border: 1px solid #e8c796; border-left: 3px solid #f0a43a; background: #fffaf1; color: #5f4528; }
.authorization strong { display: block; margin-bottom: 4px; color: #a35a16; font-size: 9pt; }
.authorization p { margin: 0; font-size: 8.5pt; line-height: 1.65; text-align: left; }
.cover-footer { display: flex; justify-content: space-between; gap: 12px; margin: 4mm 0 0; padding: 4mm 0 0; border-top: 1px solid #d9e0e7; color: #7b8794; font-family: "DejaVu Sans Mono", monospace; font-size: 7pt; letter-spacing: 0.1em; }
.report-body > h1:first-child { display: none; }
.report-body h1 { margin: 0 0 18px; padding-bottom: 8px; border-bottom: 2px solid #03c3ec; color: #202027; font-size: 22pt; }
.report-body h2 { margin: 27px 0 13px; padding: 10px 13px 9px 14px; border: 1px solid #34343d; border-left: 4px solid #03c3ec; background: #202027; color: #f1f4f7; font-size: 17.5pt; font-weight: 700; letter-spacing: 0.02em; page-break-before: auto; page-break-after: avoid; }
.report-body h2[id="目录"] { page-break-before: always; }
.report-body h2[id="4-漏洞详情"] { page-break-before: always; }
.report-body h3 { margin: 22px 0 10px; padding: 8px 11px; border-left: 3px solid #f0a43a; background: #f2f5f8; color: #202027; font-size: 13.5pt; font-weight: 700; letter-spacing: 0.015em; page-break-after: avoid; }
.report-body h4 { margin: 17px 0 7px; padding-bottom: 4px; border-bottom: 1px solid #e2e8ee; color: #344454; font-size: 11.5pt; font-weight: 700; page-break-after: avoid; }
.report-body h2[id="目录"] + ul { display: grid; gap: 7px; margin: 15px 0 0; padding: 0; list-style: none; page-break-inside: avoid; }
.report-body h2[id="目录"] + ul li { margin: 0; padding: 9px 12px; border: 1px solid #dfe5eb; border-left: 3px solid #55c7e8; background: #f7f9fb; }
.report-body h2[id="目录"] + ul a { color: #202027; font-size: 10.5pt; font-weight: 600; text-decoration: none; }
.report-body h2[id="目录"] + ul a::after { content: ""; }
p { margin: 8px 0; text-align: left; }
blockquote { margin: 10px 0; padding: 9px 13px; border-left: 3px solid #55c7e8; background: #f2f8fa; color: #40505e; }
table { width: 100%; margin: 10px 0 16px; border-collapse: collapse; page-break-inside: avoid; }
thead { display: table-header-group; }
th, td { padding: 8px 10px; border: 1px solid #d7dee6; vertical-align: top; overflow-wrap: anywhere; font-size: 9.4pt; line-height: 1.6; letter-spacing: 0.01em; }
th { border-color: #34343d; background: #202027; color: #edf2f6; font-family: "DejaVu Sans Mono", monospace; font-size: 9pt; text-align: left; }
tbody tr:nth-child(even) { background: #f7f9fb; }
pre { margin: 11px 0; padding: 12px 14px; overflow-wrap: anywhere; white-space: pre-wrap; border: 1px solid #34343d; border-left: 4px solid #03c3ec; background: #202027; color: #e6edf3; font-family: "DejaVu Sans Mono", monospace; font-size: 8.2pt; line-height: 1.55; letter-spacing: 0; page-break-inside: avoid; }
code { padding: 1px 3px; border-radius: 2px; color: #0b6378; background: #eef7fa; font-family: "DejaVu Sans Mono", monospace; font-size: 8.8pt; letter-spacing: 0; }
pre code { padding: 0; color: inherit; background: transparent; }
ul, ol { margin: 10px 0; padding-left: 27px; }
.report-clause-list li { margin: 5px 0; padding-left: 3px; overflow-wrap: anywhere; }
.report-clause-list li::marker { color: #0b88b2; font-family: "DejaVu Sans Mono", monospace; font-weight: 700; }
.report-image { display: block; max-width: 100%; max-height: 210mm; margin: 11px auto; border: 1px solid #d7dee6; object-fit: contain; page-break-inside: avoid; }
.report-image-missing { color: #a35a16; font-size: 8.5pt; }
hr { margin: 18px 0; border: 0; border-top: 1px solid #d7dee6; }
.report-body a { color: #0b6378; text-decoration: none; }
.report-body a::after { color: #8a96a3; content: " ↗"; font-size: 7pt; }
.severity-chart { margin: 15px 0 18px; padding: 13px 15px 12px; border: 1px solid #dce3e9; border-top: 2px solid #03c3ec; background: #f8fafb; page-break-inside: avoid; }
.severity-chart-head { display: flex; justify-content: space-between; gap: 18px; align-items: flex-end; padding-bottom: 10px; border-bottom: 1px solid #dce3e9; }
.severity-chart-head > div:first-child span { display: block; color: #0b88b2; font-family: "DejaVu Sans Mono", monospace; font-size: 7pt; font-weight: 700; letter-spacing: 0.1em; }
.severity-chart-head > div:first-child strong { display: block; margin-top: 3px; color: #202027; font-size: 12.5pt; }
.severity-chart-kpis { display: flex; gap: 18px; }
.severity-chart-kpis > div { text-align: right; }
.severity-chart-kpis small { display: block; color: #7b8794; font-size: 7.5pt; }
.severity-chart-kpis strong { color: #202027; font-family: "DejaVu Sans Mono", monospace; font-size: 15pt; }
.severity-chart-rows { display: grid; gap: 8px; margin-top: 11px; }
.severity-chart-row { display: grid; grid-template-columns: 8px 44px minmax(0, 1fr) 34px 42px; gap: 9px; align-items: center; --tone: #8592a3; }
.severity-chart-row.tone-critical { --tone: #ff3e1d; }
.severity-chart-row.tone-high { --tone: #ffab00; }
.severity-chart-row.tone-medium { --tone: #ffbc33; }
.severity-chart-row.tone-low { --tone: #03c3ec; }
.severity-chart-row.tone-info { --tone: #8592a3; }
.severity-chart-row.tone-unknown { --tone: #9aa4af; }
.severity-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--tone); }
.severity-label { color: #40505e; font-size: 8.5pt; font-weight: 600; }
.severity-track { height: 8px; overflow: hidden; border: 1px solid #d5dde5; border-radius: 2px; background: #e8edf2; }
.severity-track i { display: block; height: 100%; background: var(--tone); }
.severity-chart-row strong, .severity-percent { font-family: "DejaVu Sans Mono", monospace; text-align: right; }
.severity-chart-row strong { color: #202027; font-size: 9pt; }
.severity-percent { color: #7b8794; font-size: 8pt; }
.severity-empty { margin: 4px 0; color: #7b8794; font-size: 9pt; }
</style></head><body>
<section class="cover">
  <header class="cover-top">
    <div class="cover-brand" aria-label="Sophon 智能安全助手">
      <img class="brand-logo" src="` + logo + `" alt="Sophon">
      <div><div class="brand-name">Sophon</div><div class="brand-caption">智能安全助手 / INTELLIGENT SECURITY ASSISTANT</div></div>
    </div>
    <div class="cover-topline">DOSSIER / RISK ASSESSMENT<br>INTERNAL / V1.0</div>
  </header>
  <main class="cover-hero">
    <h1 class="cover-title">` + projectName + `</h1>
    <p class="cover-subtitle">风险评估报告</p>
    <p class="cover-description">基于授权测试记录、运行证据与漏洞数据生成</p>
    <div class="cover-facts">
      <div><small>报告编号</small><strong>` + reportNo + `</strong></div>
      <div><small>生成日期</small><strong>` + generatedText + `</strong></div>
      <div><small>报告密级</small><strong>内部 / V1.0</strong></div>
    </div>
  </main>
  <div class="cover-bottom">
    <div class="authorization"><strong>授权与免责声明</strong><p>` + disclaimer + `</p></div>
    <footer class="cover-footer"><span>INTERNAL USE ONLY</span><span>SOPHON / INTELLIGENT SECURITY ASSISTANT</span></footer>
  </div>
</section>
<main class="report-body">` + body + `</main>
</body></html>`
}

var (
	markdownHeadingPattern          = regexp.MustCompile(`^(#{1,6})\s+(.+)$`)
	markdownOrderedPattern          = regexp.MustCompile(`^\s*(\d+)\.\s+(.+)$`)
	markdownNumericListPattern      = regexp.MustCompile(`(?:（(\d{1,2})）|\((\d{1,2})\)|(\d{1,2})[）)、])`)
	markdownChineseListPattern      = regexp.MustCompile(`([一二三四五六七八九十]{1,3})、`)
	markdownCircledListPattern      = regexp.MustCompile(`([①-⑳㉑-㉟])`)
	markdownImagePattern            = regexp.MustCompile(`!\[([^\]]*)\]\(([^)]+)\)`)
	markdownInlineCode              = regexp.MustCompile("`([^`]+)`")
	markdownBoldPattern             = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	markdownLinkPattern             = regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)
	reportVulnerabilityImagePattern = regexp.MustCompile(`!\[([^\]]*)\]\((/api/vulnerabilities/([^/\s)]+)/reproduction-images/([^/\s)]+))\)`)
)

type reportListMarker struct {
	start  int
	end    int
	number int
}

func renderReportMarkdownHTML(markdown string) string {
	lines := strings.Split(strings.ReplaceAll(markdown, "\r\n", "\n"), "\n")
	if len(lines) > 1 && strings.TrimSpace(lines[0]) == "---" {
		for index := 1; index < len(lines); index++ {
			if strings.TrimSpace(lines[index]) == "---" {
				lines = lines[index+1:]
				break
			}
		}
	}
	var out strings.Builder
	var paragraph []string
	listType := ""
	inCode := false
	codeLang := ""
	var code []string
	flushParagraph := func() {
		if len(paragraph) == 0 {
			return
		}
		text := strings.Join(paragraph, " ")
		if lead, items, ok := splitReportInlineNumberedList(text); ok {
			if lead != "" {
				out.WriteString("<p>" + renderReportInline(lead) + "</p>\n")
			}
			out.WriteString(`<ol class="report-clause-list">` + "\n")
			for _, item := range items {
				out.WriteString("<li>" + renderReportInline(item) + "</li>\n")
			}
			out.WriteString("</ol>\n")
		} else {
			out.WriteString("<p>" + renderReportInline(text) + "</p>\n")
		}
		paragraph = nil
	}
	flushList := func() {
		if listType == "" {
			return
		}
		out.WriteString("</" + listType + ">\n")
		listType = ""
	}
	for index := 0; index < len(lines); index++ {
		line := lines[index]
		trimmed := strings.TrimSpace(line)
		if inCode {
			if strings.HasPrefix(trimmed, "```") {
				out.WriteString(`<pre><code`)
				if codeLang != "" {
					out.WriteString(` class="language-` + htmlstd.EscapeString(codeLang) + `"`)
				}
				out.WriteString(`>` + htmlstd.EscapeString(strings.Join(code, "\n")) + "</code></pre>\n")
				inCode = false
				code = nil
				codeLang = ""
			} else {
				code = append(code, line)
			}
			continue
		}
		if strings.HasPrefix(trimmed, "```") {
			flushParagraph()
			flushList()
			inCode = true
			codeLang = strings.TrimSpace(strings.TrimPrefix(trimmed, "```"))
			continue
		}
		if trimmed == "" {
			flushParagraph()
			flushList()
			continue
		}
		if match := markdownHeadingPattern.FindStringSubmatch(trimmed); len(match) == 3 {
			flushParagraph()
			flushList()
			level := len(match[1])
			out.WriteString(fmt.Sprintf(
				"<h%d id=\"%s\">%s</h%d>\n",
				level,
				markdownHeadingID(match[2]),
				renderReportInline(match[2]),
				level,
			))
			continue
		}
		if strings.HasPrefix(trimmed, "|") && index+1 < len(lines) && isMarkdownTableSeparator(lines[index+1]) {
			flushParagraph()
			flushList()
			headers := markdownTableCells(trimmed)
			out.WriteString("<table><thead><tr>")
			for _, cell := range headers {
				out.WriteString("<th>" + renderReportInline(cell) + "</th>")
			}
			out.WriteString("</tr></thead><tbody>\n")
			index += 2
			for ; index < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[index]), "|"); index++ {
				out.WriteString("<tr>")
				for _, cell := range markdownTableCells(strings.TrimSpace(lines[index])) {
					out.WriteString("<td>" + renderReportInline(cell) + "</td>")
				}
				out.WriteString("</tr>\n")
			}
			index--
			out.WriteString("</tbody></table>\n")
			continue
		}
		if item, ok := markdownUnorderedItem(trimmed); ok {
			flushParagraph()
			if listType != "ul" {
				flushList()
				listType = "ul"
				out.WriteString("<ul>\n")
			}
			out.WriteString("<li>" + renderReportInline(item) + "</li>\n")
			continue
		}
		if item, ok := markdownOrderedItem(trimmed); ok {
			flushParagraph()
			if listType != "ol" {
				flushList()
				listType = "ol"
				out.WriteString("<ol>\n")
			}
			out.WriteString("<li>" + renderReportInline(item) + "</li>\n")
			continue
		}
		if strings.HasPrefix(trimmed, ">") {
			flushParagraph()
			flushList()
			out.WriteString("<blockquote>" + renderReportInline(strings.TrimSpace(strings.TrimPrefix(trimmed, ">"))) + "</blockquote>\n")
			continue
		}
		if trimmed == "---" {
			flushParagraph()
			flushList()
			out.WriteString("<hr>\n")
			continue
		}
		paragraph = append(paragraph, trimmed)
	}
	if inCode {
		out.WriteString("<pre><code>" + htmlstd.EscapeString(strings.Join(code, "\n")) + "</code></pre>\n")
	}
	flushParagraph()
	flushList()
	return out.String()
}

func splitReportInlineNumberedList(value string) (string, []string, bool) {
	value = strings.TrimSpace(value)
	markers := reportListMarkers(value)
	if len(markers) < 2 {
		return "", nil, false
	}
	lead := strings.TrimSpace(value[:markers[0].start])
	if lead != "" && !strings.HasSuffix(lead, "：") && !strings.HasSuffix(lead, ":") {
		return "", nil, false
	}
	items := make([]string, 0, len(markers))
	for index, marker := range markers {
		if marker.number != index+1 {
			return "", nil, false
		}
		end := len(value)
		if index+1 < len(markers) {
			end = markers[index+1].start
		}
		item := strings.TrimSpace(value[marker.end:end])
		item = strings.Trim(item, " \t\r\n;；")
		if item == "" {
			return "", nil, false
		}
		items = append(items, item)
	}
	return lead, items, true
}

func reportListMarkers(value string) []reportListMarker {
	markers := make([]reportListMarker, 0, 8)
	for _, match := range markdownNumericListPattern.FindAllStringSubmatchIndex(value, -1) {
		numberText := ""
		for index := 2; index+1 < len(match); index += 2 {
			if match[index] >= 0 {
				numberText = value[match[index]:match[index+1]]
				break
			}
		}
		number, err := strconv.Atoi(numberText)
		if err == nil {
			markers = append(markers, reportListMarker{start: match[0], end: match[1], number: number})
		}
	}
	for _, match := range markdownChineseListPattern.FindAllStringSubmatchIndex(value, -1) {
		number, ok := reportChineseNumber(value[match[2]:match[3]])
		if ok {
			markers = append(markers, reportListMarker{start: match[0], end: match[1], number: number})
		}
	}
	for _, match := range markdownCircledListPattern.FindAllStringSubmatchIndex(value, -1) {
		runes := []rune(value[match[2]:match[3]])
		if len(runes) == 0 {
			continue
		}
		number, ok := reportCircledNumber(runes[0])
		if ok {
			markers = append(markers, reportListMarker{start: match[0], end: match[1], number: number})
		}
	}
	sort.SliceStable(markers, func(i, j int) bool {
		return markers[i].start < markers[j].start
	})
	result := markers[:0]
	for _, marker := range markers {
		if len(result) > 0 && marker.start < result[len(result)-1].end {
			continue
		}
		result = append(result, marker)
	}
	return result
}

func reportChineseNumber(value string) (int, bool) {
	digits := map[rune]int{
		'一': 1, '二': 2, '三': 3, '四': 4, '五': 5,
		'六': 6, '七': 7, '八': 8, '九': 9,
	}
	if len([]rune(value)) == 1 {
		number, ok := digits[[]rune(value)[0]]
		if []rune(value)[0] == '十' {
			return 10, true
		}
		return number, ok
	}
	parts := strings.SplitN(value, "十", 2)
	if len(parts) != 2 {
		return 0, false
	}
	tens := 1
	if parts[0] != "" {
		number, ok := digits[[]rune(parts[0])[0]]
		if !ok {
			return 0, false
		}
		tens = number
	}
	units := 0
	if parts[1] != "" {
		number, ok := digits[[]rune(parts[1])[0]]
		if !ok {
			return 0, false
		}
		units = number
	}
	return tens*10 + units, true
}

func reportCircledNumber(value rune) (int, bool) {
	switch {
	case value >= '①' && value <= '⑳':
		return int(value-'①') + 1, true
	case value >= '㉑' && value <= '㉟':
		return int(value-'㉑') + 21, true
	default:
		return 0, false
	}
}

func markdownUnorderedItem(value string) (string, bool) {
	for _, prefix := range []string{"- ", "* ", "• ", "● ", "▪ ", "· ", "– "} {
		if strings.HasPrefix(value, prefix) {
			item := strings.TrimSpace(strings.TrimPrefix(value, prefix))
			return item, item != ""
		}
	}
	return "", false
}

func markdownOrderedItem(value string) (string, bool) {
	if match := markdownOrderedPattern.FindStringSubmatch(value); len(match) == 3 {
		return match[2], true
	}
	markers := reportListMarkers(value)
	if len(markers) != 1 || markers[0].start != 0 {
		return "", false
	}
	item := strings.TrimSpace(value[markers[0].end:])
	return item, item != ""
}

func renderReportInline(value string) string {
	escaped := htmlstd.EscapeString(value)
	escaped = markdownImagePattern.ReplaceAllStringFunc(escaped, func(match string) string {
		parts := markdownImagePattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return htmlstd.EscapeString(match)
		}
		src := htmlstd.UnescapeString(parts[2])
		if !reportDataImageURL(src) {
			return `<span class="report-image-missing">[图片不可用：` + parts[1] + `]</span>`
		}
		return `<img class="report-image" src="` + htmlstd.EscapeString(src) + `" alt="` + parts[1] + `">`
	})
	escaped = markdownInlineCode.ReplaceAllString(escaped, "<code>$1</code>")
	escaped = markdownBoldPattern.ReplaceAllString(escaped, "<strong>$1</strong>")
	escaped = markdownLinkPattern.ReplaceAllStringFunc(escaped, func(match string) string {
		parts := markdownLinkPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return htmlstd.EscapeString(match)
		}
		parsed, err := url.Parse(htmlstd.UnescapeString(parts[2]))
		if err != nil || (parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https") {
			return parts[1]
		}
		return `<a href="` + htmlstd.EscapeString(parsed.String()) + `">` + parts[1] + `</a>`
	})
	return escaped
}

func reportDataImageURL(value string) bool {
	for _, prefix := range []string{
		"data:image/png;base64,",
		"data:image/jpeg;base64,",
		"data:image/webp;base64,",
	} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func isMarkdownTableSeparator(value string) bool {
	cells := markdownTableCells(strings.TrimSpace(value))
	if len(cells) == 0 {
		return false
	}
	for _, cell := range cells {
		cell = strings.Trim(cell, " :-")
		if cell != "" {
			return false
		}
	}
	return true
}

func markdownTableCells(value string) []string {
	value = strings.Trim(strings.TrimSpace(value), "|")
	parts := strings.Split(value, "|")
	cells := make([]string, 0, len(parts))
	for _, part := range parts {
		cells = append(cells, strings.TrimSpace(part))
	}
	return cells
}

func markdownParagraph(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	return value
}

func escapeMarkdownLine(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), "\n", " ")
}

func markdownCell(value string) string {
	value = escapeMarkdownLine(value)
	return strings.ReplaceAll(strings.ReplaceAll(value, "|", "\\|"), "`", "'")
}

func reportScopeSummary(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "未设置"
	}
	fields := strings.Fields(value)
	if len(fields) > 8 {
		return fmt.Sprintf("项目授权资产共 %d 项，完整范围见 assets.csv", len(fields))
	}
	return truncateRunes(value, 420)
}

func markdownHeadingID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, char := range value {
		switch {
		case unicode.IsLetter(char), unicode.IsDigit(char):
			builder.WriteRune(char)
			lastDash = false
		case unicode.IsSpace(char), unicode.IsPunct(char):
			if builder.Len() > 0 && !lastDash {
				builder.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(builder.String(), "-")
}

func csvSafeCell(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}
