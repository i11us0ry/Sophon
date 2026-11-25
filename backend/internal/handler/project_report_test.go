package handler

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func TestBuildProjectReportMarkdown(t *testing.T) {
	project := &database.Project{ID: "project-report", Name: "报告测试"}
	assets := []database.Asset{{ID: "asset-1", Name: "门户", Value: "https://example.com"}}
	findings := []database.Vulnerability{{
		ID:                "vuln-1",
		Title:             "https://example.com/api-未授权访问-读取数据-vuln1",
		Severity:          "high",
		Status:            "confirmed",
		VulnerabilityType: "未授权访问",
		Target:            "https://example.com/api",
		Description:       "接口缺少认证。",
		ReproductionSteps: "GET /api HTTP/1.1\nHost: example.com",
		Evidence:          "返回了业务数据。",
		EvidenceRefs:      []string{"tool:evidence-1"},
		Impact:            "可读取业务数据。",
		Recommendation:    "增加认证。",
		RetestNotes:       "无法复测",
	}}
	coverage := &database.ProjectCoverage{
		AssetsTotal:       1,
		AssetsTested:      1,
		AssetsCovered:     1,
		TestsTotal:        1,
		TestsCovered:      1,
		TestCoverageRatio: 1,
		FindingsTotal:     1,
		FindingsConfirmed: 1,
	}
	markdown := buildProjectReportMarkdown(project, assets, findings, coverage, time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC))
	for _, want := range []string{
		"# 报告测试风险评估报告",
		"## 1. 决策摘要",
		"最高风险等级为“高危”",
		"### 1.2 优先处置",
		"当前项目未记录严重漏洞",
		"## 目录",
		"[4. 漏洞详情](#4-漏洞详情)",
		"报告编号",
		"已测试资产",
		"授权与免责声明",
		"合法授权",
		"## 5. 修复计划与复测要求",
		"vulnerabilities.csv",
		"### 4.1 ",
		"#### 复现步骤",
		"#### 证据",
		"tool:evidence-1",
		"完整资产清单",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("Markdown 报告缺少 %q", want)
		}
	}
}

func TestConfirmedReportFindingsOnlyKeepsConfirmedStatus(t *testing.T) {
	items := confirmedReportFindings([]database.Vulnerability{
		{ID: "confirmed", Status: "confirmed"},
		{ID: "open", Status: "open"},
		{ID: "fixed", Status: "fixed"},
	})
	if len(items) != 1 || items[0].ID != "confirmed" {
		t.Fatalf("报告漏洞过滤错误: %+v", items)
	}
}

func TestBuildProjectAssetsCSVPreventsFormulaInjection(t *testing.T) {
	project := &database.Project{Name: "报告测试"}
	assets := []database.Asset{{
		ID:          "asset-1",
		Name:        "=cmd",
		Kind:        "url",
		Value:       "+SUM(1,2)",
		Status:      "active",
		Criticality: "high",
		RiskScore:   90,
		UpdatedAt:   time.Now().UTC(),
	}}
	findings := []database.Vulnerability{{
		AssetID:  "asset-1",
		Severity: "high",
		Status:   "confirmed",
	}}
	data, err := buildProjectAssetsCSV(project, assets, findings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("CSV 缺少 UTF-8 BOM")
	}
	text := string(data)
	for _, want := range []string{"'=cmd", "'+SUM(1,2)", "关联漏洞数", "最高漏洞等级"} {
		if !strings.Contains(text, want) {
			t.Fatalf("资产 CSV 缺少 %q", want)
		}
	}
}

func TestBuildProjectVulnerabilitiesCSVPreventsFormulaInjection(t *testing.T) {
	findings := []database.Vulnerability{{
		ID:                "vuln-1",
		Title:             "=cmd",
		Severity:          "high",
		Status:            "confirmed",
		VulnerabilityType: "+SUM(1,2)",
		Target:            "@target",
		AssetID:           "asset-1",
		Evidence:          "HTTP 200",
		UpdatedAt:         time.Now().UTC(),
	}}
	data, err := buildProjectVulnerabilitiesCSV(findings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("vulnerabilities.csv 缺少 UTF-8 BOM")
	}
	text := string(data)
	for _, want := range []string{"漏洞地址", "漏洞类型", "危害等级", "验证状态", "'+SUM(1,2)", "'@target"} {
		if !strings.Contains(text, want) {
			t.Fatalf("vulnerabilities.csv 缺少 %q", want)
		}
	}
}

func TestRenderReportMarkdownHTMLEscapesRawHTML(t *testing.T) {
	markdown := "## 标题\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n```http\nGET / HTTP/1.1\n```\n\n<script>alert(1)</script>"
	html := renderReportMarkdownHTML(markdown)
	for _, want := range []string{`<h2 id="标题">标题</h2>`, "<table>", "<pre><code", "GET / HTTP/1.1"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML 缺少 %q: %s", want, html)
		}
	}
	if strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("原始 HTML 未被转义: %s", html)
	}
	documentMarkdown := markdown + "\n\n## 4. 漏洞详情\n\n详情"
	document := reportHTMLDocument(
		&database.Project{ID: "project-test", Name: "测试项目", Scope: "10.0.0.0/24"},
		documentMarkdown,
		[]database.Vulnerability{{ID: "vuln-1", Severity: "high"}},
		time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC),
	)
	for _, want := range []string{
		"data:image/png;base64,",
		"SOPHON",
		"Sophon 智能安全助手",
		"授权与免责声明",
		"合法授权",
		"cover-band",
		"报告编号",
		"10.0.0.0/24",
		`h2[id="目录"]`,
		"page-break-before: auto",
		"text-align: left",
		`h2[id="4-漏洞详情"]`,
		`h2[id="目录"] + ul`,
		"severity-chart",
		"漏洞严重程度分布",
		"severity-chart-row tone-high",
	} {
		if !strings.Contains(document, want) {
			t.Fatalf("PDF HTML 缺少 %q", want)
		}
	}
	if strings.Contains(document, "page-footer") {
		t.Fatal("PDF HTML 不应再包含重复页脚")
	}
	if strings.Contains(document, "cover-metrics") {
		t.Fatal("PDF 封面不应再包含重复指标块")
	}
}

func TestRenderReportMarkdownFormatsOrderedClauseStyles(t *testing.T) {
	tests := []struct {
		name      string
		markdown  string
		wantLead  string
		wantItems int
	}{
		{name: "fullwidth parenthesis", markdown: "1）第一步。2）第二步。3）第三步。", wantItems: 3},
		{name: "halfwidth parenthesis", markdown: "1) 第一步。2) 第二步。", wantItems: 2},
		{name: "parenthesized", markdown: "（1）第一步。（2）第二步。", wantItems: 2},
		{name: "chinese comma", markdown: "1、第一步。2、第二步。", wantItems: 2},
		{name: "chinese numeral", markdown: "一、第一步。二、第二步。", wantItems: 2},
		{name: "circled", markdown: "①第一步。②第二步。③第三步。④第四步。", wantItems: 4},
		{name: "lead text", markdown: "测试链路：①第一步。②第二步。", wantLead: "测试链路：", wantItems: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			html := renderReportMarkdownHTML(test.markdown)
			if !strings.Contains(html, `<ol class="report-clause-list">`) {
				t.Fatalf("编号未转换为列表: %s", html)
			}
			if strings.Count(html, "<li>") != test.wantItems {
				t.Fatalf("列表数量错误: %s", html)
			}
			if test.wantLead != "" && !strings.Contains(html, "<p>"+test.wantLead+"</p>") {
				t.Fatalf("引导文字未保留: %s", html)
			}
		})
	}
}

func TestRenderReportMarkdownFormatsBulletSymbols(t *testing.T) {
	html := renderReportMarkdownHTML("• 第一项\n● 第二项\n▪ 第三项")
	if !strings.Contains(html, "<ul>") || strings.Count(html, "<li>") != 3 {
		t.Fatalf("项目符号未转换为列表: %s", html)
	}
}

func TestRenderReportMarkdownDoesNotRewriteCodeBlockLists(t *testing.T) {
	html := renderReportMarkdownHTML("```text\n1）第一步\n2）第二步\n```")
	if strings.Contains(html, "report-clause-list") || !strings.Contains(html, "<pre><code") {
		t.Fatalf("代码块中的编号不应转换为列表: %s", html)
	}
}

func TestRenderReportMarkdownEmbedsDataImages(t *testing.T) {
	html := renderReportMarkdownHTML(
		"![复现截图](data:image/png;base64,AAAA)\n\n![不可用](/api/vulnerabilities/vuln-1/reproduction-images/image-1)",
	)
	if !strings.Contains(html, `<img class="report-image" src="data:image/png;base64,AAAA" alt="复现截图">`) {
		t.Fatalf("data 图片未渲染: %s", html)
	}
	if !strings.Contains(html, "图片不可用") || strings.Contains(html, `src="/api/vulnerabilities`) {
		t.Fatalf("未解析图片不应加载外部地址: %s", html)
	}
}

func TestRenderProjectReportPDF(t *testing.T) {
	if _, err := exec.LookPath("chromium"); err != nil {
		t.Skip("当前环境未安装 Chromium")
	}
	pdf, err := renderProjectReportPDF(
		t.Context(),
		&database.Project{Name: "PDF 测试", Scope: "10.0.0.0/24"},
		"# PDF 测试\n\n这是一段中文。\n\n| 资产 | 风险 |\n|---|---|\n| example.com | 高 |",
		nil,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
		t.Fatal("输出不是有效 PDF")
	}
}

func TestBuildProjectReportPackage(t *testing.T) {
	if _, err := exec.LookPath("chromium"); err != nil {
		t.Skip("当前环境未安装 Chromium")
	}
	project := &database.Project{ID: "project-package", Name: "报告包测试"}
	assets := []database.Asset{{ID: "asset-1", Name: "门户", Kind: "url", Value: "https://example.com"}}
	findings := []database.Vulnerability{{ID: "vuln-1", AssetID: "asset-1", Title: "测试漏洞", Severity: "high", Status: "confirmed"}}
	markdown := buildProjectReportMarkdown(project, assets, findings, nil, time.Now().UTC())
	data, err := buildProjectReportPackage(project, assets, findings, markdown, markdown, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, file := range reader.File {
		found[file.Name] = true
	}
	for _, name := range []string{
		"报告包测试-风险评估报告.md",
		"报告包测试-风险评估报告.pdf",
		"assets.csv",
		"vulnerabilities.csv",
		"manifest.json",
	} {
		if !found[name] {
			t.Fatalf("报告包缺少 %s", name)
		}
	}
}

func TestProductionReportPDFSmoke(t *testing.T) {
	dbPath := strings.TrimSpace(os.Getenv("SOPHON_REPORT_SMOKE_DB"))
	projectID := strings.TrimSpace(os.Getenv("SOPHON_REPORT_SMOKE_PROJECT_ID"))
	outputPath := strings.TrimSpace(os.Getenv("SOPHON_REPORT_SMOKE_OUTPUT"))
	if dbPath == "" || projectID == "" || outputPath == "" {
		t.Skip("未设置生产报告冒烟测试参数")
	}
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := t.Context()
	var ownerID string
	if err := db.QueryRowContext(
		ctx,
		`SELECT owner_user_id FROM projects WHERE id = ?`,
		projectID,
	).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	project, err := db.GetProject(ctx, projectID, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	assets, err := db.ListProjectAssets(ctx, projectID, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	handler := &ProjectHandler{db: db}
	findings, err := handler.exportVulnerabilities(ctx, projectID, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := db.ProjectCoverage(ctx, projectID, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	generatedAt := time.Now().UTC()
	markdown := buildProjectReportMarkdown(project, assets, findings, coverage, generatedAt)
	pdf, err := renderProjectReportPDF(ctx, project, markdown, findings, generatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, pdf, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("report generated: %s assets=%d findings=%d bytes=%d", outputPath, len(assets), len(findings), len(pdf))
}

func TestProjectReportPreviewAndMarkdownCSVExports(t *testing.T) {
	handler, _ := openExportTestEnv(t)
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/projects/project-export/report", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "project-export"}}
	ctx.Set("sophon.user", &database.User{ID: "user-1", Username: "user-1"})
	handler.ReportPreview(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("报告预览失败: %d %s", recorder.Code, recorder.Body.String())
	}
	var preview projectReportPreviewResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &preview); err != nil {
		t.Fatalf("解析报告预览失败: %v", err)
	}
	if !strings.Contains(preview.Markdown, "# 导出<测试>项目风险评估报告") {
		t.Fatalf("预览 Markdown 不完整: %s", preview.Markdown)
	}
	if preview.VulnerabilitiesCSVName != "vulnerabilities.csv" {
		t.Fatalf("漏洞清单文件名错误: %s", preview.VulnerabilitiesCSVName)
	}

	markdown := runProjectExport(t, handler, "user-1", "?format=md")
	if markdown.Code != http.StatusOK ||
		!strings.Contains(markdown.Header().Get("Content-Type"), "text/markdown") ||
		!strings.Contains(markdown.Body.String(), "## 4. 漏洞详情") {
		t.Fatalf("Markdown 导出失败: %d %s", markdown.Code, markdown.Body.String())
	}
	assets := runProjectExport(t, handler, "user-1", "?format=csv")
	if assets.Code != http.StatusOK || !bytes.HasPrefix(assets.Body.Bytes(), []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatalf("资产 CSV 导出失败: %d %s", assets.Code, assets.Body.String())
	}
	vulnerabilities := runProjectExport(t, handler, "user-1", "?format=vulnerabilities")
	if vulnerabilities.Code != http.StatusOK ||
		!bytes.HasPrefix(vulnerabilities.Body.Bytes(), []byte{0xEF, 0xBB, 0xBF}) ||
		!strings.Contains(vulnerabilities.Body.String(), "漏洞地址") {
		t.Fatalf("漏洞 CSV 导出失败: %d %s", vulnerabilities.Code, vulnerabilities.Body.String())
	}
}
