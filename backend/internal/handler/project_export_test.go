package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"sophon/internal/database"

	"github.com/gin-gonic/gin"
)

func openExportTestEnv(t *testing.T) (*ProjectHandler, *database.DB) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "project-export.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().UTC()
	if err := db.CreateProject(ctx, database.Project{
		ID:          "project-export",
		OwnerUserID: "user-1",
		Name:        "导出<测试>项目",
		Status:      "active",
		Goals:       "验证导出",
		Scope:       "10.0.0.0/24",
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	if err := db.CreateAsset(ctx, database.Asset{
		ID: "asset-1", ProjectID: "project-export", OwnerUserID: "user-1",
		Name: "Web 主机", Kind: "url", Value: "https://a.com/x?id=1",
		Status: "active", Criticality: "high", RiskScore: 80,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建资产失败: %v", err)
	}
	if err := db.CreateVulnerability(ctx, database.Vulnerability{
		ID: "vuln-1", ProjectID: "project-export", AssetID: "asset-1", OwnerUserID: "user-1",
		Title: "SQL 注入 & 风险", Severity: "high", Status: "confirmed",
		VulnerabilityType: "SQL Injection",
		Target:            "https://a.com/x?id=1", Description: "描述<b>",
		Preconditions:     "无需登录即可访问",
		ReproductionSteps: "步骤1\n步骤2",
		Evidence:          "sqlmap payload",
		EvidenceRefs:      []string{"conversation:1", "tool:sqlmap:1"},
		Impact:            "数据库数据可能泄露",
		Recommendation:    "使用参数化查询",
		RetestNotes:       "只读验证，未产生数据残留",
		CreatedAt:         now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	return &ProjectHandler{db: db}, db
}

func runProjectExport(
	t *testing.T,
	handler *ProjectHandler,
	userID string,
	query string,
) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(
		http.MethodGet,
		"/api/projects/project-export/export"+query,
		nil,
	)
	ctx.Params = gin.Params{{Key: "id", Value: "project-export"}}
	ctx.Set("sophon.user", &database.User{ID: userID, Username: userID})
	handler.Export(ctx)
	return recorder
}

func TestProjectExportDocxPackage(t *testing.T) {
	handler, db := openExportTestEnv(t)
	recorder := runProjectExport(t, handler, "user-1", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("导出失败: %d %s", recorder.Code, recorder.Body.String())
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.Contains(contentType, "wordprocessingml") {
		t.Fatalf("Content-Type 应为 docx，实际 %s", contentType)
	}
	disposition := recorder.Header().Get("Content-Disposition")
	if !strings.Contains(disposition, "filename*=UTF-8''") ||
		!strings.Contains(disposition, url.PathEscape("导出-测试-项目-实网攻防演习问题隐患报告")) {
		t.Fatalf("下载文件名应按项目名称生成，实际 %s", disposition)
	}
	body := recorder.Body.Bytes()
	if len(body) < 4 || string(body[:2]) != "PK" {
		t.Fatalf("导出内容应为 ZIP/OOXML 包")
	}
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("解析 docx 包失败: %v", err)
	}
	found := map[string]bool{}
	document := ""
	for _, file := range reader.File {
		found[file.Name] = true
		if file.Name != "word/document.xml" {
			continue
		}
		document = readZipPart(t, file)
	}
	for _, name := range []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"word/document.xml",
		"word/styles.xml",
		"word/settings.xml",
		"word/header1.xml",
		"word/footer1.xml",
		"word/_rels/document.xml.rels",
		"docProps/core.xml",
		"docProps/app.xml",
	} {
		if !found[name] {
			t.Fatalf("docx 包缺少 %s", name)
		}
	}
	for _, name := range []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"word/document.xml",
		"word/styles.xml",
		"word/settings.xml",
		"word/header1.xml",
		"word/footer1.xml",
		"word/_rels/document.xml.rels",
		"docProps/core.xml",
		"docProps/app.xml",
	} {
		assertXMLPart(t, reader, name)
	}
	for _, want := range []string{
		"导出&lt;测试&gt;项目",
		"实网攻防演习问题隐患报告",
		"文档控制",
		"摘要",
		"关键词",
		"目录",
		"图表清单",
		"1 引言",
		"2 评估方法与过程",
		"3 资产与暴露面",
		"4 漏洞发现与统计分析",
		"5 漏洞分析",
		"5.2 高危漏洞",
		fmt.Sprintf("VUL-%d-001", time.Now().UTC().Year()),
		"5.2.1 ",
		"6 修复优先级与处置建议",
		"7 复测与闭环计划",
		"8 结论",
		"附录A 证据索引",
		"附录B 复现与IL证据",
		"附录C 术语与缩写",
		"附录D 工具、数据与限制说明",
		"完整复现步骤与请求",
		"完整标题",
		"CWE",
		"TOC \\o",
		"headerReference",
		"footerReference",
		"Web 主机",
		"SQL 注入 &amp; 风险",
		"SQL Injection",
		"步骤1",
		"步骤2",
		"sqlmap payload",
		"conversation:1",
		"tool:sqlmap:1",
		"使用参数化查询",
		"只读验证，未产生数据残留",
	} {
		if !strings.Contains(document, want) {
			t.Fatalf("文档缺少 %q", want)
		}
	}
	for _, obsolete := range []string{"3 漏洞台账", "4 漏洞详情", "4.1 漏洞01", "7.1 证据索引"} {
		if strings.Contains(document, obsolete) {
			t.Fatalf("文档不应继续包含旧版结构 %q", obsolete)
		}
	}
	if !strings.Contains(document, `w:top="1417" w:right="1417" w:bottom="1417" w:left="1701"`) {
		t.Fatalf("页面边距不符合报告规范")
	}
	if !strings.Contains(readNamedZipPart(t, reader, "word/styles.xml"), `w:line="360"`) {
		t.Fatalf("报告未设置正文1.5倍行距")
	}
	if !strings.Contains(document, `w:sz w:val="21"`) {
		t.Fatalf("表格未使用五号字体")
	}
	if !strings.Contains(document, "<w:tblHeader/>") {
		t.Fatalf("跨页表格未重复表头")
	}
	if got := maxDocxTableColumns(document); got > 6 {
		t.Fatalf("报告表格超过六列: %d", got)
	}
	if strings.Contains(document, "[图") {
		t.Fatalf("无真实截图时不应生成图片占位符")
	}
	if !strings.Contains(docxIssueHeading("4.2 漏洞02：测试", true), "<w:pageBreakBefore/>") {
		t.Fatalf("漏洞章节应使用标题前分页")
	}
	for want, part := range map[string]string{
		"导出&lt;测试&gt;项目 实网攻防演习问题隐患报告  |  机密": "word/header1.xml",
		"NUMPAGES":       "word/footer1.xml",
		"updateFields":   "word/settings.xml",
		"导出&lt;测试&gt;项目": "docProps/core.xml",
	} {
		if !strings.Contains(readNamedZipPart(t, reader, part), want) {
			t.Fatalf("%s 缺少 %q", part, want)
		}
	}

	var auditCount int
	if err := db.QueryRowContext(
		context.Background(),
		`SELECT COUNT(*) FROM audit_logs WHERE action = 'project.export'`,
	).Scan(&auditCount); err != nil {
		t.Fatalf("查询导出审计失败: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("应记录 1 条导出审计，实际 %d", auditCount)
	}
}

var docxTableGridPattern = regexp.MustCompile(`(?s)<w:tblGrid>(.*?)</w:tblGrid>`)

func maxDocxTableColumns(document string) int {
	maxColumns := 0
	for _, match := range docxTableGridPattern.FindAllStringSubmatch(document, -1) {
		count := strings.Count(match[1], "<w:gridCol")
		if count > maxColumns {
			maxColumns = count
		}
	}
	return maxColumns
}

func readZipPart(t *testing.T, file *zip.File) string {
	t.Helper()
	handle, err := file.Open()
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", file.Name, err)
	}
	defer func() { _ = handle.Close() }()
	raw, err := io.ReadAll(handle)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", file.Name, err)
	}
	return string(raw)
}

func readNamedZipPart(t *testing.T, reader *zip.Reader, name string) string {
	t.Helper()
	for _, file := range reader.File {
		if file.Name == name {
			return readZipPart(t, file)
		}
	}
	t.Fatalf("docx 包缺少 %s", name)
	return ""
}

func assertXMLPart(t *testing.T, reader *zip.Reader, name string) {
	t.Helper()
	content := readNamedZipPart(t, reader, name)
	decoder := xml.NewDecoder(strings.NewReader(content))
	for {
		if _, err := decoder.Token(); err != nil {
			if err == io.EOF {
				return
			}
			t.Fatalf("%s 不是合法 XML: %v", name, err)
		}
	}
}

func TestDocxFindingLabelsAndOrdering(t *testing.T) {
	now := time.Now().UTC()
	findings := []database.Vulnerability{
		{Title: "low", Severity: "low", Status: "fixed", CreatedAt: now.Add(-time.Hour)},
		{Title: "critical", Severity: "critical", Status: "open", CreatedAt: now.Add(-2 * time.Hour)},
		{Title: "high", Severity: "high", Status: "confirmed", CreatedAt: now},
	}
	sorted := sortDocxVulnerabilities(findings)
	if sorted[0].Title != "critical" || sorted[1].Title != "high" || sorted[2].Title != "low" {
		t.Fatalf("漏洞严重度排序错误: %+v", sorted)
	}
	if docxSeverityLabel("critical") != "严重" ||
		docxSeverityLabel("high") != "高危" ||
		docxStatusLabel("false_positive") != "误报" {
		t.Fatalf("漏洞标签映射错误")
	}
	if docxPercent(1, 3) != "33.3%" {
		t.Fatalf("百分比格式错误: %s", docxPercent(1, 3))
	}
}

func TestProjectExportFileName(t *testing.T) {
	generatedAt := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	got := projectExportFileName(` 代码/审计:*?"<>| 项目 `, "docx", generatedAt)
	want := "代码-审计------- 项目-实网攻防演习问题隐患报告-20261110.docx"
	if got != want {
		t.Fatalf("项目文件名不符: got=%q want=%q", got, want)
	}
	if fallback := projectExportFileName("...", "json", generatedAt); fallback != "项目安全评估报告-实网攻防演习问题隐患报告-20261110.json" {
		t.Fatalf("空项目名回退不符: %q", fallback)
	}
}

func TestDocxRichTextFormatsSections(t *testing.T) {
	block := docxRichText(
		"漏洞位置：src/WebSite/test.aspx\n\n"+
			"1) 检查入口\n"+
			"2) 验证参数\n\n"+
			"```http\n"+
			"GET / HTTP/1.1\n"+
			"Host: target\n"+
			"```",
		"",
	)
	if strings.Contains(block, "```") || !strings.Contains(block, "GET / HTTP/1.1") {
		t.Fatalf("技术内容未正确清理代码围栏")
	}
	if strings.Contains(block, "<w:cantSplit/>") {
		t.Fatalf("技术内容应允许跨页")
	}
	if strings.Count(block, "<w:p>") < 4 {
		t.Fatalf("不同内容行应拆成独立段落: %s", block)
	}
	if !strings.Contains(block, "1) 检查入口") || !strings.Contains(block, "2) 验证参数") {
		t.Fatalf("编号内容未保留为独立条目")
	}
	if strings.Contains(block, "**") || strings.Contains(block, "`") {
		t.Fatalf("正文不应残留 Markdown 标记")
	}
	code := docxCodeBlock("GET / HTTP/1.1")
	if strings.Contains(code, "<w:tbl>") {
		t.Fatalf("代码块不应使用表格承载")
	}
}

func TestDocxEvidenceIndexAndCompactText(t *testing.T) {
	findings := []database.Vulnerability{
		{ID: "vuln-1", EvidenceRefs: []string{"fact:one", "tool:scan:1", "fact:one"}},
		{ID: "vuln-2", EvidenceRefs: []string{"artifact:proof.txt", "fact:one"}},
	}
	index := buildDocxEvidenceIndex(findings, map[string]string{
		"vuln-1": "VUL-2026-001",
		"vuln-2": "VUL-2026-002",
	})
	if len(index.Items) != 3 || index.ByRef["fact:one"].Code != "E001" ||
		index.ByRef["artifact:proof.txt"].Kind != "产物" {
		t.Fatalf("证据索引生成错误: %+v", index)
	}
	if !stringSliceContains(index.ByRef["fact:one"].Findings, "VUL-2026-001") ||
		!stringSliceContains(index.ByRef["fact:one"].Findings, "VUL-2026-002") ||
		index.ByRef["fact:one"].Purpose == "" {
		t.Fatalf("证据关联漏洞或用途缺失: %+v", index.ByRef["fact:one"])
	}
	if got := docxCompactText("1234567890", 6); got != "12345…" {
		t.Fatalf("标题截断错误: %q", got)
	}
}

func TestDocxIssueGroupsUseStableCodesAndTypeOrder(t *testing.T) {
	now := time.Now().UTC()
	groups, codes := buildDocxIssueGroups([]database.Vulnerability{
		{ID: "high-upload", Title: "上传漏洞", Severity: "high", VulnerabilityType: "Upload", UpdatedAt: now},
		{ID: "critical-command", Title: "命令执行", Severity: "critical", VulnerabilityType: "Command Injection", UpdatedAt: now},
		{ID: "high-sql", Title: "SQL 注入", Severity: "high", VulnerabilityType: "SQL Injection", UpdatedAt: now.Add(time.Hour)},
	}, 2026)
	issues := docxFlattenIssues(groups)
	if len(issues) != 3 ||
		issues[0].Code != "VUL-2026-001" ||
		issues[0].Section != "5.1.1" ||
		issues[1].Code != "VUL-2026-002" ||
		issues[2].Code != "VUL-2026-003" ||
		issues[1].Item.VulnerabilityType != "SQL Injection" ||
		issues[2].Item.VulnerabilityType != "Upload" {
		t.Fatalf("漏洞编号或类型排序错误: %+v", issues)
	}
	if codes["high-sql"] != "VUL-2026-002" || codes["high-upload"] != "VUL-2026-003" {
		t.Fatalf("漏洞编号映射错误: %+v", codes)
	}
}

func TestDocxReportSafeText(t *testing.T) {
	got := docxReportSafeText("攻击者使用攻击工具测试攻击目标")
	if strings.Contains(got, "攻击") || !strings.Contains(got, "未授权人员") {
		t.Fatalf("报告术语替换不完整: %q", got)
	}
}

func TestProjectExportJSONAndTenantIsolation(t *testing.T) {
	handler, _ := openExportTestEnv(t)
	recorder := runProjectExport(t, handler, "user-1", "?format=json")
	if recorder.Code != http.StatusOK {
		t.Fatalf("JSON 导出失败: %d %s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Project struct {
			ID string `json:"id"`
		} `json:"project"`
		Assets []struct {
			ID string `json:"id"`
		} `json:"assets"`
		Vulnerabilities []struct {
			ID string `json:"id"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("解析 JSON 导出失败: %v", err)
	}
	if payload.Project.ID != "project-export" ||
		len(payload.Assets) != 1 ||
		len(payload.Vulnerabilities) != 1 {
		t.Fatalf("JSON 导出内容不完整: %+v", payload)
	}

	other := runProjectExport(t, handler, "user-2", "")
	if other.Code == http.StatusOK {
		t.Fatalf("其他用户不应导出成功")
	}
}
