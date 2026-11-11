package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"sophon/internal/database"
	"sophon/internal/middleware"

	"github.com/gin-gonic/gin"
)

const (
	docxContentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	exportBatchSize = 1000
)

// Export 导出项目资产与漏洞：默认生成 Office Open XML（.docx），format=json 时返回结构化数据。
func (h *ProjectHandler) Export(c *gin.Context) {
	project, ok := h.projectForRequest(c)
	if !ok {
		return
	}
	user := middleware.UserFromContext(c)
	if user == nil {
		unauthorized(c)
		return
	}
	ctx := c.Request.Context()
	assets, err := h.db.ListProjectAssets(ctx, project.ID, user.ID)
	if err != nil {
		internalError(c, "project_export_failed", "读取项目资产失败")
		return
	}
	findings, err := h.exportVulnerabilities(ctx, project.ID, user.ID)
	if err != nil {
		internalError(c, "project_export_failed", "读取项目漏洞失败")
		return
	}

	format := strings.ToLower(strings.TrimSpace(c.DefaultQuery("format", "docx")))
	generatedAt := time.Now().UTC()
	switch format {
	case "json":
		setProjectExportHeaders(
			c,
			projectExportFileName(project.Name, "json", generatedAt),
			"project-export-"+generatedAt.Format("20060102")+".json",
		)
		c.JSON(http.StatusOK, gin.H{
			"project":         project,
			"assets":          assets,
			"vulnerabilities": findings,
			"exportedAt":      generatedAt,
		})
	default:
		document, buildErr := buildProjectDocx(project, assets, findings)
		if buildErr != nil {
			internalError(c, "project_export_failed", "生成导出文档失败")
			return
		}
		setProjectExportHeaders(
			c,
			projectExportFileName(project.Name, "docx", generatedAt),
			"project-export-"+generatedAt.Format("20060102")+".docx",
		)
		c.Data(http.StatusOK, docxContentType, document)
	}

	_ = h.db.AddAuditLog(ctx, database.AuditLog{
		UserID:       user.ID,
		Username:     user.Username,
		Action:       "project.export",
		ResourceType: "project",
		ResourceID:   project.ID,
		Result:       "success",
		Detail: fmt.Sprintf(
			"format=%s assets=%d vulnerabilities=%d",
			format,
			len(assets),
			len(findings),
		),
	})
}

func setProjectExportHeaders(c *gin.Context, filename, fallback string) {
	c.Header(
		"Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, fallback, url.PathEscape(filename)),
	)
}

func projectExportFileName(projectName, extension string, generatedAt time.Time) string {
	name := sanitizeProjectExportName(projectName)
	return fmt.Sprintf(
		"%s-实网攻防演习问题隐患报告-%s.%s",
		name,
		generatedAt.Format("20060102"),
		extension,
	)
}

func sanitizeProjectExportName(projectName string) string {
	var builder strings.Builder
	runes := 0
	for _, char := range strings.TrimSpace(projectName) {
		if char < 0x20 || strings.ContainsRune(`/\:*?"<>|`, char) {
			char = '-'
		}
		if runes >= 80 {
			break
		}
		builder.WriteRune(char)
		runes++
	}
	name := strings.Trim(builder.String(), " .-")
	if name == "" {
		return "项目安全评估报告"
	}
	return name
}

func (h *ProjectHandler) exportVulnerabilities(
	ctx context.Context,
	projectID string,
	userID string,
) ([]database.Vulnerability, error) {
	filter := database.VulnerabilityFilter{
		OwnerUserID: userID,
		ProjectID:   projectID,
		Limit:       exportBatchSize,
	}
	items := make([]database.Vulnerability, 0, exportBatchSize)
	for offset := 0; ; offset += exportBatchSize {
		filter.Offset = offset
		page, total, err := h.db.ListVulnerabilitiesFiltered(ctx, filter)
		if err != nil {
			return nil, err
		}
		items = append(items, page...)
		if len(page) < exportBatchSize || len(items) >= total {
			break
		}
	}
	return items, nil
}

type docxTextOptions struct {
	bold            bool
	sizeHalfPoints  int
	color           string
	style           string
	alignment       string
	before          int
	after           int
	keepNext        bool
	pageBreakBefore bool
	code            bool
	indent          int
	noFirstLine     bool
	shading         string
}

// buildProjectDocx 生成正式项目安全评估报告（ZIP + XML，无需外部依赖）。
func buildProjectDocx(
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
) ([]byte, error) {
	if project == nil {
		return nil, fmt.Errorf("项目不能为空")
	}
	return buildProfessionalProjectDocx(project, assets, findings)
}

// writeDocxPackage 组装正式 OOXML 包：内容类型、关系、样式、页眉页脚与元数据。
func writeDocxPackage(documentXML, title string, generatedAt time.Time) ([]byte, error) {
	const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
  <Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>
  <Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>`
	const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>`
	const documentRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>
</Relationships>`
	const stylesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault>
      <w:rPr>
        <w:rFonts w:ascii="Times New Roman" w:eastAsia="宋体" w:hAnsi="Times New Roman"/>
        <w:sz w:val="24"/>
        <w:szCs w:val="24"/>
      </w:rPr>
    </w:rPrDefault>
    <w:pPrDefault>
      <w:pPr>
        <w:jc w:val="both"/>
        <w:ind w:firstLine="480"/>
        <w:spacing w:after="0" w:line="360" w:lineRule="auto"/>
      </w:pPr>
    </w:pPrDefault>
  </w:docDefaults>
  <w:style w:type="paragraph" w:default="1" w:styleId="Normal">
    <w:name w:val="Normal"/>
    <w:qFormat/>
    <w:pPr>
      <w:jc w:val="both"/>
      <w:ind w:firstLine="480"/>
      <w:spacing w:after="0" w:line="360" w:lineRule="auto"/>
    </w:pPr>
    <w:rPr>
      <w:rFonts w:ascii="Times New Roman" w:eastAsia="宋体" w:hAnsi="Times New Roman"/>
      <w:sz w:val="24"/>
      <w:szCs w:val="24"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Title">
    <w:name w:val="Title"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:qFormat/>
    <w:pPr>
      <w:jc w:val="center"/>
      <w:ind w:firstLine="0"/>
      <w:spacing w:before="0" w:after="240"/>
    </w:pPr>
    <w:rPr>
      <w:rFonts w:ascii="Times New Roman" w:eastAsia="Microsoft YaHei" w:hAnsi="Times New Roman"/>
      <w:color w:val="000000"/>
      <w:sz w:val="44"/>
      <w:szCs w:val="44"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Subtitle">
    <w:name w:val="Subtitle"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:qFormat/>
    <w:pPr>
      <w:jc w:val="center"/>
      <w:ind w:firstLine="0"/>
      <w:spacing w:after="240"/>
    </w:pPr>
    <w:rPr>
      <w:color w:val="475467"/>
      <w:sz w:val="24"/>
      <w:szCs w:val="24"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="heading 1"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:qFormat/>
    <w:pPr>
      <w:keepNext/>
      <w:keepLines/>
      <w:ind w:firstLine="0"/>
      <w:spacing w:before="360" w:after="180"/>
      <w:outlineLvl w:val="0"/>
    </w:pPr>
    <w:rPr>
      <w:rFonts w:ascii="Times New Roman" w:eastAsia="Microsoft YaHei" w:hAnsi="Times New Roman"/>
      <w:color w:val="000000"/>
      <w:sz w:val="32"/>
      <w:szCs w:val="32"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="heading 2"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:qFormat/>
    <w:pPr>
      <w:keepNext/>
      <w:keepLines/>
      <w:ind w:firstLine="0"/>
      <w:spacing w:before="240" w:after="120"/>
      <w:outlineLvl w:val="1"/>
    </w:pPr>
    <w:rPr>
      <w:rFonts w:ascii="Times New Roman" w:eastAsia="Microsoft YaHei" w:hAnsi="Times New Roman"/>
      <w:color w:val="000000"/>
      <w:sz w:val="28"/>
      <w:szCs w:val="28"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading3">
    <w:name w:val="heading 3"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:qFormat/>
    <w:pPr>
      <w:keepNext/>
      <w:ind w:firstLine="0"/>
      <w:spacing w:before="180" w:after="80"/>
      <w:outlineLvl w:val="2"/>
    </w:pPr>
    <w:rPr>
      <w:rFonts w:ascii="Times New Roman" w:eastAsia="Microsoft YaHei" w:hAnsi="Times New Roman"/>
      <w:color w:val="000000"/>
      <w:sz w:val="24"/>
      <w:szCs w:val="24"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Caption">
    <w:name w:val="Caption"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:qFormat/>
    <w:pPr>
      <w:jc w:val="center"/>
      <w:ind w:firstLine="0"/>
      <w:spacing w:before="80" w:after="80"/>
    </w:pPr>
    <w:rPr>
      <w:color w:val="667085"/>
      <w:i/>
      <w:sz w:val="20"/>
      <w:szCs w:val="20"/>
    </w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Code">
    <w:name w:val="Code"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr>
      <w:jc w:val="left"/>
      <w:spacing w:before="40" w:after="80" w:line="300" w:lineRule="auto"/>
      <w:ind w:firstLine="0"/>
    </w:pPr>
    <w:rPr>
      <w:rFonts w:ascii="Consolas" w:eastAsia="Arial Unicode MS" w:hAnsi="Consolas"/>
      <w:color w:val="344054"/>
      <w:sz w:val="18"/>
      <w:szCs w:val="18"/>
    </w:rPr>
  </w:style>
</w:styles>`
	const settingsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:zoom w:percent="100"/>
  <w:updateFields w:val="true"/>
  <w:compat>
    <w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/>
  </w:compat>
</w:settings>`
	headerXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:p>
    <w:pPr>
      <w:pBdr><w:bottom w:val="single" w:sz="4" w:space="4" w:color="CBD5E1"/></w:pBdr>
      <w:jc w:val="right"/>
      <w:spacing w:after="0"/>
    </w:pPr>
    <w:r>
      <w:rPr><w:color w:val="667085"/><w:sz w:val="16"/></w:rPr>
      <w:t>%s  |  机密</w:t>
    </w:r>
  </w:p>
</w:hdr>`, docxEscape(title))
	const footerXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:p>
    <w:pPr>
      <w:pBdr><w:top w:val="single" w:sz="4" w:space="4" w:color="CBD5E1"/></w:pBdr>
      <w:tabs><w:tab w:val="right" w:pos="9026"/></w:tabs>
      <w:spacing w:before="0" w:after="0"/>
    </w:pPr>
    <w:r>
      <w:rPr><w:color w:val="667085"/><w:sz w:val="16"/></w:rPr>
      <w:t>机密 · CONFIDENTIAL</w:t>
    </w:r>
    <w:r><w:tab/></w:r>
    <w:r>
      <w:rPr><w:color w:val="667085"/><w:sz w:val="16"/></w:rPr>
      <w:t>第 </w:t>
    </w:r>
    <w:fldSimple w:instr=" PAGE ">
      <w:r><w:rPr><w:color w:val="667085"/><w:sz w:val="16"/></w:rPr><w:t>1</w:t></w:r>
    </w:fldSimple>
    <w:r>
      <w:rPr><w:color w:val="667085"/><w:sz w:val="16"/></w:rPr>
      <w:t> 页 / 共 </w:t>
    </w:r>
    <w:fldSimple w:instr=" NUMPAGES ">
      <w:r><w:rPr><w:color w:val="667085"/><w:sz w:val="16"/></w:rPr><w:t>1</w:t></w:r>
    </w:fldSimple>
    <w:r>
      <w:rPr><w:color w:val="667085"/><w:sz w:val="16"/></w:rPr>
      <w:t> 页</w:t>
    </w:r>
  </w:p>
</w:ftr>`
	coreXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>%s</dc:title>
  <dc:subject>实网攻防演习问题隐患报告</dc:subject>
  <dc:creator>Sophon Security Platform</dc:creator>
  <cp:lastModifiedBy>Sophon Security Platform</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">%s</dcterms:modified>
</cp:coreProperties>`,
		docxEscape(title),
		generatedAt.Format(time.RFC3339),
		generatedAt.Format(time.RFC3339),
	)
	const appXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Sophon Security Platform</Application>
  <AppVersion>1.0</AppVersion>
  <Company>Sophon</Company>
</Properties>`

	buffer := &bytes.Buffer{}
	writer := zip.NewWriter(buffer)
	files := []struct {
		name    string
		content string
	}{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rootRels},
		{"word/document.xml", documentXML},
		{"word/_rels/document.xml.rels", documentRels},
		{"word/styles.xml", stylesXML},
		{"word/settings.xml", settingsXML},
		{"word/header1.xml", headerXML},
		{"word/footer1.xml", footerXML},
		{"docProps/core.xml", coreXML},
		{"docProps/app.xml", appXML},
	}
	for _, file := range files {
		entry, err := writer.Create(file.name)
		if err != nil {
			_ = writer.Close()
			return nil, err
		}
		if _, err := entry.Write([]byte(file.content)); err != nil {
			_ = writer.Close()
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

type docxTextRun struct {
	text string
	bold bool
	code bool
}

func docxParagraph(text string, options docxTextOptions) string {
	return docxParagraphRuns([]docxTextRun{{text: text}}, options)
}

func docxParagraphRuns(runs []docxTextRun, options docxTextOptions) string {
	var paragraphProperties strings.Builder
	paragraphProperties.WriteString("<w:pPr>")
	if options.style != "" {
		paragraphProperties.WriteString(fmt.Sprintf(`<w:pStyle w:val="%s"/>`, docxEscape(options.style)))
	}
	if options.keepNext {
		paragraphProperties.WriteString("<w:keepNext/>")
	}
	if options.pageBreakBefore {
		paragraphProperties.WriteString("<w:pageBreakBefore/>")
	}
	if options.alignment != "" {
		paragraphProperties.WriteString(fmt.Sprintf(`<w:jc w:val="%s"/>`, docxEscape(options.alignment)))
	}
	before := options.before
	if before == 0 {
		before = 80
	}
	after := options.after
	if after == 0 {
		after = 40
	}
	paragraphProperties.WriteString(fmt.Sprintf(`<w:spacing w:before="%d" w:after="%d"/>`, before, after))
	if options.indent > 0 || options.noFirstLine {
		paragraphProperties.WriteString("<w:ind")
		if options.indent > 0 {
			paragraphProperties.WriteString(fmt.Sprintf(` w:left="%d"`, options.indent))
		}
		if options.noFirstLine {
			paragraphProperties.WriteString(` w:firstLine="0"`)
		}
		paragraphProperties.WriteString("/>")
	}
	if options.shading != "" {
		paragraphProperties.WriteString(fmt.Sprintf(`<w:shd w:val="clear" w:color="auto" w:fill="%s"/>`, docxEscape(options.shading)))
	}
	paragraphProperties.WriteString("</w:pPr>")

	var body strings.Builder
	wroteContent := false
	for _, run := range runs {
		runProperties := docxRunProperties(options, run)
		for index, line := range strings.Split(run.text, "\n") {
			if index > 0 {
				body.WriteString(`<w:r><w:br/></w:r>`)
			}
			if line == "" {
				continue
			}
			body.WriteString(`<w:r>` + runProperties + `<w:t xml:space="preserve">` + docxEscape(line) + `</w:t></w:r>`)
			wroteContent = true
		}
	}
	if !wroteContent {
		body.WriteString(`<w:r>` + docxRunProperties(options, docxTextRun{}) + `</w:r>`)
	}
	return `<w:p>` + paragraphProperties.String() + body.String() + `</w:p>`
}

func docxRunProperties(options docxTextOptions, run docxTextRun) string {
	var runProperties strings.Builder
	runProperties.WriteString("<w:rPr>")
	if options.code || run.code {
		runProperties.WriteString(`<w:rFonts w:ascii="Consolas" w:eastAsia="Arial Unicode MS" w:hAnsi="Consolas"/>`)
	}
	if options.bold || run.bold {
		runProperties.WriteString("<w:b/>")
	}
	if options.color != "" {
		runProperties.WriteString(fmt.Sprintf(`<w:color w:val="%s"/>`, docxEscape(options.color)))
	}
	if options.sizeHalfPoints > 0 {
		runProperties.WriteString(fmt.Sprintf(`<w:sz w:val="%d"/>`, options.sizeHalfPoints))
	}
	runProperties.WriteString("</w:rPr>")
	return runProperties.String()
}

type docxTableOptions struct {
	widths        []int
	headerFill    string
	zebraFill     string
	borderColor   string
	allowRowSplit bool
}

func docxTableWithOptions(headers []string, rows [][]string, options docxTableOptions) string {
	widths := append([]int(nil), options.widths...)
	if len(widths) != len(headers) {
		widths = make([]int, len(headers))
		for index := range widths {
			widths[index] = 1800
		}
	}
	headerFill := options.headerFill
	if headerFill == "" {
		headerFill = "0B7285"
	}
	zebraFill := options.zebraFill
	if zebraFill == "" {
		zebraFill = "F2F7FA"
	}
	borderColor := options.borderColor
	if borderColor == "" {
		borderColor = "CBD5E1"
	}

	var builder strings.Builder
	builder.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblLayout w:type="fixed"/><w:tblBorders>` +
		fmt.Sprintf(`<w:top w:val="single" w:sz="10" w:color="%s"/>`, borderColor) +
		fmt.Sprintf(`<w:left w:val="nil" w:color="%s"/>`, borderColor) +
		fmt.Sprintf(`<w:bottom w:val="single" w:sz="10" w:color="%s"/>`, borderColor) +
		fmt.Sprintf(`<w:right w:val="nil" w:color="%s"/>`, borderColor) +
		fmt.Sprintf(`<w:insideH w:val="nil" w:color="%s"/>`, borderColor) +
		fmt.Sprintf(`<w:insideV w:val="nil" w:color="%s"/>`, borderColor) +
		`</w:tblBorders><w:tblCellMar>` +
		`<w:top w:w="80" w:type="dxa"/><w:left w:w="100" w:type="dxa"/>` +
		`<w:bottom w:w="80" w:type="dxa"/><w:right w:w="100" w:type="dxa"/>` +
		`</w:tblCellMar></w:tblPr><w:tblGrid>`)
	for _, width := range widths {
		builder.WriteString(fmt.Sprintf(`<w:gridCol w:w="%d"/>`, width))
	}
	builder.WriteString(`</w:tblGrid>`)
	builder.WriteString(docxTableRow(headers, true, widths, headerFill, false))
	for index, row := range rows {
		fill := ""
		if index%2 == 1 {
			fill = zebraFill
		}
		builder.WriteString(docxTableRow(row, false, widths, fill, options.allowRowSplit))
	}
	builder.WriteString(`</w:tbl>`)
	return builder.String()
}

func docxTableRow(cells []string, header bool, widths []int, fill string, allowRowSplit bool) string {
	var builder strings.Builder
	builder.WriteString(`<w:tr>`)
	if header || !allowRowSplit {
		builder.WriteString("<w:trPr>")
		if header {
			builder.WriteString("<w:tblHeader/>")
		}
		if !allowRowSplit {
			builder.WriteString("<w:cantSplit/>")
		}
		builder.WriteString("</w:trPr>")
	}
	for index, cell := range cells {
		width := 1800
		if index < len(widths) {
			width = widths[index]
		}
		builder.WriteString(`<w:tc><w:tcPr>`)
		builder.WriteString(fmt.Sprintf(`<w:tcW w:w="%d" w:type="dxa"/>`, width))
		if header {
			builder.WriteString(fmt.Sprintf(
				`<w:tcBorders><w:bottom w:val="single" w:sz="8" w:color="%s"/></w:tcBorders>`,
				"344054",
			))
		}
		if fill != "" {
			builder.WriteString(fmt.Sprintf(`<w:shd w:val="clear" w:color="auto" w:fill="%s"/>`, fill))
		}
		verticalAlignment := "top"
		if header {
			verticalAlignment = "center"
		}
		builder.WriteString(fmt.Sprintf(`<w:vAlign w:val="%s"/></w:tcPr>`, verticalAlignment))
		options := docxTextOptions{
			sizeHalfPoints: 21,
			before:         60,
			after:          60,
			noFirstLine:    true,
		}
		if header {
			options.bold = true
			options.color = "FFFFFF"
			options.alignment = "center"
		} else {
			options.alignment = "left"
		}
		builder.WriteString(docxParagraph(cell, options))
		builder.WriteString(`</w:tc>`)
	}
	builder.WriteString(`</w:tr>`)
	return builder.String()
}

type docxMetricCard struct {
	label string
	value string
	fill  string
	color string
}

func docxMetricCards(cards []docxMetricCard) string {
	if len(cards) != 4 {
		return ""
	}
	var body strings.Builder
	body.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblLayout w:type="fixed"/><w:tblBorders>` +
		`<w:top w:val="single" w:sz="4" w:color="D0D5DD"/><w:left w:val="single" w:sz="4" w:color="D0D5DD"/>` +
		`<w:bottom w:val="single" w:sz="4" w:color="D0D5DD"/><w:right w:val="single" w:sz="4" w:color="D0D5DD"/>` +
		`<w:insideH w:val="single" w:sz="4" w:color="D0D5DD"/><w:insideV w:val="single" w:sz="4" w:color="D0D5DD"/>` +
		`</w:tblBorders><w:tblCellMar><w:top w:w="120" w:type="dxa"/><w:left w:w="120" w:type="dxa"/>` +
		`<w:bottom w:w="120" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tblCellMar></w:tblPr>` +
		`<w:tblGrid><w:gridCol w:w="2500"/><w:gridCol w:w="2500"/><w:gridCol w:w="2500"/><w:gridCol w:w="2500"/></w:tblGrid>` +
		`<w:tr><w:trPr><w:cantSplit/></w:trPr>`)
	for _, card := range cards {
		body.WriteString(`<w:tc><w:tcPr><w:tcW w:w="2500" w:type="dxa"/>` +
			fmt.Sprintf(`<w:shd w:val="clear" w:color="auto" w:fill="%s"/>`, docxEscape(card.fill)) +
			`<w:vAlign w:val="center"/></w:tcPr>`)
		body.WriteString(docxParagraph(card.value, docxTextOptions{
			bold:           true,
			sizeHalfPoints: 40,
			color:          card.color,
			alignment:      "center",
			before:         80,
			after:          20,
			noFirstLine:    true,
		}))
		body.WriteString(docxParagraph(card.label, docxTextOptions{
			sizeHalfPoints: 18,
			color:          "475467",
			alignment:      "center",
			before:         10,
			after:          80,
			noFirstLine:    true,
		}))
		body.WriteString(`</w:tc>`)
	}
	body.WriteString(`</w:tr></w:tbl>`)
	return body.String()
}

func docxRiskTagStrip(item database.Vulnerability) string {
	severityFill, severityColor := docxSeverityTagStyle(item.Severity)
	statusFill, statusColor := docxStatusTagStyle(item.Status)
	return docxTagStrip([]docxTag{
		{Text: docxSeverityLabel(item.Severity), Fill: severityFill, Color: severityColor},
		{Text: docxStatusLabel(item.Status), Fill: statusFill, Color: statusColor},
		{Text: docxValue(item.VulnerabilityType, "未分类"), Fill: "E0F2FE", Color: "026AA2"},
	})
}

type docxTag struct {
	Text  string
	Fill  string
	Color string
}

func docxTagStrip(tags []docxTag) string {
	widths := []int{1800, 1800, 6400}
	var body strings.Builder
	body.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblLayout w:type="fixed"/><w:tblBorders>` +
		`<w:top w:val="nil"/><w:left w:val="nil"/><w:bottom w:val="nil"/><w:right w:val="nil"/>` +
		`<w:insideH w:val="nil"/><w:insideV w:val="single" w:sz="4" w:color="FFFFFF"/>` +
		`</w:tblBorders><w:tblCellMar><w:top w:w="100" w:type="dxa"/><w:left w:w="100" w:type="dxa"/>` +
		`<w:bottom w:w="100" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>`)
	for _, width := range widths {
		body.WriteString(fmt.Sprintf(`<w:gridCol w:w="%d"/>`, width))
	}
	body.WriteString(`</w:tblGrid><w:tr><w:trPr><w:cantSplit/></w:trPr>`)
	for index, tag := range tags {
		if index >= len(widths) {
			break
		}
		body.WriteString(`<w:tc><w:tcPr>` + fmt.Sprintf(`<w:tcW w:w="%d" w:type="dxa"/>`, widths[index]) +
			fmt.Sprintf(`<w:shd w:val="clear" w:color="auto" w:fill="%s"/>`, docxEscape(tag.Fill)) +
			`<w:vAlign w:val="center"/></w:tcPr>` +
			docxParagraph(tag.Text, docxTextOptions{
				bold:           true,
				sizeHalfPoints: 18,
				color:          tag.Color,
				alignment:      "center",
				before:         20,
				after:          20,
				noFirstLine:    true,
			}) + `</w:tc>`)
	}
	body.WriteString(`</w:tr></w:tbl>`)
	return body.String()
}

// docxEscape 做 XML 转义并剔除非法控制字符，避免破坏文档结构。
func docxEscape(value string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 {
			return r
		}
		return -1
	}, value)
	var builder strings.Builder
	_ = xml.EscapeText(&builder, []byte(cleaned))
	return builder.String()
}

var docxSeverityOrder = []string{"critical", "high", "medium", "low", "info", "unknown"}

var docxStatusOrder = []string{"open", "confirmed", "fixed", "ignored", "false_positive", "unknown"}

type docxEvidenceItem struct {
	Code     string
	Kind     string
	Ref      string
	Purpose  string
	Findings []string
}

type docxEvidenceIndex struct {
	ByRef map[string]docxEvidenceItem
	Items []docxEvidenceItem
}

func buildDocxEvidenceIndex(
	findings []database.Vulnerability,
	issueCodes map[string]string,
) docxEvidenceIndex {
	index := docxEvidenceIndex{ByRef: make(map[string]docxEvidenceItem)}
	for _, item := range findings {
		for _, raw := range item.EvidenceRefs {
			ref := strings.TrimSpace(raw)
			if ref == "" {
				continue
			}
			if existing, exists := index.ByRef[ref]; exists {
				if code := strings.TrimSpace(issueCodes[item.ID]); code != "" &&
					!stringSliceContains(existing.Findings, code) {
					existing.Findings = append(existing.Findings, code)
					index.ByRef[ref] = existing
					for position := range index.Items {
						if index.Items[position].Ref == ref {
							index.Items[position].Findings = existing.Findings
							break
						}
					}
				}
				continue
			}
			entry := docxEvidenceItem{
				Code:    fmt.Sprintf("E%03d", len(index.Items)+1),
				Kind:    docxEvidenceKind(ref),
				Ref:     ref,
				Purpose: docxEvidencePurpose(ref),
			}
			if code := strings.TrimSpace(issueCodes[item.ID]); code != "" {
				entry.Findings = append(entry.Findings, code)
			}
			index.ByRef[ref] = entry
			index.Items = append(index.Items, entry)
		}
	}
	return index
}

func docxEvidencePurpose(ref string) string {
	switch {
	case strings.HasPrefix(strings.ToLower(ref), "fact:"):
		return "支撑环境判断或攻击路径结论"
	case strings.HasPrefix(strings.ToLower(ref), "artifact:"):
		return "保留源码、请求或扫描产物"
	case strings.HasPrefix(strings.ToLower(ref), "conversation:"):
		return "追溯测试过程与人工判断"
	case strings.HasPrefix(strings.ToLower(ref), "tool:"):
		return "证明工具执行及原始输出"
	default:
		return "补充验证依据"
	}
}

func docxEvidenceKind(ref string) string {
	switch {
	case strings.HasPrefix(strings.ToLower(ref), "fact:"):
		return "事实"
	case strings.HasPrefix(strings.ToLower(ref), "artifact:"):
		return "产物"
	case strings.HasPrefix(strings.ToLower(ref), "conversation:"):
		return "会话"
	case strings.HasPrefix(strings.ToLower(ref), "tool:"):
		return "工具"
	default:
		return "其他"
	}
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type docxIssue struct {
	Item    database.Vulnerability
	Code    string
	Section string
}

type docxIssueGroup struct {
	Severity string
	Title    string
	Issues   []docxIssue
}

func buildDocxIssueGroups(
	findings []database.Vulnerability,
	year int,
) ([]docxIssueGroup, map[string]string) {
	sorted := sortDocxVulnerabilities(findings)
	issueCodes := make(map[string]string, len(sorted))
	groups := make([]docxIssueGroup, 0, len(docxSeverityOrder))
	nextIssueNumber := 1
	for _, severity := range docxSeverityOrder {
		group := docxIssueGroup{
			Severity: severity,
			Title:    docxSeverityLabel(severity) + "漏洞",
		}
		for _, item := range sorted {
			if normalizeDocxSeverity(item.Severity) != severity {
				continue
			}
			code := fmt.Sprintf("VUL-%d-%03d", year, nextIssueNumber)
			nextIssueNumber++
			issue := docxIssue{
				Item:    item,
				Code:    code,
				Section: fmt.Sprintf("5.%d.%d", len(groups)+1, len(group.Issues)+1),
			}
			group.Issues = append(group.Issues, issue)
			if item.ID != "" {
				issueCodes[item.ID] = code
			}
		}
		groups = append(groups, group)
	}
	return groups, issueCodes
}

func buildProfessionalProjectDocx(
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
) ([]byte, error) {
	generatedAt := time.Now().UTC()
	issueGroups, issueCodes := buildDocxIssueGroups(findings, generatedAt.Year())
	assetNames := make(map[string]string, len(assets))
	for _, asset := range assets {
		assetNames[asset.ID] = docxValue(asset.Name, asset.Value)
	}
	evidenceIndex := buildDocxEvidenceIndex(findings, issueCodes)

	var body strings.Builder
	body.WriteString(docxCoverPage(project, assets, findings, generatedAt))
	body.WriteString(docxPageBreak())
	body.WriteString(docxDocumentControl(project, generatedAt))
	body.WriteString(docxPageBreak())
	body.WriteString(docxFrontMatter(project, assets, findings, issueGroups))
	body.WriteString(docxPageBreak())
	body.WriteString(docxIntroduction(project, assets, findings))
	body.WriteString(docxMethodology(findings))
	body.WriteString(docxPageBreak())
	body.WriteString(docxAssetExposure(assets, findings, issueGroups, assetNames, evidenceIndex))
	body.WriteString(docxPageBreak())
	body.WriteString(docxFindingStatistics(findings, issueGroups, assetNames))
	body.WriteString(docxPageBreak())
	body.WriteString(docxVulnerabilityAnalysis(issueGroups, assetNames, evidenceIndex))
	body.WriteString(docxPageBreak())
	body.WriteString(docxRemediationAndRetest(issueGroups))
	body.WriteString(docxPageBreak())
	body.WriteString(docxConclusion(project, assets, findings, issueGroups))
	body.WriteString(docxPageBreak())
	body.WriteString(docxReportAppendix(project, issueGroups, evidenceIndex))

	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" ` +
		`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>` +
		body.String() +
		`<w:sectPr>` +
		`<w:headerReference w:type="default" r:id="rId3"/>` +
		`<w:footerReference w:type="default" r:id="rId4"/>` +
		`<w:pgSz w:w="11906" w:h="16838"/>` +
		`<w:pgMar w:top="1417" w:right="1417" w:bottom="1417" w:left="1701" w:header="567" w:footer="567" w:gutter="0"/>` +
		`</w:sectPr>` +
		`</w:body></w:document>`

	return writeDocxPackage(document, project.Name+" 实网攻防演习问题隐患报告", generatedAt)
}

func docxCoverPage(
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
	generatedAt time.Time,
) string {
	var body strings.Builder
	severityCounts := countDocxSeverities(findings)
	statusCounts := countDocxStatuses(findings)
	body.WriteString(docxParagraph("SOPHON", docxTextOptions{
		style:          "Subtitle",
		bold:           true,
		color:          "0B7285",
		sizeHalfPoints: 28,
		alignment:      "center",
		before:         500,
		after:          600,
	}))
	body.WriteString(docxParagraph(project.Name, docxTextOptions{
		style:          "Title",
		bold:           true,
		color:          "102A43",
		sizeHalfPoints: 44,
		alignment:      "center",
		before:         0,
		after:          240,
	}))
	body.WriteString(docxParagraph("实网攻防演习问题隐患报告", docxTextOptions{
		bold:           true,
		color:          "475467",
		sizeHalfPoints: 28,
		alignment:      "center",
		before:         80,
		after:          520,
	}))
	body.WriteString(docxTableWithOptions(
		[]string{"报告信息", "内容"},
		[][]string{
			{"项目状态", docxProjectStatusLabel(project.Status)},
			{"资产范围", docxValue(project.Scope, "未设置")},
			{"资产数量", fmt.Sprintf("%d 个", len(assets))},
			{"漏洞数量", fmt.Sprintf("%d 个", len(findings))},
			{"严重/高危", fmt.Sprintf("%d 个", severityCounts["critical"]+severityCounts["high"])},
			{"已确认", fmt.Sprintf("%d 个", statusCounts["confirmed"])},
			{"报告生成时间", generatedAt.Format("2006-01-02 15:04:05 UTC")},
			{"保密级别", "机密 / 仅限授权人员"},
		},
		docxTableOptions{
			widths:      []int{2600, 7400},
			headerFill:  "0B7285",
			zebraFill:   "F2F7FA",
			borderColor: "B8C4CE",
		},
	))
	body.WriteString(docxSpacer(360))
	body.WriteString(docxCallout(
		"本报告由 Sophon 安全评估平台根据项目当前记录自动生成。报告中的资产、漏洞、证据和复测信息以导出时平台数据为准。",
		"F8FAFC",
		"475467",
	))
	body.WriteString(docxParagraph("CONFIDENTIAL", docxTextOptions{
		bold:           true,
		color:          "B42318",
		sizeHalfPoints: 18,
		alignment:      "center",
		before:         500,
		after:          0,
	}))
	return body.String()
}

func docxDocumentControl(project *database.Project, generatedAt time.Time) string {
	var body strings.Builder
	body.WriteString(docxHeading("文档控制", 1))
	body.WriteString(docxParagraph(
		"本报告用于记录项目安全评估范围、资产暴露情况、漏洞发现和修复建议，供项目负责人、安全团队和管理人员审阅。",
		docxTextOptions{},
	))
	body.WriteString(docxCallout(
		docxValue(project.Description, "项目未填写描述。"),
		"F8FAFC",
		"344054",
	))
	body.WriteString(docxTableWithOptions(
		[]string{"控制项", "内容"},
		[][]string{
			{"报告名称", project.Name + " 实网攻防演习问题隐患报告"},
			{"报告版本", "V1.0"},
			{"编制方式", "Sophon 安全评估平台自动汇总"},
			{"数据来源", "项目资产清单、漏洞记录、证据和复测记录"},
			{"报告状态", "正式导出"},
			{"导出时间", generatedAt.Format("2006-01-02 15:04:05 UTC")},
			{"保密要求", "未经授权不得复制、转发或向第三方披露"},
		},
		docxTableOptions{
			widths:     []int{2200, 7800},
			headerFill: "344054",
		},
	))
	return body.String()
}

func docxTableOfContents() string {
	sections := []string{
		"1 引言",
		"2 评估方法与过程",
		"3 资产与暴露面",
		"4 漏洞发现与统计分析",
		"5 漏洞分析",
		"6 修复优先级与处置建议",
		"7 复测与闭环计划",
		"8 结论",
		"附录A 证据索引",
		"附录B 复现与IL证据",
		"附录C 术语与缩写",
		"附录D 工具、数据与限制说明",
	}
	var body strings.Builder
	body.WriteString(`<w:p><w:pPr><w:pStyle w:val="Normal"/><w:spacing w:before="80" w:after="80"/><w:ind w:firstLine="0"/>` +
		`<w:tabs><w:tab w:val="right" w:leader="dot" w:pos="9000"/></w:tabs></w:pPr>` +
		`<w:r><w:fldChar w:fldCharType="begin"/></w:r>` +
		`<w:r><w:instrText xml:space="preserve"> TOC \o "1-3" \h \z \u </w:instrText></w:r>` +
		`<w:r><w:fldChar w:fldCharType="separate"/></w:r>` +
		`<w:r><w:t>` + docxEscape(sections[0]) + `</w:t></w:r><w:r><w:tab/></w:r><w:r><w:t>-</w:t></w:r></w:p>`)
	for _, section := range sections[1:] {
		body.WriteString(`<w:p><w:pPr><w:pStyle w:val="Normal"/><w:spacing w:before="40" w:after="40"/><w:ind w:firstLine="0"/>` +
			`<w:tabs><w:tab w:val="right" w:leader="dot" w:pos="9000"/></w:tabs></w:pPr>` +
			`<w:r><w:t>` + docxEscape(section) + `</w:t></w:r><w:r><w:tab/></w:r><w:r><w:t>-</w:t></w:r></w:p>`)
	}
	body.WriteString(`<w:p><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>`)
	return body.String()
}

func docxFrontMatter(
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
	groups []docxIssueGroup,
) string {
	var body strings.Builder
	body.WriteString(docxHeading("摘要", 1))
	severityCounts := countDocxSeverities(findings)
	statusCounts := countDocxStatuses(findings)
	body.WriteString(docxParagraph(fmt.Sprintf(
		"本报告基于项目“%s”在导出时记录的资产、漏洞、证据和复测数据，对授权范围内的暴露面、风险分布和重点问题进行归纳。共记录资产 %d 个、漏洞 %d 个，其中严重 %d 个、高危 %d 个、已确认 %d 个。报告正文突出风险结论和修复优先级，完整复现步骤、请求与IL证据归入附录。",
		project.Name,
		len(assets),
		len(findings),
		severityCounts["critical"],
		severityCounts["high"],
		statusCounts["confirmed"],
	), docxTextOptions{}))
	if goals := strings.TrimSpace(project.Goals); goals != "" {
		body.WriteString(docxParagraph("评估目标："+goals, docxTextOptions{
			color:       "475467",
			shading:     "F8FAFC",
			noFirstLine: true,
		}))
	}
	body.WriteString(docxParagraph("关键词："+docxReportKeywords(findings), docxTextOptions{
		bold:        true,
		noFirstLine: true,
	}))
	body.WriteString(docxPageBreak())
	body.WriteString(docxHeading("目录", 1))
	body.WriteString(docxTableOfContents())
	body.WriteString(docxPageBreak())
	body.WriteString(docxHeading("图表清单", 1))
	body.WriteString(docxTableList(groups))
	return body.String()
}

func docxReportKeywords(findings []database.Vulnerability) string {
	counts := countDocxVulnerabilityTypes(findings)
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	if len(names) > 5 {
		names = names[:5]
	}
	names = append([]string{"代码审计", "安全评估"}, names...)
	return strings.Join(names, "；")
}

func docxTableList(groups []docxIssueGroup) string {
	rows := [][]string{
		{"表2-1", "风险分级与统计口径", "第2章"},
		{"表3-1", "资产清单", "第3章"},
		{"表3-2", "入口、参数与实现位置映射", "第3章"},
		{"表4-1", "漏洞等级分布", "第4章"},
		{"表4-2", "漏洞类型分布", "第4章"},
		{"表4-3", "资产关联统计", "第4章"},
		{"表4-4", "重点漏洞摘要", "第4章"},
		{"表6-1", "修复优先级与处置动作", "第6章"},
		{"表7-1", "复测与闭环安排", "第7章"},
		{"表A-1", "证据索引", "附录A"},
	}
	if len(groups) > 0 {
		rows = append(rows, []string{"表5-x", "漏洞基本信息卡", "第5章"})
	}
	return docxParagraph(
		"本报告的数据分布采用文本条形表示，未使用无来源截图。",
		docxTextOptions{color: "667085", noFirstLine: true},
	) + docxTableWithOptions(
		[]string{"编号", "名称", "位置"},
		rows,
		docxTableOptions{
			widths:     []int{1400, 6200, 2400},
			headerFill: "344054",
		},
	)
}

func docxIntroduction(
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
) string {
	var body strings.Builder
	body.WriteString(docxHeading("1 引言", 1))
	body.WriteString(docxHeading("1.1 背景与目标", 2))
	body.WriteString(docxRichText(
		docxValue(project.Description, "项目未填写背景描述。"),
		"项目未填写背景描述。",
	))
	body.WriteString(docxParagraph(
		"评估目标："+docxValue(project.Goals, "未设置"),
		docxTextOptions{noFirstLine: true},
	))
	body.WriteString(docxHeading("1.2 评估范围与边界", 2))
	body.WriteString(docxParagraph(fmt.Sprintf(
		"授权范围为：%s。导出时记录资产 %d 个、漏洞 %d 个。本报告只汇总平台已有数据，不重新发送测试请求，不推断未记录漏洞。",
		docxValue(project.Scope, "未设置"),
		len(assets),
		len(findings),
	), docxTextOptions{}))
	body.WriteString(docxHeading("1.3 报告结构说明", 2))
	body.WriteString(docxParagraph(
		"主报告用于呈现范围、方法、资产、统计、重点结论、修复优先级和复测计划；第5章使用漏洞卡片承载结论；附录A提供证据索引，附录B保留完整复现步骤、请求、IL和工具证据。",
		docxTextOptions{},
	))
	return body.String()
}

func docxMethodology(findings []database.Vulnerability) string {
	var body strings.Builder
	body.WriteString(docxHeading("2 评估方法与过程", 1))
	body.WriteString(docxHeading("2.1 数据来源与资产识别", 2))
	body.WriteString(docxParagraph(
		"资产、漏洞、证据引用和复测状态均来自项目结构化记录。资产标识、入口、参数和实现位置用于建立暴露面与漏洞的对应关系。",
		docxTextOptions{},
	))
	body.WriteString(docxHeading("2.2 代码审计与验证方法", 2))
	body.WriteString(docxParagraph(
		"报告按“入口—参数—实现位置—前置条件—验证证据”的顺序组织漏洞信息。正文只引用结论性证据，完整请求、源码片段、IL偏移和工具输出通过证据编号索引到附录。",
		docxTextOptions{},
	))
	body.WriteString(docxHeading("2.3 风险分级与统计口径", 2))
	body.WriteString(docxTableCaption("2-1", "风险分级与统计口径"))
	rows := make([][]string, 0, len(docxSeverityOrder))
	for _, severity := range docxSeverityOrder {
		if severity == "unknown" {
			continue
		}
		rows = append(rows, []string{
			docxSeverityLabel(severity),
			docxSeverityRecommendation(severity),
			fmt.Sprintf("%d", countDocxSeverities(findings)[severity]),
		})
	}
	body.WriteString(docxTableWithOptions(
		[]string{"等级", "处置口径", "本次数量"},
		rows,
		docxTableOptions{
			widths:     []int{1800, 6000, 2200},
			headerFill: "344054",
		},
	))
	return body.String()
}

func docxAssetExposure(
	assets []database.Asset,
	findings []database.Vulnerability,
	groups []docxIssueGroup,
	assetNames map[string]string,
	evidenceIndex docxEvidenceIndex,
) string {
	vulnerabilitiesByAsset := make(map[string]int, len(assets))
	highRiskByAsset := make(map[string]int, len(assets))
	for _, item := range findings {
		if strings.TrimSpace(item.AssetID) != "" {
			vulnerabilitiesByAsset[item.AssetID]++
			rank := docxSeverityRank(item.Severity)
			if rank >= docxSeverityRank("high") {
				highRiskByAsset[item.AssetID]++
			}
		}
	}

	var body strings.Builder
	body.WriteString(docxHeading("3 资产与暴露面", 1))
	body.WriteString(docxHeading("3.1 资产清单", 2))
	body.WriteString(docxParagraph(
		"资产清单按资产类型、状态、关键度和关联漏洞数量汇总。名称与值相同时只展示一次，避免重复占用表格宽度。",
		docxTextOptions{},
	))
	if len(assets) == 0 {
		body.WriteString(docxCallout("当前项目未记录资产。", "FFFAEB", "B54708"))
	} else {
		rows := make([][]string, 0, len(assets))
		for index, asset := range assets {
			rows = append(rows, []string{
				fmt.Sprintf("%d", index+1),
				docxAssetIdentity(asset),
				docxAssetKindLabel(asset.Kind),
				docxAssetStatusLabel(asset.Status),
				docxCriticalityLabel(asset.Criticality) + " / " + docxRiskScoreLabel(asset.RiskScore),
				fmt.Sprintf("%d", vulnerabilitiesByAsset[asset.ID]),
			})
		}
		body.WriteString(docxTableCaption("3-1", "资产清单"))
		body.WriteString(docxTableWithOptions(
			[]string{"序号", "资产标识", "类型", "状态", "关键度 / 风险", "漏洞"},
			rows,
			docxTableOptions{
				widths:        []int{500, 3500, 1100, 1200, 2100, 800},
				headerFill:    "0B7285",
				allowRowSplit: true,
			},
		))
	}

	body.WriteString(docxHeading("3.2 入口、参数与实现位置映射", 2))
	issues := docxFlattenIssues(groups)
	if len(issues) == 0 {
		body.WriteString(docxCallout("当前项目未记录可映射的漏洞入口。", "ECFDF3", "027A48"))
	} else {
		rows := make([][]string, 0, len(issues))
		for _, issue := range issues {
			item := issue.Item
			rows = append(rows, []string{
				issue.Code,
				docxInlineText(docxVulnerabilityLocation(item), 80),
				docxInlineText(docxValue(item.Parameter, "未记录"), 36),
				docxInlineText(docxFindingImplementationLocation(item), 56),
				docxInlineText(docxValue(docxReportSafeText(item.Preconditions), "未记录"), 36),
				docxValue(docxEvidenceReferenceLine(item.EvidenceRefs, evidenceIndex), "未记录"),
			})
		}
		body.WriteString(docxTableCaption("3-2", "入口、参数与实现位置映射"))
		body.WriteString(docxTableWithOptions(
			[]string{"漏洞编号", "入口", "参数", "实现位置", "前置条件", "证据"},
			rows,
			docxTableOptions{
				widths:        []int{1100, 2300, 1200, 2300, 1900, 900},
				headerFill:    "344054",
				allowRowSplit: true,
			},
		))
	}
	body.WriteString(docxHeading("3.3 总体风险画像", 2))
	highRiskAssets := 0
	for _, count := range highRiskByAsset {
		if count > 0 {
			highRiskAssets++
		}
	}
	body.WriteString(docxParagraph(fmt.Sprintf(
		"当前资产 %d 个，其中存在严重或高危漏洞的资产 %d 个；漏洞关联资产 %d 个。资产名称与入口仅用于授权报告追溯，不能据此扩大测试范围。",
		len(assets),
		highRiskAssets,
		len(assetNames),
	), docxTextOptions{}))
	return body.String()
}

func docxFindingStatistics(
	findings []database.Vulnerability,
	groups []docxIssueGroup,
	assetNames map[string]string,
) string {
	var body strings.Builder
	body.WriteString(docxHeading("4 漏洞发现与统计分析", 1))
	severityCounts := countDocxSeverities(findings)
	statusCounts := countDocxStatuses(findings)
	total := len(findings)
	body.WriteString(docxParagraph(fmt.Sprintf(
		"当前共记录漏洞 %d 个，严重及高危 %d 个，已确认 %d 个。统计结果与封面、摘要、第5章漏洞卡片和结论使用同一份导出时数据。",
		total,
		severityCounts["critical"]+severityCounts["high"],
		statusCounts["confirmed"],
	), docxTextOptions{}))

	body.WriteString(docxHeading("4.1 严重程度分布", 2))
	severityRows := make([][]string, 0, len(docxSeverityOrder))
	for _, severity := range docxSeverityOrder {
		if severity == "unknown" && severityCounts[severity] == 0 {
			continue
		}
		severityRows = append(severityRows, []string{
			docxSeverityLabel(severity),
			fmt.Sprintf("%d", severityCounts[severity]),
			docxPercent(severityCounts[severity], total),
			docxSeverityRecommendation(severity),
		})
	}
	body.WriteString(docxTableCaption("4-1", "漏洞等级分布"))
	body.WriteString(docxTableWithOptions(
		[]string{"严重程度", "数量", "占比", "处置建议"},
		severityRows,
		docxTableOptions{
			widths:     []int{1800, 1200, 1400, 5600},
			headerFill: "B42318",
		},
	))

	body.WriteString(docxHeading("4.2 漏洞类型分布", 2))
	typeCounts := countDocxVulnerabilityTypes(findings)
	typeNames := make([]string, 0, len(typeCounts))
	for name := range typeCounts {
		typeNames = append(typeNames, name)
	}
	sort.Slice(typeNames, func(i, j int) bool {
		if typeCounts[typeNames[i]] != typeCounts[typeNames[j]] {
			return typeCounts[typeNames[i]] > typeCounts[typeNames[j]]
		}
		return typeNames[i] < typeNames[j]
	})
	typeRows := make([][]string, 0, len(typeNames))
	for _, name := range typeNames {
		typeRows = append(typeRows, []string{
			name,
			fmt.Sprintf("%d", typeCounts[name]),
			docxPercent(typeCounts[name], total),
		})
	}
	body.WriteString(docxTableCaption("4-2", "漏洞类型分布"))
	if len(typeRows) == 0 {
		body.WriteString(docxParagraph("当前项目未记录漏洞类型。", docxTextOptions{}))
	} else {
		body.WriteString(docxTableWithOptions(
			[]string{"漏洞类型", "数量", "占比"},
			typeRows,
			docxTableOptions{
				widths:     []int{6000, 1600, 2400},
				headerFill: "344054",
			},
		))
		body.WriteString(docxTableCaption("图4-1", "漏洞类型数量分布（文本条形图）"))
		for _, name := range typeNames {
			body.WriteString(docxParagraph(
				docxCompactText(name, 28)+"  "+docxPercentBar(typeCounts[name], total),
				docxTextOptions{noFirstLine: true, before: 20, after: 40},
			))
		}
	}

	body.WriteString(docxHeading("4.3 资产关联统计", 2))
	assetCounts := make(map[string]int)
	assetHighCounts := make(map[string]int)
	for _, item := range findings {
		if item.AssetID == "" {
			continue
		}
		assetCounts[item.AssetID]++
		if docxSeverityRank(item.Severity) >= docxSeverityRank("high") {
			assetHighCounts[item.AssetID]++
		}
	}
	assetIDs := make([]string, 0, len(assetCounts))
	for assetID := range assetCounts {
		assetIDs = append(assetIDs, assetID)
	}
	sort.Slice(assetIDs, func(i, j int) bool {
		if assetCounts[assetIDs[i]] != assetCounts[assetIDs[j]] {
			return assetCounts[assetIDs[i]] > assetCounts[assetIDs[j]]
		}
		return assetIDs[i] < assetIDs[j]
	})
	assetRows := make([][]string, 0, len(assetIDs))
	for _, assetID := range assetIDs {
		assetRows = append(assetRows, []string{
			docxAssetName(assetID, assetNames),
			fmt.Sprintf("%d", assetCounts[assetID]),
			fmt.Sprintf("%d", assetHighCounts[assetID]),
		})
	}
	body.WriteString(docxTableCaption("4-3", "资产关联统计"))
	if len(assetRows) == 0 {
		body.WriteString(docxParagraph("当前漏洞未关联资产。", docxTextOptions{}))
	} else {
		body.WriteString(docxTableWithOptions(
			[]string{"关联资产", "漏洞数量", "严重及高危"},
			assetRows,
			docxTableOptions{
				widths:     []int{6000, 1800, 2200},
				headerFill: "0B7285",
			},
		))
	}

	body.WriteString(docxHeading("4.4 重点漏洞摘要", 2))
	body.WriteString(docxParagraph(
		"重点漏洞按严重程度排序展示前五项，完整标题、入口、实现位置和证据编号进入第5章卡片及附录。",
		docxTextOptions{},
	))
	issues := docxFlattenIssues(groups)
	if len(issues) == 0 {
		body.WriteString(docxCallout("当前项目未记录漏洞。", "ECFDF3", "027A48"))
		return body.String()
	}
	limit := len(issues)
	if limit > 5 {
		limit = 5
	}
	rows := make([][]string, 0, limit)
	for index := 0; index < limit; index++ {
		issue := issues[index]
		item := issue.Item
		rows = append(rows, []string{
			issue.Code,
			docxShortVulnerabilityTitle(item.Title),
			docxSeverityLabel(item.Severity),
			docxStatusLabel(item.Status),
			docxCompactText(docxAssetName(item.AssetID, assetNames), 28),
		})
	}
	body.WriteString(docxTableCaption("4-4", "重点漏洞摘要"))
	body.WriteString(docxTableWithOptions(
		[]string{"漏洞编号", "短标题", "严重度", "状态", "关联资产"},
		rows,
		docxTableOptions{
			widths:     []int{1400, 4000, 1100, 1200, 2300},
			headerFill: "344054",
		},
	))
	return body.String()
}

func docxVulnerabilityAnalysis(
	groups []docxIssueGroup,
	assetNames map[string]string,
	evidenceIndex docxEvidenceIndex,
) string {
	var body strings.Builder
	body.WriteString(docxHeading("5 漏洞分析", 1))
	issues := docxFlattenIssues(groups)
	if len(issues) == 0 {
		body.WriteString(docxCallout("当前项目未记录漏洞详情。", "ECFDF3", "027A48"))
		return body.String()
	}

	globalIndex := 0
	for groupIndex, group := range groups {
		body.WriteString(docxHeading(
			fmt.Sprintf("5.%d %s", groupIndex+1, group.Title),
			2,
		))
		if len(group.Issues) == 0 {
			body.WriteString(docxParagraph("当前未记录该等级漏洞。", docxTextOptions{
				color:       "667085",
				noFirstLine: true,
			}))
			continue
		}
		currentType := ""
		for _, issue := range group.Issues {
			item := issue.Item
			vulnerabilityType := docxValue(item.VulnerabilityType, "未分类")
			typeChanged := vulnerabilityType != currentType
			body.WriteString(docxIssueHeading(
				fmt.Sprintf(
					"%s %s %s",
					issue.Section,
					issue.Code,
					docxShortVulnerabilityTitle(item.Title),
				),
				globalIndex > 0,
			))
			if typeChanged {
				body.WriteString(docxTypeDivider(vulnerabilityType))
				currentType = vulnerabilityType
			}
			body.WriteString(docxVulnerabilityBasicInfo(issue, assetNames, evidenceIndex))
			if docxSeverityRank(item.Severity) >= docxSeverityRank("high") {
				body.WriteString(docxDetailedFindingCard(item, issue))
			} else {
				body.WriteString(docxCompactFindingCard(item, issue))
			}
			globalIndex++
		}
	}
	return body.String()
}

func docxTypeDivider(vulnerabilityType string) string {
	return docxParagraph("类型分组："+vulnerabilityType, docxTextOptions{
		bold:        true,
		color:       "344054",
		shading:     "EAECF0",
		before:      120,
		after:       60,
		keepNext:    true,
		noFirstLine: true,
	})
}

func docxVulnerabilityBasicInfo(
	issue docxIssue,
	assetNames map[string]string,
	evidenceIndex docxEvidenceIndex,
) string {
	item := issue.Item
	evidenceCodes := docxValue(docxEvidenceReferenceLine(item.EvidenceRefs, evidenceIndex), "未记录")
	summary := strings.Join([]string{
		docxSeverityLabel(item.Severity),
		docxStatusLabel(item.Status),
		docxValue(item.VulnerabilityType, "未分类"),
	}, " / ")
	rows := [][]string{
		{"完整标题", item.Title},
		{"风险标签", summary},
		{"漏洞编号", issue.Code},
		{"CWE", "未记录"},
		{"入口", docxInlineText(docxVulnerabilityLocation(item), 100)},
		{"参数", docxInlineText(docxValue(item.Parameter, "未记录"), 48)},
		{"实现位置", docxInlineText(docxFindingImplementationLocation(item), 72)},
		{"证据", evidenceCodes},
		{"关联资产", docxInlineText(docxAssetName(item.AssetID, assetNames), 48)},
		{"置信度", fmt.Sprintf("%d / 100", item.Confidence)},
	}
	return docxTableCaption("5-x", issue.Code+" 基本信息") +
		docxTableWithOptions(
			[]string{"字段", "内容"},
			rows,
			docxTableOptions{
				widths:        []int{1600, 8400},
				headerFill:    "344054",
				allowRowSplit: true,
			},
		)
}

func docxDetailedFindingCard(
	item database.Vulnerability,
	issue docxIssue,
) string {
	var body strings.Builder
	body.WriteString(docxCardLabel("概述"))
	body.WriteString(docxParagraph(docxFindingOverview(item), docxTextOptions{}))
	body.WriteString(docxCardLabel("成因分析"))
	body.WriteString(docxCauseAnalysis(item.Description))
	body.WriteString(docxCardLabel("影响与利用条件"))
	body.WriteString(docxRichText(
		docxCompactText(docxFindingImpact(item), 360),
		"未记录危害与利用条件。",
	))
	body.WriteString(docxCardLabel("修复建议"))
	body.WriteString(docxRichText(
		docxCompactText(docxReportSafeText(item.Recommendation), 360),
		"未记录修复建议。",
	))
	body.WriteString(docxCardLabel("验证与复测"))
	body.WriteString(docxParagraph(
		"证据摘要："+docxFindingEvidenceSummary(item),
		docxTextOptions{noFirstLine: true},
	))
	body.WriteString(docxParagraph(
		"复测与清理："+docxValue(
			docxCompactText(docxReportSafeText(item.RetestNotes), 260),
			"未记录复测与清理记录。",
		),
		docxTextOptions{noFirstLine: true},
	))
	body.WriteString(docxAppendixReference(issue))
	return body.String()
}

func docxCompactFindingCard(
	item database.Vulnerability,
	issue docxIssue,
) string {
	var body strings.Builder
	body.WriteString(docxCardLabel("概述与影响"))
	body.WriteString(docxParagraph(docxFindingOverview(item), docxTextOptions{}))
	body.WriteString(docxRichText(
		docxCompactText(docxFindingImpact(item), 260),
		"未记录危害与利用条件。",
	))
	body.WriteString(docxCardLabel("修复与复测"))
	body.WriteString(docxRichText(
		docxCompactText(docxReportSafeText(item.Recommendation), 300),
		"未记录修复建议。",
	))
	body.WriteString(docxParagraph(
		"验证摘要："+docxFindingEvidenceSummary(item),
		docxTextOptions{noFirstLine: true},
	))
	body.WriteString(docxAppendixReference(issue))
	return body.String()
}

func docxCardLabel(label string) string {
	return docxParagraph(label, docxTextOptions{
		bold:           true,
		sizeHalfPoints: 22,
		color:          "1D2939",
		before:         140,
		after:          50,
		keepNext:       true,
		noFirstLine:    true,
	})
}

func docxAppendixReference(issue docxIssue) string {
	return docxParagraph(
		fmt.Sprintf("完整复现步骤、请求、IL、源码和工具证据见 附录B %s。", issue.Code),
		docxTextOptions{
			color:       "667085",
			before:      40,
			after:       80,
			noFirstLine: true,
		},
	)
}

func docxFlattenIssues(groups []docxIssueGroup) []docxIssue {
	issues := make([]docxIssue, 0)
	for _, group := range groups {
		issues = append(issues, group.Issues...)
	}
	return issues
}

func docxAssetIdentity(asset database.Asset) string {
	name := strings.TrimSpace(asset.Name)
	value := strings.TrimSpace(asset.Value)
	switch {
	case name == "":
		return docxValue(value, "未记录")
	case value == "" || strings.EqualFold(name, value):
		return name
	default:
		return name + "\n" + value
	}
}

func docxInlineText(value string, limit int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	return docxCompactText(value, limit)
}

func docxFindingImplementationLocation(item database.Vulnerability) string {
	for _, line := range strings.Split(strings.ReplaceAll(item.Description, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range []string{"漏洞位置：", "实现位置：", "文件位置：", "文件："} {
			if strings.HasPrefix(trimmed, prefix) {
				if value := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix)); value != "" {
					return value
				}
			}
		}
	}
	for _, candidate := range []string{item.Description, item.Evidence, item.Target} {
		if match := docxImplementationPathPattern.FindString(candidate); match != "" {
			return match
		}
	}
	return docxValue(item.Target, "未记录")
}

func docxShortVulnerabilityTitle(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" {
		return "未命名漏洞"
	}
	for _, separator := range []string{"：", ":", "（", "("} {
		if index := strings.Index(value, separator); index >= 12 {
			return docxCompactText(strings.TrimSpace(value[:index]), 48)
		}
	}
	return docxCompactText(value, 48)
}

func docxFindingOverview(item database.Vulnerability) string {
	overview := fmt.Sprintf(
		"在测试目标 %s 记录到 %s，当前风险等级为%s，状态为%s。",
		docxValue(docxInlineText(docxVulnerabilityLocation(item), 120), "未记录"),
		docxValue(item.VulnerabilityType, "未分类漏洞"),
		docxSeverityLabel(item.Severity),
		docxStatusLabel(item.Status),
	)
	if description := docxFirstParagraph(docxReportSafeText(item.Description), 160); description != "" {
		overview += description
	}
	return overview
}

func docxCauseAnalysis(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\r\n", "\n"))
	if value == "" {
		return docxParagraph("未记录漏洞原理和测试链路。", docxTextOptions{})
	}
	labels := []string{"漏洞位置：", "实现位置：", "原理：", "鉴权条件：", "测试链路：", "根因："}
	selected := make([]string, 0, 4)
	lines := strings.Split(value, "\n")
	for _, label := range labels {
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, label) {
				continue
			}
			content := strings.TrimSpace(strings.TrimPrefix(trimmed, label))
			if content != "" {
				selected = append(selected, docxInlineText(content, 180))
			}
			break
		}
		if len(selected) >= 4 {
			break
		}
	}
	if len(selected) == 0 {
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || (len(line) >= 3 && strings.Trim(line, "-") == "") {
				continue
			}
			selected = append(selected, docxInlineText(line, 220))
			if len(selected) >= 4 {
				break
			}
		}
	}
	if len(selected) == 0 {
		selected = append(selected, docxInlineText(docxReportSafeText(value), 320))
	}
	var body strings.Builder
	for index, item := range selected {
		body.WriteString(docxRichParagraph(
			fmt.Sprintf("%d）%s", index+1, docxReportSafeText(item)),
			docxTextOptions{
				indent:      280,
				before:      25,
				after:       55,
				noFirstLine: true,
			},
		))
	}
	body.WriteString(docxParagraph(
		"完整成因、请求和证据原文见附录B。",
		docxTextOptions{
			color:       "667085",
			before:      20,
			after:       70,
			noFirstLine: true,
		},
	))
	return body.String()
}

func docxFindingImpact(item database.Vulnerability) string {
	impact := strings.TrimSpace(docxReportSafeText(item.Impact))
	if exploitability := strings.TrimSpace(docxReportSafeText(item.Exploitability)); exploitability != "" {
		if impact != "" {
			impact += "\n"
		}
		impact += "可利用条件：" + exploitability
	}
	return impact
}

func docxFindingEvidenceSummary(item database.Vulnerability) string {
	summary := docxFirstParagraph(docxReportSafeText(item.Evidence), 280)
	if summary == "" {
		return "未记录实际验证结果。"
	}
	return summary
}

func docxFirstParagraph(value string, limit int) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\r\n", "\n"))
	if value == "" {
		return ""
	}
	for _, block := range strings.Split(value, "\n\n") {
		block = strings.Join(strings.Fields(block), " ")
		if block != "" {
			return docxCompactText(block, limit)
		}
	}
	return ""
}

func countDocxVulnerabilityTypes(findings []database.Vulnerability) map[string]int {
	counts := make(map[string]int)
	for _, item := range findings {
		counts[docxValue(item.VulnerabilityType, "未分类")]++
	}
	return counts
}

func docxTableCaption(number, title string) string {
	prefix := "表"
	if strings.HasPrefix(number, "图") {
		prefix = ""
	}
	return docxParagraph(prefix+number+"  "+title, docxTextOptions{
		style:       "Caption",
		bold:        true,
		alignment:   "center",
		before:      100,
		after:       60,
		keepNext:    true,
		noFirstLine: true,
	})
}

func docxFolderMeta(item database.Vulnerability, assetNames map[string]string) string {
	return docxTableWithOptions(
		[]string{"字段", "内容"},
		[][]string{
			{"完整标题", docxValue(item.Title, "未命名漏洞")},
			{"关联资产", docxReportValue(docxAssetName(item.AssetID, assetNames))},
			{"验证目标", docxReportValue(docxVulnerabilityLocation(item))},
			{"漏洞标识", docxReportValue(item.ID)},
		},
		docxTableOptions{
			widths:     []int{1800, 8200},
			headerFill: "344054",
		},
	)
}

func docxVulnerabilityLocation(item database.Vulnerability) string {
	location := docxReportValue(item.Target)
	if method := strings.TrimSpace(item.HTTPMethod); method != "" {
		location = method + " " + location
	}
	if parameter := strings.TrimSpace(item.Parameter); parameter != "" {
		location += "，参数 " + parameter
	}
	return location
}

func docxReportValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return "未记录"
	}
	return value
}

func docxReportSafeText(value string) string {
	replacer := strings.NewReplacer(
		"攻击者", "未授权人员",
		"攻击目标", "测试目标",
		"攻击时间段", "测试时间段",
		"攻击资源", "测试资源",
		"攻击方式", "测试方式",
		"攻击工具", "测试工具",
		"攻击链路", "测试链路",
		"攻击链", "测试链",
		"攻击面", "测试面",
		"黑客", "未授权人员",
	)
	result := replacer.Replace(strings.TrimSpace(value))
	return strings.ReplaceAll(result, "攻击", "测试")
}

func docxRemediationAndRetest(groups []docxIssueGroup) string {
	issues := docxFlattenIssues(groups)
	var body strings.Builder
	body.WriteString(docxHeading("6 修复优先级与处置建议", 1))
	body.WriteString(docxHeading("6.1 优先级矩阵", 2))
	body.WriteString(docxParagraph(
		"优先级按漏洞等级和当前状态确定。实际排期还应结合业务重要性、账号权限、数据敏感度和修复依赖。",
		docxTextOptions{},
	))
	if len(issues) == 0 {
		body.WriteString(docxCallout("当前项目未记录需要处置的漏洞。", "ECFDF3", "027A48"))
	} else {
		rows := make([][]string, 0, len(issues))
		for _, issue := range issues {
			item := issue.Item
			rows = append(rows, []string{
				docxIssuePriority(item),
				issue.Code,
				docxInlineText(docxValue(item.Recommendation, docxSeverityRecommendation(item.Severity)), 72),
				docxResponsibilitySuggestion(item),
				docxRetestAction(item.Status),
			})
		}
		body.WriteString(docxTableCaption("6-1", "修复优先级与处置动作"))
		body.WriteString(docxTableWithOptions(
			[]string{"优先级", "漏洞编号", "处置动作", "责任建议", "复测要求"},
			rows,
			docxTableOptions{
				widths:        []int{1100, 1300, 3500, 1900, 2200},
				headerFill:    "B42318",
				allowRowSplit: true,
			},
		))
	}
	body.WriteString(docxHeading("6.2 立即处置项", 2))
	body.WriteString(docxIssueCodeParagraph(issues, "critical"))
	body.WriteString(docxHeading("6.3 短期修复项", 2))
	body.WriteString(docxIssueCodeParagraph(issues, "high"))
	body.WriteString(docxHeading("6.4 长期加固建议", 2))
	body.WriteString(docxParagraph(
		"将输入校验、统一鉴权、上传与文件路径约束、错误处理、日志审计和安全测试用例纳入研发基线；对同类入口开展横向排查，避免只修复单点。",
		docxTextOptions{},
	))

	body.WriteString(docxPageBreak())
	body.WriteString(docxHeading("7 复测与闭环计划", 1))
	body.WriteString(docxHeading("7.1 复测范围", 2))
	body.WriteString(docxParagraph(
		"复测覆盖第5章全部问题及其关联入口。已修复项执行回归验证，待处理和已确认项在修复后安排复测，误报和接受风险项保留判定依据。",
		docxTextOptions{},
	))
	body.WriteString(docxHeading("7.2 复测方法", 2))
	body.WriteString(docxParagraph(
		"使用与原始验证等价的最小请求复现问题，对比修复前后的状态码、响应内容、权限结果、文件落盘行为或命令执行结果，并补充新的证据引用。",
		docxTextOptions{},
	))
	statusCounts := countDocxStatuses(findingsFromIssueGroups(groups))
	retestRows := make([][]string, 0, len(docxStatusOrder))
	for _, status := range docxStatusOrder {
		if status == "unknown" && statusCounts[status] == 0 {
			continue
		}
		retestRows = append(retestRows, []string{
			docxStatusLabel(status),
			fmt.Sprintf("%d", statusCounts[status]),
			docxRetestAction(status),
		})
	}
	body.WriteString(docxTableCaption("7-1", "复测与闭环安排"))
	body.WriteString(docxTableWithOptions(
		[]string{"状态", "数量", "复测与闭环要求"},
		retestRows,
		docxTableOptions{
			widths:     []int{1800, 1200, 7000},
			headerFill: "344054",
		},
	))
	body.WriteString(docxHeading("7.3 闭环判定标准", 2))
	body.WriteString(docxParagraph(
		"漏洞已修复、原利用条件不再成立、回归请求未复现，并且复测证据已写回项目，方可判定闭环。仅修改状态或缺少复测证据时不得关闭。",
		docxTextOptions{},
	))
	return body.String()
}

func docxConclusion(
	project *database.Project,
	assets []database.Asset,
	findings []database.Vulnerability,
	groups []docxIssueGroup,
) string {
	severityCounts := countDocxSeverities(findings)
	statusCounts := countDocxStatuses(findings)
	var body strings.Builder
	body.WriteString(docxHeading("8 结论", 1))
	body.WriteString(docxParagraph(fmt.Sprintf(
		"项目“%s”本次共汇总资产 %d 个、漏洞 %d 个，其中严重 %d 个、高危 %d 个、已确认 %d 个。",
		project.Name,
		len(assets),
		len(findings),
		severityCounts["critical"],
		severityCounts["high"],
		statusCounts["confirmed"],
	), docxTextOptions{}))
	highRisk := severityCounts["critical"] + severityCounts["high"]
	if highRisk > 0 {
		body.WriteString(docxCallout(fmt.Sprintf(
			"建议优先处置 %d 个严重或高危问题，先完成利用条件收敛、证据复核和修复责任确认，再按第7章执行复测闭环。",
			highRisk,
		), "FEF3F2", "B42318"))
	} else {
		body.WriteString(docxCallout(
			"当前未记录严重或高危漏洞，仍需结合业务变化、资产新增和复测结果持续更新风险判断。",
			"ECFDF3",
			"027A48",
		))
	}
	issues := docxFlattenIssues(groups)
	if len(issues) > 0 {
		body.WriteString(docxParagraph(
			"重点漏洞编号："+strings.Join(docxIssueCodes(issues, 8), "、"),
			docxTextOptions{noFirstLine: true},
		))
	}
	return body.String()
}

func docxReportAppendix(
	project *database.Project,
	groups []docxIssueGroup,
	evidenceIndex docxEvidenceIndex,
) string {
	var body strings.Builder
	issues := docxFlattenIssues(groups)
	body.WriteString(docxHeading("附录A 证据索引", 1))
	if len(evidenceIndex.Items) == 0 {
		body.WriteString(docxParagraph("当前项目未记录证据引用。", docxTextOptions{}))
	} else {
		rows := make([][]string, 0, len(evidenceIndex.Items))
		for _, item := range evidenceIndex.Items {
			rows = append(rows, []string{
				item.Code,
				item.Kind,
				item.Ref,
				item.Purpose,
				docxValue(strings.Join(item.Findings, "、"), "未关联"),
			})
		}
		body.WriteString(docxTableCaption("A-1", "证据索引"))
		body.WriteString(docxTableWithOptions(
			[]string{"编号", "类型", "原始引用", "用途", "对应漏洞"},
			rows,
			docxTableOptions{
				widths:        []int{800, 900, 3500, 2600, 2200},
				headerFill:    "0B7285",
				allowRowSplit: true,
			},
		))
	}

	body.WriteString(docxPageBreak())
	body.WriteString(docxHeading("附录B 复现与IL证据", 1))
	if len(issues) == 0 {
		body.WriteString(docxParagraph("当前项目未记录复现与IL证据。", docxTextOptions{}))
	} else {
		for index, issue := range issues {
			item := issue.Item
			body.WriteString(docxIssueHeading(
				fmt.Sprintf("B.%d %s %s", index+1, issue.Code, docxShortVulnerabilityTitle(item.Title)),
				false,
			))
			body.WriteString(docxParagraph(
				"入口："+docxVulnerabilityLocation(item),
				docxTextOptions{noFirstLine: true},
			))
			body.WriteString(docxParagraph(
				"证据引用："+docxValue(docxEvidenceReferenceLine(item.EvidenceRefs, evidenceIndex), "未记录"),
				docxTextOptions{noFirstLine: true},
			))
			if strings.TrimSpace(item.Description) != "" {
				body.WriteString(docxCardLabel("成因与描述"))
				body.WriteString(docxCodeBlock(item.Description))
			}
			body.WriteString(docxCardLabel("完整复现步骤与请求"))
			body.WriteString(docxCodeBlock(docxValue(
				item.ReproductionSteps,
				"未记录完整 PoC、HTTP 数据包或复现步骤。",
			)))
			body.WriteString(docxCardLabel("完整验证证据"))
			body.WriteString(docxCodeBlock(docxValue(item.Evidence, "未记录实际验证结果。")))
			body.WriteString(docxCardLabel("完整影响与利用条件"))
			body.WriteString(docxCodeBlock(docxValue(
				docxFindingImpact(item),
				"未记录危害与利用条件。",
			)))
			body.WriteString(docxCardLabel("完整修复建议"))
			body.WriteString(docxCodeBlock(docxValue(
				docxReportSafeText(item.Recommendation),
				"未记录修复建议。",
			)))
			body.WriteString(docxCardLabel("复测与清理记录"))
			body.WriteString(docxCodeBlock(docxValue(
				docxReportSafeText(item.RetestNotes),
				"未记录复测与清理记录。",
			)))
		}
	}

	body.WriteString(docxPageBreak())
	body.WriteString(docxHeading("附录C 术语与缩写", 1))
	body.WriteString(docxTableWithOptions(
		[]string{"术语", "说明"},
		[][]string{
			{"严重", "可直接导致核心业务失陷、敏感数据泄露或大范围影响。"},
			{"高危", "具备较高利用价值或影响关键业务，应尽快修复并验证。"},
			{"中危", "在特定条件下产生影响，应纳入近期修复计划。"},
			{"低危", "影响有限或利用条件较高，可结合版本迭代修复。"},
			{"信息", "非直接安全风险，作为安全加固和配置优化参考。"},
			{"IL", "Microsoft Intermediate Language，.NET 程序集的中间语言。"},
			{"PoC", "Proof of Concept，用于验证漏洞成立的最小复现材料。"},
			{"CWE", "Common Weakness Enumeration，通用软件弱点分类。"},
		},
		docxTableOptions{
			widths:     []int{1600, 8400},
			headerFill: "344054",
		},
	))

	body.WriteString(docxPageBreak())
	body.WriteString(docxHeading("附录D 工具、数据与限制说明", 1))
	body.WriteString(docxParagraph(fmt.Sprintf(
		"本报告基于项目“%s”在导出时记录的资产、漏洞、证据引用和复测信息自动生成。CWE未记录时不自动推断；未配置真实图表时使用数据表与文本条形展示。",
		project.Name,
	), docxTextOptions{}))
	body.WriteString(docxCallout(
		"报告不替代业务影响分析、合规审计或人工复核。未记录项不代表不存在风险；完整证据仅限授权人员使用。",
		"FEF3F2",
		"B42318",
	))
	return body.String()
}

func findingsFromIssueGroups(groups []docxIssueGroup) []database.Vulnerability {
	issues := docxFlattenIssues(groups)
	findings := make([]database.Vulnerability, 0, len(issues))
	for _, issue := range issues {
		findings = append(findings, issue.Item)
	}
	return findings
}

func docxIssuePriority(item database.Vulnerability) string {
	switch normalizeDocxSeverity(item.Severity) {
	case "critical":
		return "P0"
	case "high":
		return "P1"
	case "medium":
		return "P2"
	case "low", "info":
		return "P3"
	default:
		return "待评级"
	}
}

func docxResponsibilitySuggestion(item database.Vulnerability) string {
	switch {
	case strings.Contains(strings.ToLower(item.VulnerabilityType), "upload"),
		strings.Contains(item.VulnerabilityType, "上传"):
		return "应用负责人 / 文件服务负责人"
	case strings.Contains(strings.ToLower(item.VulnerabilityType), "sql"),
		strings.Contains(item.VulnerabilityType, "注入"):
		return "应用负责人 / 数据接口负责人"
	case strings.Contains(strings.ToLower(item.VulnerabilityType), "auth"),
		strings.Contains(item.VulnerabilityType, "鉴权"):
		return "应用负责人 / 身份认证负责人"
	default:
		return "应用负责人 / 安全团队"
	}
}

func docxIssueCodeParagraph(issues []docxIssue, severity string) string {
	codes := make([]string, 0)
	for _, issue := range issues {
		if normalizeDocxSeverity(issue.Item.Severity) == severity {
			codes = append(codes, issue.Code)
		}
	}
	if len(codes) == 0 {
		return docxParagraph("当前无该优先级的漏洞。", docxTextOptions{color: "667085"})
	}
	return docxParagraph(strings.Join(codes, "、"), docxTextOptions{noFirstLine: true})
}

func docxIssueCodes(issues []docxIssue, limit int) []string {
	if limit > 0 && len(issues) > limit {
		issues = issues[:limit]
	}
	codes := make([]string, 0, len(issues))
	for _, issue := range issues {
		codes = append(codes, issue.Code)
	}
	return codes
}

func docxHeading(text string, level int) string {
	style := "Heading1"
	size := 32
	color := "102A43"
	before := 180
	if level == 2 {
		style = "Heading2"
		size = 28
		color = "1D2939"
		before = 180
	}
	if level >= 3 {
		style = "Heading3"
		size = 24
		color = "344054"
		before = 140
	}
	return docxParagraph(text, docxTextOptions{
		style:          style,
		bold:           true,
		color:          color,
		sizeHalfPoints: size,
		before:         before,
		after:          100,
		keepNext:       true,
		noFirstLine:    true,
	})
}

func docxIssueHeading(text string, pageBreakBefore bool) string {
	return docxParagraph(text, docxTextOptions{
		style:           "Heading2",
		bold:            true,
		color:           "1D2939",
		sizeHalfPoints:  28,
		before:          180,
		after:           100,
		keepNext:        true,
		pageBreakBefore: pageBreakBefore,
		noFirstLine:     true,
	})
}

func docxPageBreak() string {
	return `<w:p><w:r><w:br w:type="page"/></w:r></w:p>`
}

func docxCompactText(value string, limit int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	runes := []rune(value)
	if limit <= 0 || len(runes) <= limit {
		return value
	}
	if limit == 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}

func docxPercentBar(value, total int) string {
	const width = 16
	if total <= 0 || value <= 0 {
		return strings.Repeat("░", width)
	}
	filled := value * width / total
	if filled == 0 {
		filled = 1
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func docxEvidenceReferenceLine(refs []string, index docxEvidenceIndex) string {
	values := make([]string, 0, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if item, ok := index.ByRef[ref]; ok {
			values = append(values, item.Code)
		}
	}
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, "、")
}

func docxSpacer(before int) string {
	return docxParagraph("", docxTextOptions{before: before, after: 1})
}

func docxCallout(text, fill, color string) string {
	return `<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/><w:tblLayout w:type="fixed"/><w:tblBorders>` +
		`<w:top w:val="single" w:sz="4" w:color="D0D5DD"/>` +
		`<w:left w:val="single" w:sz="4" w:color="D0D5DD"/>` +
		`<w:bottom w:val="single" w:sz="4" w:color="D0D5DD"/>` +
		`<w:right w:val="single" w:sz="4" w:color="D0D5DD"/>` +
		`</w:tblBorders><w:tblCellMar>` +
		`<w:top w:w="100" w:type="dxa"/><w:left w:w="120" w:type="dxa"/>` +
		`<w:bottom w:w="100" w:type="dxa"/><w:right w:w="120" w:type="dxa"/>` +
		`</w:tblCellMar></w:tblPr><w:tblGrid><w:gridCol w:w="10000"/></w:tblGrid>` +
		`<w:tr><w:tc><w:tcPr><w:tcW w:w="10000" w:type="dxa"/>` +
		fmt.Sprintf(`<w:shd w:val="clear" w:color="auto" w:fill="%s"/>`, docxEscape(fill)) +
		`<w:vAlign w:val="center"/></w:tcPr>` +
		docxParagraph(text, docxTextOptions{
			color:          color,
			sizeHalfPoints: 20,
			before:         100,
			after:          100,
			alignment:      "left",
			noFirstLine:    true,
		}) +
		`</w:tc></w:tr></w:tbl>`
}

func docxCodeBlock(text string) string {
	var runs strings.Builder
	for index, line := range strings.Split(text, "\n") {
		if index > 0 {
			runs.WriteString(`<w:r><w:br/></w:r>`)
		}
		if line == "" {
			continue
		}
		runs.WriteString(`<w:r><w:rPr><w:rFonts w:ascii="Consolas" w:eastAsia="Arial Unicode MS" w:hAnsi="Consolas"/>` +
			`<w:color w:val="344054"/><w:sz w:val="18"/></w:rPr><w:t xml:space="preserve">` +
			docxEscape(line) + `</w:t></w:r>`)
	}
	return `<w:p><w:pPr><w:jc w:val="left"/>` +
		`<w:pBdr><w:top w:val="single" w:sz="4" w:space="4" w:color="D0D5DD"/>` +
		`<w:left w:val="single" w:sz="4" w:space="4" w:color="D0D5DD"/>` +
		`<w:bottom w:val="single" w:sz="4" w:space="4" w:color="D0D5DD"/>` +
		`<w:right w:val="single" w:sz="4" w:space="4" w:color="D0D5DD"/></w:pBdr>` +
		`<w:shd w:val="clear" w:color="auto" w:fill="F8FAFC"/>` +
		`<w:spacing w:before="80" w:after="80" w:line="300" w:lineRule="auto"/>` +
		`<w:ind w:left="120" w:right="120" w:firstLine="0"/></w:pPr>` +
		runs.String() + `</w:p>`
}

var docxTechnicalSpanPattern = regexp.MustCompile(
	"`[^`]+`|https?://[^\\s，。；、）)]+|IL_[0-9A-Fa-f]+(-[0-9A-Fa-f]+)*|([A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+(:[0-9]+)?",
)

var docxImplementationPathPattern = regexp.MustCompile(
	`(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+(?::[0-9]+)?`,
)

func docxRichParagraph(value string, options docxTextOptions) string {
	return docxParagraphRuns(docxRichRuns(value), options)
}

func docxRichRuns(value string) []docxTextRun {
	value = strings.TrimSpace(strings.NewReplacer("**", "", "__", "").Replace(value))
	label := ""
	rest := value
	if index := strings.Index(value, "："); index > 0 && index <= 24 {
		label = value[:index+len("：")]
		rest = value[index+len("："):]
	} else if index := strings.Index(value, ":"); index > 0 && index <= 24 &&
		!strings.HasPrefix(strings.ToLower(value), "http") {
		label = value[:index+1]
		rest = value[index+1:]
	}
	runes := make([]docxTextRun, 0, 4)
	if strings.TrimSpace(label) != "" {
		runes = append(runes, docxTextRun{text: label, bold: true})
	}
	matches := docxTechnicalSpanPattern.FindAllStringIndex(rest, -1)
	cursor := 0
	for _, match := range matches {
		if match[0] > cursor {
			runes = append(runes, docxTextRun{text: rest[cursor:match[0]]})
		}
		token := strings.Trim(rest[match[0]:match[1]], "`")
		runes = append(runes, docxTextRun{text: token, code: true})
		cursor = match[1]
	}
	if cursor < len(rest) {
		runes = append(runes, docxTextRun{text: rest[cursor:]})
	}
	if len(runes) == 0 {
		runes = append(runes, docxTextRun{text: value})
	}
	return runes
}

func docxRichText(text, fallback string) string {
	text = docxMergeRepeatedLabel(text, "测试链路：")
	text = strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n"))
	if text == "" {
		return docxParagraph(fallback, docxTextOptions{})
	}

	var body strings.Builder
	var code strings.Builder
	inCode := false
	flushCode := func() {
		value := strings.Trim(code.String(), "\n")
		code.Reset()
		if value != "" {
			body.WriteString(docxCodeBlock(value))
		}
	}

	for _, raw := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "```") {
			if inCode {
				flushCode()
			}
			inCode = !inCode
			continue
		}
		if inCode {
			code.WriteString(raw)
			code.WriteByte('\n')
			continue
		}
		if trimmed == "" || (len(trimmed) >= 3 && strings.Trim(trimmed, "-") == "") {
			continue
		}
		if heading, ok := docxMarkdownHeading(trimmed); ok {
			body.WriteString(docxParagraph(heading, docxTextOptions{
				bold:           true,
				sizeHalfPoints: 21,
				before:         100,
				after:          60,
				keepNext:       true,
				noFirstLine:    true,
			}))
			continue
		}
		line := docxCleanInlineMarkdown(trimmed)
		if line == "" {
			continue
		}
		if item, ok := docxStripBullet(line); ok {
			body.WriteString(docxRichParagraph("• "+item, docxTextOptions{
				indent:      280,
				before:      30,
				after:       60,
				noFirstLine: true,
			}))
			continue
		}
		if docxIsNumberedLine(line) {
			body.WriteString(docxRichParagraph(line, docxTextOptions{
				indent:      280,
				before:      30,
				after:       60,
				noFirstLine: true,
			}))
			continue
		}
		body.WriteString(docxRichParagraph(line, docxTextOptions{
			before:      30,
			after:       80,
			noFirstLine: true,
		}))
	}
	if inCode {
		flushCode()
	}
	if body.Len() == 0 {
		return docxParagraph(fallback, docxTextOptions{})
	}
	return body.String()
}

func docxMarkdownHeading(value string) (string, bool) {
	level := 0
	for level < len(value) && value[level] == '#' {
		level++
	}
	if level == 0 || level >= len(value) || value[level] != ' ' {
		return "", false
	}
	heading := strings.TrimSpace(value[level:])
	return heading, heading != ""
}

func docxStripBullet(value string) (string, bool) {
	for _, prefix := range []string{"- ", "* ", "+ ", "• "} {
		if strings.HasPrefix(value, prefix) {
			item := strings.TrimSpace(strings.TrimPrefix(value, prefix))
			return item, item != ""
		}
	}
	return "", false
}

func docxIsNumberedLine(value string) bool {
	index := 0
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		index++
	}
	if index == 0 || index >= len(value) {
		return false
	}
	switch value[index] {
	case '.', ')':
		return true
	default:
		return strings.HasPrefix(value[index:], "、")
	}
}

func docxCleanInlineMarkdown(value string) string {
	return strings.TrimSpace(strings.NewReplacer(
		"**", "",
		"__", "",
		"`", "",
	).Replace(value))
}

func docxMergeRepeatedLabel(text, label string) string {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	first := -1
	values := make([]string, 0, 2)
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, label) {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(trimmed, label))
		if value == "" {
			continue
		}
		if first < 0 {
			first = index
		} else {
			lines[index] = ""
		}
		values = append(values, value)
	}
	if first >= 0 && len(values) > 1 {
		lines[first] = label + strings.Join(values, "；")
	}
	return strings.Join(lines, "\n")
}

func sortDocxVulnerabilities(findings []database.Vulnerability) []database.Vulnerability {
	sorted := append([]database.Vulnerability(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left := docxSeverityRank(sorted[i].Severity)
		right := docxSeverityRank(sorted[j].Severity)
		if left != right {
			return left > right
		}
		leftType := strings.ToLower(docxValue(sorted[i].VulnerabilityType, "未分类"))
		rightType := strings.ToLower(docxValue(sorted[j].VulnerabilityType, "未分类"))
		if leftType != rightType {
			return leftType < rightType
		}
		return sorted[i].UpdatedAt.After(sorted[j].UpdatedAt)
	})
	return sorted
}

func countDocxSeverities(findings []database.Vulnerability) map[string]int {
	counts := make(map[string]int, len(docxSeverityOrder))
	for _, item := range findings {
		counts[normalizeDocxSeverity(item.Severity)]++
	}
	return counts
}

func countDocxStatuses(findings []database.Vulnerability) map[string]int {
	counts := make(map[string]int, len(docxStatusOrder))
	for _, item := range findings {
		counts[normalizeDocxStatus(item.Status)]++
	}
	return counts
}

func normalizeDocxSeverity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "critical", "high", "medium", "low", "info":
		return value
	default:
		return "unknown"
	}
}

func normalizeDocxStatus(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "open", "confirmed", "fixed", "ignored", "false_positive":
		return value
	default:
		return "unknown"
	}
}

func docxSeverityRank(value string) int {
	switch normalizeDocxSeverity(value) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func docxSeverityLabel(value string) string {
	switch normalizeDocxSeverity(value) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	case "info":
		return "信息"
	default:
		return "未评级"
	}
}

func docxSeverityTagStyle(value string) (string, string) {
	switch normalizeDocxSeverity(value) {
	case "critical":
		return "FEE4E2", "B42318"
	case "high":
		return "FEF0C7", "B54708"
	case "medium":
		return "FEF7C3", "854A0E"
	case "low":
		return "DBEAFE", "175CD3"
	case "info":
		return "F2F4F7", "475467"
	default:
		return "EAECF0", "667085"
	}
}

func docxStatusTagStyle(value string) (string, string) {
	switch normalizeDocxStatus(value) {
	case "open":
		return "EAECF0", "344054"
	case "confirmed":
		return "FEE4E2", "B42318"
	case "fixed":
		return "D1FADF", "027A48"
	case "ignored":
		return "F2F4F7", "667085"
	case "false_positive":
		return "EAECF0", "667085"
	default:
		return "F2F4F7", "667085"
	}
}

func docxSeverityRecommendation(value string) string {
	switch normalizeDocxSeverity(value) {
	case "critical":
		return "立即处置，必要时启动应急响应"
	case "high":
		return "优先修复并安排复测"
	case "medium":
		return "纳入近期修复计划"
	case "low":
		return "结合版本迭代修复"
	case "info":
		return "按安全加固建议优化"
	default:
		return "补充风险评级后处置"
	}
}

func docxRetestAction(value string) string {
	switch normalizeDocxStatus(value) {
	case "open":
		return "完成修复后安排复测并补充验证证据"
	case "confirmed":
		return "优先安排复测，确认修复措施是否闭环"
	case "fixed":
		return "执行回归验证并保留复测记录"
	case "ignored":
		return "记录接受风险依据，按周期复核"
	case "false_positive":
		return "保留误报判定依据，无需重复测试"
	default:
		return "补充状态后进行复测安排"
	}
}

func docxStatusLabel(value string) string {
	switch normalizeDocxStatus(value) {
	case "open":
		return "待处理"
	case "confirmed":
		return "已确认"
	case "fixed":
		return "已修复"
	case "ignored":
		return "已忽略"
	case "false_positive":
		return "误报"
	default:
		return "未知"
	}
}

func docxProjectStatusLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "planning":
		return "规划中"
	case "active":
		return "进行中"
	case "paused":
		return "已暂停"
	case "done":
		return "已完成"
	case "archived":
		return "已归档"
	default:
		return docxValue(value, "未设置")
	}
}

func docxAssetStatusLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active":
		return "活跃"
	case "inactive":
		return "停用"
	case "archived":
		return "已归档"
	default:
		return docxValue(value, "未设置")
	}
}

func docxAssetKindLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "domain":
		return "域名"
	case "ip":
		return "IP"
	case "url":
		return "URL"
	case "service":
		return "服务"
	case "port":
		return "端口"
	case "host":
		return "主机"
	case "other":
		return "其他"
	default:
		return docxValue(value, "未设置")
	}
}

func docxCriticalityLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "核心"
	case "high":
		return "高"
	case "medium":
		return "中"
	case "low":
		return "低"
	default:
		return docxValue(value, "未设置")
	}
}

func docxRiskScoreLabel(score int) string {
	switch {
	case score >= 80:
		return fmt.Sprintf("%d（严重）", score)
	case score >= 60:
		return fmt.Sprintf("%d（高）", score)
	case score >= 40:
		return fmt.Sprintf("%d（中）", score)
	case score > 0:
		return fmt.Sprintf("%d（低）", score)
	default:
		return "0（未评分）"
	}
}

func docxAssetName(assetID string, assetNames map[string]string) string {
	assetID = strings.TrimSpace(assetID)
	if assetID == "" {
		return "-"
	}
	if name := strings.TrimSpace(assetNames[assetID]); name != "" {
		return name
	}
	return assetID
}

func docxPercent(value, total int) string {
	if total <= 0 {
		return "0.0%"
	}
	return fmt.Sprintf("%.1f%%", float64(value)*100/float64(total))
}

func docxValue(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func docxFormatTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Format("2006-01-02 15:04:05")
}
