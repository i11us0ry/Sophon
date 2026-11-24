package skillaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

type Issue struct {
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	Severity Severity `json:"severity"`
}

type Result struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Compliant  bool     `json:"compliant"`
	Issues     []Issue  `json:"issues"`
	SectionSet []string `json:"-"`
}

type Report struct {
	Root         string   `json:"root"`
	Total        int      `json:"total"`
	Compliant    int      `json:"compliant"`
	NonCompliant int      `json:"nonCompliant"`
	Results      []Result `json:"results"`
}

type frontmatter struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

var (
	headingPattern     = regexp.MustCompile(`(?m)^#{1,6}\s+(.+?)\s*$`)
	commandPattern     = regexp.MustCompile(`(?mi)(?:^|\s)(?:curl|wget|nmap|sqlmap|nuclei|ffuf|httpx|naabu|katana|python3?|bash|sh|terminal:|browser_navigate:)\b`)
	codeFencePattern   = regexp.MustCompile("(?m)^```")
	frontmatterPattern = regexp.MustCompile(`(?s)\A---\s*\n(.*?)\n---`)
)

var requiredSections = []struct {
	Code     string
	Message  string
	Keywords []string
}{
	{
		Code:     "missing_applicability",
		Message:  "缺少适用场景或不适用场景",
		Keywords: []string{"适用场景", "适用范围", "不适用场景"},
	},
	{
		Code:    "missing_core_judgment",
		Message: "缺少核心判断、判断框架或核心方法",
		Keywords: []string{
			"核心判断", "判断框架", "核心方法", "判断原则",
			"审计流程", "分析方法", "执行方法", "验证流程",
			"检查流程", "分析方法论", "流程",
		},
	},
	{
		Code:    "missing_evidence_standard",
		Message: "缺少证据标准或证据要求",
		Keywords: []string{
			"证据标准", "证据要求", "确认标准", "证据状态",
			"证据引用", "输出要求", "输出要素", "输出完整性",
		},
	},
	{
		Code:    "missing_decision_tree",
		Message: "缺少决策树、停止条件或换向条件",
		Keywords: []string{
			"决策树", "停止条件", "停止与换向", "换向条件", "停止或换向",
			"完成标志", "完成条件", "自检清单", "安全边界", "分级",
		},
	},
}

var forcedFlowPhrases = []string{
	"必须按以下步骤执行",
	"必须严格按",
	"只能依次执行",
	"不得改变执行顺序",
	"唯一执行路径",
}

func AuditDir(root string) (Report, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return Report{}, fmt.Errorf("Skill 目录不能为空")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return Report{}, fmt.Errorf("读取 Skill 目录失败: %w", err)
	}
	report := Report{Root: root, Results: make([]Result, 0)}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name(), "SKILL.md")
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		result := AuditContent(entry.Name(), string(raw), path)
		report.Results = append(report.Results, result)
		report.Total++
		if result.Compliant {
			report.Compliant++
		} else {
			report.NonCompliant++
		}
	}
	sort.Slice(report.Results, func(i, j int) bool {
		return report.Results[i].Name < report.Results[j].Name
	})
	return report, nil
}

func AuditContent(name, content, path string) Result {
	result := Result{
		Name:       strings.TrimSpace(name),
		Path:       strings.TrimSpace(path),
		Issues:     make([]Issue, 0),
		SectionSet: make([]string, 0),
	}
	front := parseFrontmatter(content)
	if strings.TrimSpace(front.Name) == "" {
		result.Issues = append(result.Issues, Issue{
			Code: "missing_frontmatter_name", Message: "frontmatter 缺少 name", Severity: SeverityError,
		})
	}
	if strings.TrimSpace(front.Description) == "" {
		result.Issues = append(result.Issues, Issue{
			Code: "missing_frontmatter_description", Message: "frontmatter 缺少 description", Severity: SeverityError,
		})
	}
	headings := collectHeadings(content)
	result.SectionSet = headings
	for _, section := range requiredSections {
		if !containsAnyHeading(headings, section.Keywords) {
			result.Issues = append(result.Issues, Issue{
				Code: section.Code, Message: section.Message, Severity: SeverityError,
			})
		}
	}
	if !containsAnyHeading(headings, []string{
		"常见误判", "误判", "注意事项", "禁止误报", "安全边界", "自检清单",
	}) {
		result.Issues = append(result.Issues, Issue{
			Code: "missing_misjudgment", Message: "缺少常见误判或注意事项", Severity: SeverityWarning,
		})
	}
	commandCount := len(commandPattern.FindAllStringIndex(content, -1))
	hasJudgment := containsAnyHeading(headings, []string{"核心判断", "判断框架", "核心方法", "判断原则"})
	hasEvidence := containsAnyHeading(headings, []string{"证据标准", "证据要求", "确认标准"})
	if commandCount >= 5 && (!hasJudgment || !hasEvidence) {
		result.Issues = append(result.Issues, Issue{
			Code:     "command_heavy_without_methodology",
			Message:  "命令或工具条目较多，但缺少核心判断或证据标准",
			Severity: SeverityWarning,
		})
	}
	if len(codeFencePattern.FindAllStringIndex(content, -1)) >= 8 && !hasJudgment {
		result.Issues = append(result.Issues, Issue{
			Code:     "code_heavy_without_methodology",
			Message:  "代码块或命令清单过多，缺少方法论层",
			Severity: SeverityWarning,
		})
	}
	for _, phrase := range forcedFlowPhrases {
		if strings.Contains(content, phrase) {
			result.Issues = append(result.Issues, Issue{
				Code:     "forced_workflow",
				Message:  "包含强制固定流程措辞：" + phrase,
				Severity: SeverityWarning,
			})
			break
		}
	}
	result.Compliant = !hasBlockingIssue(result.Issues)
	return result
}

func Template(name, description string) string {
	name = strings.TrimSpace(name)
	description = strings.TrimSpace(description)
	if description == "" {
		description = name
	}
	return fmt.Sprintf(`---
name: %s
description: %q
metadata:
  tags: []
---

# %s

## 适用场景

说明什么目标、信号或问题适合使用本 Skill。

## 不适用场景

说明哪些情况不应机械套用本 Skill。

## 核心判断

说明这类问题真正需要判断什么，以及哪些现象没有实际意义。

## 需要观察的信号

- 入口、参数和权限边界
- 数据流、状态和配置
- 响应差异、错误和可观测证据
- 已有事实、漏洞和重复测试记录

## 候选假设空间

列出候选漏洞类型、成立条件和可能的前置依赖。候选空间不是覆盖清单。

## 测试方法

- 基线和对照
- 等价表达与绕过维度
- 最小验证步骤
- 可选工具、命令和请求示例

## 证据标准

- 哪些证据可以升级为 confirmed
- 哪些只能标记 suspicious 或 conditional
- 哪些结果应判断为 tested_clean、blocked 或 false positive

## 决策树

- 出现什么结果继续深挖
- 出现什么结果切换方向
- 出现什么结果降低结论等级
- 出现什么结果立即停止

## 常见误判

- 扫描器命中
- 版本指纹
- WAF 或网关错误
- 参数名相似
- 响应差异但没有安全影响

## 可选工具与示例

工具、命令和 payload 仅作为候选手段，不是强制执行顺序。
`, name, description, name)
}

func parseFrontmatter(content string) frontmatter {
	match := frontmatterPattern.FindStringSubmatch(content)
	if len(match) != 2 {
		return frontmatter{}
	}
	var parsed frontmatter
	_ = yaml.Unmarshal([]byte(match[1]), &parsed)
	return parsed
}

func collectHeadings(content string) []string {
	matches := headingPattern.FindAllStringSubmatch(content, -1)
	headings := make([]string, 0, len(matches))
	seen := make(map[string]bool, len(matches))
	for _, match := range matches {
		if len(match) != 2 {
			continue
		}
		value := normalizeHeading(match[1])
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		headings = append(headings, value)
	}
	return headings
}

func normalizeHeading(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Trim(value, "#*_`：: ")
	return value
}

func containsAnyHeading(headings []string, keywords []string) bool {
	for _, heading := range headings {
		for _, keyword := range keywords {
			if strings.Contains(heading, strings.ToLower(keyword)) {
				return true
			}
		}
	}
	return false
}

func hasBlockingIssue(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == SeverityError {
			return true
		}
	}
	return false
}
