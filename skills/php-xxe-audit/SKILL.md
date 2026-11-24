---
name: php-xxe-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, xxe, xml]
---

# PHP XXE 审计（php-xxe-audit）

分析 PHP 项目源码，识别 XXE（XML External Entity）风险：当 XML 解析点允许外部实体/DOCTYPE，且 XML 输入可控、并存在回显或 OOB 通道时，可能导致文件读取/SSRF/DoS。

## 适用场景

适合 XML 或包含 DTD 的文档进入解析器，需要判断输入是否可控、外部实体是否实际启用，以及是否存在文件读取、网络请求或错误回显通道。

## 不适用场景

只发现 `DOMDocument`、`SimpleXML` 或 XML 请求参数不能直接认定 XXE。解析器已禁用外部实体、输入是可信固定 XML、DOCTYPE 被拒绝，或解析结果没有任何可观测通道时，需要降级或判为否。

## 核心判断

XXE 成立需要同时满足 XML 输入可控、DOCTYPE/外部实体可被解析，以及存在可观测的读取、外联或错误影响。PHP/libxml 版本和解析时的安全选项决定实际行为。

## 证据标准

- 可确认：解析入口、XML 输入映射、实体配置和回显/OOB 效果证据闭合。
- 待验证：存在可控 XML 和危险配置候选，但解析器版本、防护选项、DOCTYPE 处理或输出通道尚未确认。
- 判为否：外部实体不可用、输入不可控、网络与文件访问被阻断，或解析结果没有安全可观测影响。

## 决策树

- 找到 XML 解析器：确认库、版本和加载选项。
- 检查输入来源：判断请求体、文件或字符串是否真正进入解析。
- 检查实体与 DOCTYPE：核对安全参数和禁用策略是否对应实际解析器。
- 检查输出：区分直接回显、错误型通道、Blind OOB 和完全不可观测。
- 只有解析器错误：先证明实体展开，不把普通 XML 语法错误当成 XXE。

## 常见误判

- 只看到 XML 解析函数就认定外部实体已启用。
- 使用 `LIBXML_NONET` 就认为所有文件读取路径都被消除。
- 把解析失败、500 错误或响应差异直接当成实体读取成功。
- 忽略 PHP/libxml 版本差异和全局实体加载配置。
- 在验证时读取真实密钥、凭据或大规模敏感文件。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-XXE-{序号}`

## XXE Sink（按需）识别 XML 解析相关：
- `DOMDocument->loadXML/loadHTML`
- `simplexml_load_string/simplexml_load_file`
- `XMLReader->open/xml`
- `DOMDocument->load`（若内容来自用户可控字符串/流）
危险模式：
- 未禁用外部实体/未限制网络访问
- 解析参数允许 DOCTYPE

## 防护检查（按需）形成结论时说明解析器防护证据：
- libxml 安全参数：`LIBXML_NONET`、`LIBXML_NOENT`（注意：NOENT 可能放大风险）、`LIBXML_DTDLOAD` 等使用情况
- 是否使用：`libxml_disable_entity_loader(true)`（不同 PHP 版本策略不同，仍需给证据）
- 解析时是否传入安全选项并禁用网络访问

## 输入来源与回显
- XML 输入来源：`$_POST`/`php://input`/上传文件流等
- 回显路径：是否把解析结果写回响应（`echo`/模板输出）或仅 Blind（OOB）。

## tracer 使用条件
- 回显位置不清晰或在工具类中

## 证据引用（有 trace 时）
每条 XXE 疑似漏洞有对应 trace 时优先引用 trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **XXE 行**对应证据要点（有 trace 时引用；没有 trace 时直接使用源码位置、参数流和 Sink 证据）：
1. `EVID_XXE_PARSER_CALL`：XML 解析器调用点位置证据（DOMDocument->loadXML/simplexml_load_string/XMLReader->open 等）
2. `EVID_XXE_INPUT_SOURCE`：输入流来源证据（$_POST/`php://input`/上传读取/参数进入解析的对应证据）
3. `EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO`：外部实体/DOCTYPE 禁用相关安全选项证据（LIBXML_* 或禁用策略）以及解析结果回显位置证据

## 报告建议
将证据支持的结论写回项目审计台账或最终报告，不创建空文件。

