---
name: php-file-read-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, 文件读取, 路径穿越]
---

# PHP 任意文件读取审计（php-file-read-audit）

分析 PHP 项目源码，识别文件读取与包含执行风险：路径穿越导致任意文件读取、包含任意文件（include/require）导致信息泄露或代码执行（当包含的是可执行内容/或受流包装器影响）。

## 适用场景

适合发现 `file_get_contents/readfile/fopen/include/require` 等文件读取或包含 Sink，需要判断路径来源、规范化、wrapper 和执行边界。

## 不适用场景

只有文件函数命中时，不能直接认定任意文件读取。必须证明路径可控、规范化可绕过或包含目标实际可执行。

## 核心判断

文件读取风险取决于路径来源、basePath 校验、wrapper 过滤、最终解析目标和文件内容用途。读取和 include 执行面必须分开判断。

## 证据标准

- Source 到文件 Sink 的路径和数据流。
- 路径过滤、realpath、basePath 和 wrapper 处理。
- 最终解析到的真实文件或资源。
- include 场景需要内容类型和执行面证据。

## 决策树

- 路径直接来自请求：检查穿越和编码变体。
- 有 basePath 校验：检查规范化顺序和符号链接。
- wrapper 可用：检查最终协议和资源目标。
- include/require：检查是否执行 PHP 以及配置边界。
- 只能读取固定模板：不升级为任意文件读取。

## 常见误判

- 有 `../` 过滤就认定安全。
- 忽略 URL 编码、混合分隔符和 wrapper。
- 把 include 路径可控直接当成 RCE。
- 不检查最终解析目标。
- 读取非敏感文件也标记高危。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-FILE-{序号}`

## FILE Sink（按需）识别以下函数/语法：
- 读取：`file_get_contents/readfile/fopen/stream_get_contents/file/Storage::get`
- 包含：`include/require/include_once/require_once`（路径拼接风险尤其高危）
- 压缩/归档：`ZipArchive->open`（若路径可控）
- 流包装/过滤：`php://filter`、`php://input`（若被作为文件内容读取/包含）
危险：当 `allow_url_fopen/allow_url_include` 或 wrapper 允许时，读取/包含可跨协议
危险模式：
- 读取/包含路径变量直接来自用户输入
- 路径拼接未做规范化与 basePath 校验
- 允许 `file://`、`php://`、`data://`、`zip://` 等流包装且未限制
- 在 include/require 场景存在 `allow_url_include=On` 或通过配置/封装间接开启网络/跨协议 include 的证据

## 路径穿越检测（按需）可分析并给出证据：
- 是否过滤 `../`、`..\\`、混合分隔符
- 是否做 `realpath/canonicalize` 并用 basePath 校验前缀
- 是否处理流包装器（wrapper）前缀：`php://`、`file://`、`phar://`、`zip://` 等（必须逐项证据化）
- 编码/双重编码/大小写/尾部空格/`\0`（旧版本 PHP）绕过可能性
- 是否对后缀/扩展名做白名单，并且白名单不易绕过

## 包含执行判定（建议：提升真阳性）
当检测到 `include/require*` 使用可控路径时，形成结论时说明以下判定证据（不能跳过）：
1. **包含内容类型**：包含目标是否可能被当作 PHP 代码执行（例如扩展名/解析方式/执行路径证据）
2. **包含路径的最终解析结果**：wrapper 解析后是否仍指向可控资源
3. **执行面边界**：include/require 是否位于异常处理、return/throw 分支之后（即使能读也可能不执行）
4. **配置证据**：是否存在 `allow_url_include=On`、或 `auto_prepend_file/auto_append_file`、或自定义封装对 include 的放行点

## tracer 使用条件
- 存在分支：校验逻辑是否只在某路径分支生效

## 报告建议
将证据支持的结论写回项目审计台账或最终报告，不创建空文件。

## 漏洞记录建议
- 位置证据
- 数据流链（Source→Sink，包含路径拼接与校验分支）
- 证据引用（来自 `php-route-tracer` 输出，有对应 trace 时优先引用）：有 trace 时对应引用，否则直接使用源码证据 的 `## 9) Sink Evidence Type Checklist`（FILE 行）中的证据要点
  - `EVID_FILE_WRAPPER_PREFIX`：wrapper/流包装前缀（如 `php://`/`phar://`/`zip://` 等）
  - `EVID_FILE_RESOLVED_TARGET`：final/resolved target（wrapper 解析后的最终目标）
  - `EVID_FILE_INCLUDE_REQUIRE_EXEC_BOUNDARY`：include/require 执行面边界（是否会执行 PHP 代码 vs 仅读取内容/报错；该证据点也可包含与 allow_url_include/封装放行相关的证据）
- 可利用前置条件（鉴权/输入可控性/触发条件）
- 可执行 PoC（HTTP 请求，含真实路由）
- 建议修复（basePath 校验 + 流包装禁用策略 + include/require 的安全替代要点 + 代码搜索语句）

## tracer 证据使用说明

