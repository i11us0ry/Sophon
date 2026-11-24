---
name: php-archive-extract-audit
description: >-
  用于安全审计方法分析、技术验证和项目结论写回
metadata:
  tags: [代码审计, php, 解压, zip_slip, 路径穿越]
---

# PHP 归档解压路径穿越审计（php-archive-extract-audit）

分析 PHP 项目中“解压/提取归档文件到磁盘目录”的实现逻辑。重点审计 Zip Slip 类问题：攻击者可通过精心构造归档条目名（entry name/path）使最终写入落点逃逸目标目录。

## 适用场景

适合上传归档、导入压缩包、主题或插件安装等会解压多个 entry 的流程，需要判断 entry 路径、解压根目录、库行为和最终落点。

## 不适用场景

只发现 `extractTo`、只允许上传归档或归档中存在 `../` 名称，都不能直接证明文件写出目标目录。所用库或封装已经安全归一化、拒绝穿越 entry，或解压结果不可触达时，应降级或判为否。

## 核心判断

Zip Slip 的关键不是归档里存在异常文件名，而是攻击者能否控制 entry，且解压实现基于未受约束的最终解析路径写出基目录。需要区分库内建保护、调用方过滤和操作系统路径解释。

## 证据标准

- 可确认：entry 来源、解压基目录、最终解析落点和目录外写入效果形成闭环；最好能观察到落点存在或可访问。
- 待验证：静态链路显示可能逃逸，但解压库版本、路径归一化、运行平台或写权限尚未确认。
- 判为否：entry 被可靠拒绝或安全拼接、最终解析路径始终位于基目录，或解压链路不可由目标入口触发。

## 决策树

- 找到解压 sink：确认使用的库、调用方式和实际解压目录。
- 可控制归档：检查 entry 是否由调用方逐项处理，以及库是否自身过滤穿越路径。
- 存在路径拼接：按运行平台归一化后判断最终解析落点，不只检查字符串中是否含 `../`。
- 落点可计算但无法触达：保留环境依赖，不直接确认可利用。
- 已观察到目录外写入：再评估文件类型、权限和后续访问影响。

## 常见误判

- 归档包含 `../` 但解压库已安全丢弃或重命名该 entry。
- 只控制归档文件内容，不能控制归档中的 entry 名称。
- 目标目录参数可控但运行用户没有对应写权限。
- 只看初始路径字符串，忽略最终规范化、符号链接和平台差异。
- 为验证生成覆盖系统文件或业务配置的不可逆写入。

## 分级与编号
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-ARCHIVE-{序号}`

## ARCHIVE Sink（按需）识别并追踪归档提取调用点，至少包括：
- `ZipArchive->extractTo($destination, {value})`
- `ZipArchive->extract($destination, {value})`（若项目使用封装）
- `PharData->extractTo($destination, {value})`
- `Archive_Tar->extractTo($destination, {value})`（若项目使用 PEAR/等价封装）
- `Archive_Tar->extract($destination, {value})`（若项目使用封装）
- 自定义解压封装：最终仍对每个 entry name 做“拼接到 destination 目录并落盘”

## 必检证据点（可选：可与 trace 交叉核对）
每条 ARCHIVE 疑似漏洞有对应 trace 时优先引用 `php-route-tracer` trace 输出中 `## 9) Sink Evidence Type Checklist` 的 **ARCHIVE 行**对应证据要点（有 trace 时引用；没有 trace 时直接使用源码位置、参数流和 Sink 证据）：
1. `EVID_ARCHIVE_EXTRACT_CALLSITE`：归档解压/提取调用点证据（extractTo/extractTo 包装函数入口）
2. `EVID_ARCHIVE_ENTRY_NAME_SOURCE`：entry name/path 来源证据（来自归档内容的 entry 列表，或由用户输入构造的条目路径）
3. `EVID_ARCHIVE_ENTRY_SANITIZATION`：条目路径净化/归一化证据（去除/拒绝 `../`、绝对路径、盘符等路径穿越片段；以及如何处理编码/同形字符）
4. `EVID_ARCHIVE_EXTRACT_BASE_DIR`：解压基目录证据（destination/base directory 的来源与传入方式）
5. `EVID_ARCHIVE_FINAL_TARGET`：最终解析落点证据（entry join 后的 resolved final path，以及 base 目录约束判定是否成立）

## 可利用性与漏洞成立条件（按需）按需判断：
- entry name/path 是否可被攻击者控制（至少来自 attacker's crafted zip 的条目）
- 基目录约束是否真正执行到“最终路径解析之后”（例如 `realpath` + 前缀校验，而不是仅字符串替换）
- 是否存在绕过：双重编码、混合分隔符、windows 盘符、绝对路径、尾部/空白/控制字符、Unicode 同形字符等
- 写入是否真的发生在目标目录之外（或至少能够证明 final target 逃逸）

## tracer 使用条件
- destination/base directory 或 entry name 经过多层函数/对象封装后才进入 extractTo
- entry name 列表或解压路径存在分支逻辑（某些 entry 才被过滤/某些分支未过滤）

## 报告建议
将证据支持的结论写回项目审计台账或最终报告，不创建空文件。

## 漏洞记录建议
### [{等级前缀}-ARCHIVE-{序号}] 归档解压路径穿越（Zip Slip）风险

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function/Class}) |

#### 数据流链（Source -> Transform -> Sink）
（逐行写出：归档 entry name/path 进入 -> 净化/归一化 -> base destination join -> resolved final target -> 是否逃逸 base 约束 -> 实际写入/提取调用点）

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常路径/需要特定归档格式/需要特定服务器文件权限}

#### 证据引用（可参考 php-route-tracer）
有对应 trace 时优先引用：
- `EVID_ARCHIVE_EXTRACT_CALLSITE`：{证据点简述}
- `EVID_ARCHIVE_ENTRY_NAME_SOURCE`：{证据点简述}
- `EVID_ARCHIVE_ENTRY_SANITIZATION`：{证据点简述（缺失则写“未发现过滤/归一化不足”并给出 trace 证据）}
- `EVID_ARCHIVE_EXTRACT_BASE_DIR`：{证据点简述}
- `EVID_ARCHIVE_FINAL_TARGET`：{证据点简述（说明 resolved target 是否逃逸）}

#### 验证 PoC（按需：可观测验证框架）
```http
{HTTP Method} {真实路由与完整参数} HTTP/1.1
Host: {host}
{必要 Header/Session/JWT/Cookie}

{Payload}
```
PoC 生成/触发策略（必须写清楚你要观察什么）：
- 制作恶意归档，包含路径穿越 entry，例如 `../../../../var/www/html/pwn.php`（或 Windows 路径变体）
- 触发解压路由（通常是上传归档/或提供可下载 URL 后由服务端解压）
- 观察点：目标目录之外是否出现文件、是否能访问到落点（取决于站点权限/可写目录策略）

#### 建议修复
- 以“最终解析落点”为准：对 entry name 做规范化后执行 `realpath` + base 前缀校验
- 禁止 absolute path/盘符/反斜杠分隔/目录上跳：entry name 发现穿越片段直接拒绝或跳过
- 在归档处理流程中对 entry name 列表做统一净化，并对解压过程强制一致的 base 约束
- 给出代码搜索语句：`rg` 定位所有 `extractTo`/`extract`/归档解压封装入口与 destination 拼接逻辑
```

## tracer 证据使用说明

