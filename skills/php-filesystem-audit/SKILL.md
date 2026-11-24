---
name: php-filesystem-audit
metadata:
  tags: [代码审计, php, 文件系统, 权限, toctou]
description: PHP 文件系统操作审计工具。聚焦 mkdir/chmod/chown/unlink/rmdir/link/symlink/readlink/touch/权限与 TOCTOU 等操作的安全风险，为路径校验绕过与写入链利用提供“可利用性增强证据”（不替代 FILE/UPLOAD/WRITE 等 sink 子审计）。
---

# PHP 文件系统操作审计（php-filesystem-audit）

分析 PHP 项目中对文件系统的关键操作，特别关注这些操作如何与：

- 路径校验/归一化失败（目录遍历、basePath 缺失）
- 落点写入/读取/包含链路
- 写后触发（可执行性、可包含性）
- 竞争条件（TOCTOU）

发生联动，从而提升真实利用可能性。

## 适用场景

适合 `mkdir/chmod/symlink/unlink/rename` 等操作与路径控制、文件读写、上传落点或并发流程联动，需要判断它们是否产生独立安全效果或增强其他漏洞链路。

## 不适用场景

只统计危险函数命中不能证明漏洞。操作参数固定、路径不可控、权限由平台稳定约束，或没有可达入口和后续链路时，应记录为候选或代码风险，而不是可利用漏洞。

## 核心判断

文件系统操作本身通常是攻击链中的能力或前置条件。关键判断是它改变了什么安全状态：创建可写落点、改变权限、替换链接目标、删除防护文件，还是打开可利用的竞态窗口。

## 证据标准

- 可确认：操作入口、路径来源、实际状态变化和后续安全影响证据闭合。
- 待验证：存在路径控制或 TOCTOU 形态，但入口、权限、时序窗口或链路效果尚未证明。
- 判为否：路径固定、权限不可影响、文件状态变化不可观测，或后续链路没有安全效果。

## 决策树

- 找到文件系统操作：确认路径来源和调用身份。
- 与写入/上传/包含链关联：判断操作是否为危险落点提供条件。
- 涉及链接或重命名：检查解析时机、所有权和符号链接策略。
- 涉及 TOCTOU：确认检查点与使用点之间存在可竞争状态，而不是仅代码相邻。
- 只有函数调用没有状态变化：保留为审计信号，不生成已确认漏洞。

## 常见误判

- 把 `chmod/chown/symlink/unlink` 命中直接等同于提权或任意删除。
- 认为先检查后使用必然可利用，未证明竞态窗口和影响。
- 忽略进程权限、挂载选项、容器只读层和操作系统行为。
- 将后台清理任务的风险写成可由 HTTP 触发。
- 为验证效果删除真实业务文件或修改关键目录权限。

## 覆盖范围（按需）可覆盖并输出“证据点 + 风险解释 + 可利用性判断”的点：

### 1) 创建/目录操作
- `mkdir($path, $mode, $recursive)`
- `rmdir($path)`
- `touch($path)`
- `tmpfile()` / `tempnam()`
- 框架封装的目录创建（如 `Storage::put`/`ensureDirectory` 的底层封装，若识别得到）

### 2) 权限/所有权变更（常用于提权链或绕过执行策略）
- `chmod/chown/chgrp`
- `umask`

### 3) 链接与重定向落点（常见 symlink/hardlink 绕过）
- `symlink($target, $link)`
- `link($target, $link)`
- `readlink($path)`

### 4) 删除与清理（结合 TOCTOU 或覆盖链）
- `unlink($path)`
- `unlink/rename` 变体删除
- `rename($src, $dest)`（用于落点变更时需特别关注 TOCTOU）
- `copy/move` 变体（当作为“落点准备步骤”出现）

### 5) 路径竞态与 TOCTOU（可按需审计）
对“检查-使用分离”的代码模式给出判定：
- 是否存在 `if (realpath/canonicalize + 前缀校验)` 后又在某个分支/异常处理里重复 join/open/write（路径可能变化）
- 是否存在先判断可写/再写入、先检查再执行文件操作
- 是否存在符号链接解析/不一致解析（检查时与实际打开时 resolved path 不一致）

## 关键写回要求（可选）每条发现可包含：

1. 位置证据：文件路径与函数/调用点（尽量带行号；找不到行号则标注待定位）
2. 操作类型：创建/权限/链接/删除/重命名/拷贝等
3. 路径控制来源：路径参数来自 GET/POST/SESSION/配置还是硬编码
4. 跟链路的关系（必须至少选一条说明）：
   - 与 `WRITE`/`UPLOAD` 落点可执行性或可包含性关联
   - 与 `FILE`（读取/包含）或 `ARCHIVE`（解压落点）关联
   - 与鉴权/资源归属关联（例如仅管理员目录有写权限但绕过）
   - 与 TOCTOU 竞态关联（检查点 -> 使用点之间路径可能被替换）
5. 可利用性判断：
   - ✅ 已确认：能证明利用链的关键前置条件由此文件系统操作提供（或与 WRITE/UPLOAD/FILE 的证据形成闭环）
   - ⚠️ 待验证：存在风险，但缺少某个关键前置条件或 trace/解析证据不足
   - ❌ 不可利用：有强约束（baseDir allowlist 生效、resolved path 一致性保护、权限固定且无法更改、竞态窗口被消除）
   - 🔍 环境依赖：需依赖特定文件系统/权限/并发时序/服务端目录结构

6. 可触发性参考：
   - 对能够关联到具体 HTTP 路由或入口的文件系统操作，可优先补充真实路由和参数用于验证。
   - 若暂时无法定位入口，可标记“入口待补证”，并保留源码证据和可能的触发条件。

## 报告建议
将证据支持的结论写回项目审计台账或最终报告，不创建空文件。
```

## 漏洞编号规范（建议：FS）
- 详见：`shared/SEVERITY_RATING.md`
- 漏洞编号：`{C/H/M/L}-FS-{序号}`

## 漏洞记录建议
```markdown
### [{等级前缀}-FS-{序号}] 文件系统操作链风险（权限/链接/删除/TOCTOU/路径控制）

| 项目 | 信息 |
|------|------|
| 严重等级 | {🔴/🟠/🟡/🔵} (CVSS {score}) |
| 可达性 (R) | {0-3} - {理由} |
| 影响范围 (I) | {0-3} - {理由} |
| 利用复杂度 (C) | {0-3} - {理由} |
| 可利用性 | ✅ 已确认 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖 |
| 位置 | {file}:{line} ({Function/Class}) |

#### 数据流链（Source → Path Control → FS Operation → Chain Influence）
（逐行写出：用户/上下文输入如何进入路径控制变量、是否经过 realpath/canonicalize 及前缀校验、最终如何落到 mkdir/chown/symlink/unlink/rename/等文件系统操作参数、以及该文件系统操作如何影响后续链路能力：WRITE/UPLOAD/FILE/ARCHIVE/CMD/TPL/EXPR/DESER 等）

#### 可利用前置条件
- 鉴权要求：{无需/需登录/需特定权限}
- 输入可控性：{完全可控/条件可控/不可控}
- 触发条件：{分支/异常路径/需要特定文件系统权限/需要竞态窗口/需要特定目录结构}
- 链路承接：{它如何为其它 sink 类别提供“可利用性增强”说明（写入落点/可包含性/权限提升/绕过执行策略/触发竞态）}

#### 验证 PoC（按需：可观测验证框架）
```http
{HTTP Method} {真实路由与完整参数} HTTP/1.1
Host: {host}
{必要 Header/Session/JWT/Cookie}

{Payload}
```

PoC 输出/观察点（必须写清楚）：
1. 由该 FS 操作造成的文件系统状态变化是否可观测（例如：目标路径下文件创建/权限变化/链接指向变化/删除结果/最终落点存在性）。
2. 若为 TOCTOU：展示“检查点与使用点 resolved path 不一致/窗口可被利用”的可观测现象（例如并发触发导致最终落点改变）。

#### 证据引用（可参考源码片段）
必须至少包含三段与定位对应的证据片段（可以直接在文本中复述关键行）：
1. FS 操作调用点（mkdir/chmod/chown/symlink/unlink/rename 等）及参数位置（file:line）
2. 路径校验/归一化逻辑（realpath/canonicalize/baseDir 前缀校验）及其与 FS 操作之间的关系（同一函数内或跨函数）
3. 路径控制来源（GET/POST/SESSION/配置硬编码等）及其传递链

#### 建议修复
- 路径校验与实际使用必须绑定到同一个 resolved target：`realpath`/canonicalize 后用同一个值进行 open/rename/write（避免 TOCTOU）
- 禁止对可被攻击者影响的路径进行“先校验后使用”的拆分；若必须拆分，应在同一系统调用/同一文件描述符上下文内完成
- 对 symlink/hardlink：在目标落点启用防链接策略（平台支持时禁用跟随符号链接，或基于 inode/文件描述符校验一致性）
- 权限变更必须最小化并确保不可由用户影响；避免攻击者能控制 `chmod/chown` 的路径

#### 代码搜索语句（可选）
```text
rg -n "(mkdir\\(|rmdir\\(|touch\\(|tmpfile\\(|tempnam\\(|chmod\\(|chown\\(|chgrp\\(|symlink\\(|readlink\\(|link\\(|unlink\\(|rename\\(|copy\\(|symlink\\()" .
rg -n "(realpath\\(|canonicalize\\(|dirname\\(|basename\\(|baseDir|dest(path)?|target(path)?)" .
```

## 修复建议（可选要点）
- 路径校验与实际使用必须绑定到同一个 resolved target：`realpath`/canonicalize 后用同一个值进行 open/rename/write（避免 TOCTOU）
- 禁止对可被攻击者影响的路径进行“先校验后使用”的拆分；若必须拆分，应在同一系统调用/同一文件描述符上下文内完成
- 对 symlink/hardlink：在目标落点上启用防链接策略（平台支持时禁用跟随符号链接，或基于 inode/文件描述符校验一致性）
- 权限变更必须最小化并确保不可由用户影响；避免攻击者能控制 `chmod/chown` 的路径

