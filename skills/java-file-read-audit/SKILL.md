---
name: java-file-read-audit
metadata:
  tags: [代码审计, java, 文件读取, 路径穿越]
description: Java Web 源码任意文件读取漏洞审计工具。从源码中识别所有文件读取操作并检测路径遍历漏洞。适用于：(1) 识别文件读取框架和实现方式，(2) 发现任意文件读取漏洞，(3) 检测路径遍历漏洞，(4) 审计文件路径参数校验逻辑。支持 BufferedReader、Scanner、Files.lines/readAllLines/readAllBytes 等方法。**支持反编译 .class/.jar 文件提取文件操作逻辑**。结合 java-route-mapper 使用可实现完整的路由+文件读取审计。
---

# Java 文件读取漏洞审计工具

检查 Java Web 项目源码，识别文件读取操作实现，检测任意文件读取和路径遍历漏洞。

## 适用场景

适合下载、预览、日志、配置或模板读取接口，需要判断请求参数是否进入文件路径，以及规范化后的最终路径是否仍位于允许目录。

## 不适用场景

看到 `FileInputStream`、`Files.readAllBytes` 或路径包含用户输入不能直接确认任意文件读取。固定文件、只读取允许目录、路径被可靠规范化，或响应不能返回文件内容时，需要降级或判为否。

## 核心判断

关键是用户输入能否改变最终打开的文件，而不是代码中是否出现路径拼接。需要检查 canonical/absolute 路径、base 前缀、符号链接、扩展名、运行权限和内容返回通道。

## 证据标准

- 可确认：真实路由、路径来源、约束缺口、最终解析落点和文件内容读取效果证据闭合。
- 待验证：存在可控路径或危险拼接，但规范化方式、落点、权限或响应通道尚未确认。
- 判为否：路径固定、最终解析路径受可靠目录约束、文件不可读，或读取结果不会返回给攻击者。

## 决策树

- 找到读取 sink：回查 path 的来源和规范化过程。
- 检查目录约束：优先验证 canonical/absolute 路径后的 base 前缀比较。
- 检查文件名处理：区分 basename、扩展名和用户可控子目录的影响。
- 检查运行条件：确认文件权限、部署路径和响应下载/回显通道。
- 只存在拼接字符串：先证明最终读取效果，不直接定级。

## 常见误判

- `base + userInput` 形式就认定可路径穿越。
- 字符串包含 `..` 检查可靠，忽略编码、分隔符和规范化顺序。
- `getCanonicalPath()` 存在但前缀比较在对目标不存在的路径上失真。
- 文件可读但接口只返回大小或哈希，不能证明内容泄露。
- 为验证读取真实私钥、数据库或大规模敏感文件。

## 与路由分析协作（可选）

已有路由映射结果时，可用于定位入口和参数；没有时直接从源码、字节码和当前审计目标开始，不要求检查或生成任何上游文件。

### 已有路由结果时可利用的信息

| 信息 | 用途 |
|:-----|:-----|
| 路由路径 | 定位 Controller/Action 入口 |
| 参数名 + 类型 | 识别 String 类型高危参数 |
| JSON 内部字段 | 识别嵌套参数（如 `fileInfo.path`） |
| 参数用途描述 | 判断是否用于文件路径 |

---

## 工作流程（三阶段）

### 阶段1: 快速扫描（优先执行）

**目标：快速定位文件读取相关代码，不遗漏关键点。**

```bash
# 1.1 搜索文件读取方法
grep -ri "BufferedReader\|FileReader\|FileInputStream" --include="*.java"
grep -ri "Scanner.*File\|Scanner.*Path" --include="*.java"
grep -ri "Files.lines\|Files.readAllLines\|Files.readAllBytes" --include="*.java"

# 1.2 搜索文件下载/读取接口
grep -ri "download\|readFile\|getFile\|viewFile" --include="*.java"
grep -ri "@RequestMapping.*download\|@GetMapping.*download" --include="*.java"

# 1.3 搜索路径拼接模式
grep -ri "new File.*\+" --include="*.java"
grep -ri "Paths.get.*\+" --include="*.java"
grep -ri "File.separator" --include="*.java"

# 1.4 搜索路径参数
grep -ri "filePath\|fileName\|file\|path" --include="*.java" | grep "@RequestParam\|@PathVariable"
```

**输出：高危文件清单（按优先级排序）**

| 优先级 | 文件类型 | 审计重点 |
|:-------|:---------|:---------|
| P0 | `*Controller.java` 中包含 download/readFile 的方法 | filePath, fileName 参数 |
| P1 | `*Service.java`, `*ServiceImpl.java` | 文件路径处理逻辑 |
| P2 | `*Util.java`, `*Helper.java` | 通用文件读取方法 |
| P3 | `*Dao.java`, `*Repository.java` | 配置文件读取 |

### 阶段2: 参数-文件路径映射检查

**基于 java-route-mapper 的输出，检查每个参数是否用作文件路径。**

#### 2.1 高危参数识别

从 route_mapper 输出中提取所有 String 类型参数：

| 参数来源 | 参数名 | 类型 | 文件读取漏洞可能性 |
|:---------|:-------|:-----|:-------------|
| @RequestParam | `filePath` | String | **高危** - 直接用作路径 |
| @RequestParam | `fileName` | String | **高危** - 文件名拼接 |
| @RequestParam | `file` | String | **高危** - 文件路径 |
| @PathVariable | `path` | String | **高危** - URL 路径参数 |
| JSON | `fileInfo.path` | String | **高危** - JSON 内部字段 |

#### 2.2 参数追踪

对每个高危参数，追踪其在代码中的使用：

```
HTTP 参数: filePath (String)
    ↓ 传递
Controller.download(filePath)
    ↓ 传递
Service.readFile(filePath)
    ↓ 拼接
basePath + File.separator + filePath
    ↓ 使用
new FileInputStream(fullPath)  ← 文件读取点
```

#### 2.3 文件读取点检查

对阶段1发现的每个文件读取点，检查：

1. **文件路径是否可控？**
   - 完全来自用户输入 → 高危
   - 基础路径固定 + 用户输入文件名 → 中危
   - 完全硬编码 → 安全

2. **是否有路径校验？**
   - 白名单目录限制 → 安全
   - 文件扩展名校验 → 可能绕过
   - 无校验 → 高危

3. **是否过滤路径遍历字符？**
   - 过滤 `../`, `..\\` → 可能安全（需测试绕过）
   - 无过滤 → 高危

### 阶段3: 深入检查与报告

#### 3.1 触发 java-route-tracer

当发现以下情况时，调用 java-route-tracer 获取完整调用链：

| 触发条件 | 调用方式 |
|:---------|:---------|
| 参数经过多层传递 | `Skill(skill="java-route-tracer", args="--route {route}")` |
| 路径拼接逻辑复杂 | `Skill(skill="java-route-tracer", args="--route {route}")` |
| 校验逻辑不明确 | `Skill(skill="java-route-tracer", args="--route {route}")` |

#### 3.2 执行条件检查

发现文件读取后，必须检查执行条件（详见后续章节）。

#### 3.3 生成报告

整合所有分析结果，生成综合审计报告。

---

## 文件读取方法识别

详细规则参见 [FILE_READ_METHODS.md](references/FILE_READ_METHODS.md)

| 方法类别 | 识别特征 | 风险点 |
|---------|----------|--------|
| BufferedReader | `new BufferedReader(new FileReader(path))` | path 参数来源 |
| Scanner | `new Scanner(new FileReader(path))` | path 参数来源 |
| Files.lines | `Files.lines(Path.of(path))` | path 参数来源 |
| Files.readAllLines | `Files.readAllLines(Path.of(path))` | path 参数来源 |
| Files.readAllBytes | `Files.readAllBytes(Path.of(path))` | path 参数来源 |
| FileInputStream | `new FileInputStream(path)` | path 参数来源 |

### 反编译阶段（CRITICAL）

**当源码不可用时，按运行环境中可用的反编译能力处理文件操作相关类。**

详细策略参见 [DECOMPILE_STRATEGY.md](references/DECOMPILE_STRATEGY.md)

#### 反编译工具调用

可使用运行环境中可用的反编译工具。内置 `java_decompile`、CFR、`javap` 等均可作为候选，按实际能力和结果选择。

**输出文件命名规范：**
- 反编译后的文件保存在 `{output_dir}` 目录
- 文件名格式：`{ClassName}.java`
- 保持原始包结构：`com/example/controller/FileController.java`

#### 必须反编译的类

| 类型 | 匹配模式 | 目的 |
|------|----------|------|
| Controller | `*Controller.class` | 提取路由和参数定义 |
| Service | `*Service.class`, `*ServiceImpl.class` | 追踪文件操作调用链 |
| 工具类 | `*FileUtil*.class`, `*FileHelper*.class` | 提取通用文件读取方法 |
| DAO | `*Dao.class`, `*Repository.class` | 配置文件读取逻辑 |

---

## 执行条件检查（CRITICAL - 避免误报）

**发现文件读取代码后，必须检查该代码是否真的会被执行！**

### 1. 路径校验检查

在发现文件读取后，必须检查是否存在路径校验：

| 检查模式 | 代码特征 | 处理方式 |
|----------|----------|----------|
| 白名单目录 | `path.startsWith("/upload/")` | 标注为受限路径 |
| 扩展名校验 | `fileName.endsWith(".txt")` | 检查是否可绕过 |
| 路径规范化 | `new File(path).getCanonicalPath()` | 检查是否完整 |
| 无校验 | 直接使用用户输入 | 标注为高危 |

### 2. 代码路径可达性分析

追踪从入口到文件读取的完整路径，检查：

| 检查项 | 说明 | 影响 |
|--------|------|------|
| 提前 return | `if (!validate()) return;` | 可能阻止执行 |
| 异常抛出 | `throw new SecurityException()` | 代码不执行 |
| 条件不满足 | `if (false)` 等死代码 | 代码不执行 |
| 权限限制 | 仅管理员可访问 | 需确认权限 |

### 3. 结论分级（必须标注）

| 状态 | 含义 | 后续操作 |
|------|------|----------|
| ⚠️ **待验证** | 代码存在文件读取，但执行条件未确认 | 需确认目标环境 |
| ✅ **已确认可利用** | 已验证代码路径会执行且无有效校验 | 进行漏洞利用测试 |
| ❌ **不可利用** | 存在有效的安全校验 | 标注原因，降低优先级 |
| 🔍 **环境依赖** | 漏洞存在但仅在特定条件下可利用 | 标注环境条件 |

---

## 路径遍历检测规则速查

### ⚠️ 高危模式检测（CRITICAL）

| 危险模式 | 代码示例 | 风险说明 |
|:---------|:---------|:---------|
| 直接拼接 | `basePath + fileName` | 未过滤 `../` |
| File.separator 拼接 | `basePath + File.separator + fileName` | 可路径遍历 |
| 字符串格式化 | `String.format("%s/%s", base, file)` | 未过滤 `../` |
| Path.of 拼接 | `Path.of(basePath, fileName)` | 可能路径遍历 |
| Paths.get 拼接 | `Paths.get(basePath).resolve(fileName)` | 需检查规范化 |

### ⚠️ 安全 vs 危险模式

| 类型 | 危险模式 | 安全模式 |
|------|----------|----------|
| 路径拼接 | `basePath + fileName` | 白名单校验 + 规范化 |
| 文件读取 | `new FileInputStream(userInput)` | `getCanonicalPath()` 校验 |
| 路径遍历 | 无过滤 `../` | `path.contains("..")` 拦截 |
| 扩展名 | 不校验 | 白名单扩展名 |

**安全模式示例：**
```java
// 安全: 路径规范化 + 白名单目录校验
String basePath = "/var/uploads";
File file = new File(basePath, fileName);
String canonicalPath = file.getCanonicalPath();
if (!canonicalPath.startsWith(basePath)) {
    throw new SecurityException("Path traversal detected");
}
```

---

## 审计检查清单（防遗漏）

### 可参考的危险模式搜索

**需要快速定位时，可参考以下搜索；是否执行由当前证据缺口决定：**

```bash
# 文件读取方法检测
grep -r "FileInputStream\|FileReader\|BufferedReader" --include="*.java"
grep -r "Files.readAllBytes\|Files.readAllLines\|Files.lines" --include="*.java"

# 路径拼接检测
grep -r "new File.*\+" --include="*.java"
grep -r "File.separator" --include="*.java"

# 下载接口检测
grep -r "download\|readFile\|getFile" --include="*.java"
```

---

## 数据流追踪（需要时加载 java-route-tracer）

### 何时需要参数追踪

当发现以下情况时，**可考虑加载 java-route-tracer 技能进行深度追踪**；是否加载由当前证据缺口和审计收益决定：

| 场景 | 说明 | 操作 |
|------|------|------|
| 参数经过多层传递 | HTTP 参数经 Controller → Service → Util 多层传递后用作文件路径 | 加载 java-route-tracer |
| 路径拼接复杂 | 多处路径拼接和转换 | 加载 java-route-tracer |
| 校验逻辑分散 | 校验逻辑在不同类/方法中 | 加载 java-route-tracer |

---

