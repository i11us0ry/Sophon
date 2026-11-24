---
name: java-file-upload-audit
metadata:
  tags: [代码审计, java, 文件上传, 路径穿越, rce]
description: Java Web 源码文件上传漏洞审计工具。用于从源码中识别所有文件上传入口并检查上传路径、文件名处理与校验逻辑漏洞。适用于：(1) 识别 Servlet/Commons FileUpload 与 Spring Boot MultipartFile 上传实现，(2) 发现任意文件上传、路径穿越与可执行文件上传漏洞，(3) 检查文件名/目录/类型/大小校验是否缺失或可绕过，(4) 审计上传目录与访问控制。**支持反编译 .class/.jar 文件提取上传逻辑**。结合 java-route-mapper 使用可实现完整的路由+文件上传审计。
---

# Java 文件上传漏洞审计工具

检查 Java Web 项目源码，识别文件上传实现并检测上传相关漏洞（任意文件上传、路径穿越、文件覆盖、Web 根目录可执行等）。

## 适用场景

适合 Servlet/Commons FileUpload、Spring `MultipartFile`、存储服务或自定义上传封装，需要判断文件名、保存路径、类型校验和写后访问执行条件。

## 不适用场景

只看到上传接口或 `getOriginalFilename()` 不能直接确认 RCE。必须证明危险文件能够写入有效落点，并且可被访问或解释；仅能上传无效内容到隔离目录时，不应按代码执行处理。

## 核心判断

文件上传影响由保存路径、服务器生成文件名、内容/扩展名校验、目录执行策略和访问控制共同决定。原始文件名可控、路径穿越和任意文件写入是三个不同层次的证据。

## 证据标准

- 可确认：真实上传入口、可控文件内容/名称、最终落点、校验缺口和写后触达/执行效果证据闭合。
- 待验证：存在弱校验或路径拼接，但落点、文件权限、服务器命名或访问策略尚未确认。
- 判为否：文件被重命名到隔离目录、类型和内容受可靠约束、扩展名不执行，或上传结果不可触达。

## 决策树

- 找到上传入口：确认鉴权、multipart 字段和文件内容来源。
- 检查最终文件名：区分原始名称、basename、随机名和扩展名策略。
- 检查最终路径：验证 normalize/resolve 后是否受上传根目录约束。
- 检查类型：同时评估扩展名、Content-Type、魔数、解析器和二次处理。
- 检查写后效果：确认 Web 映射、包含链、权限和解释配置。

## 常见误判

- `getOriginalFilename()` 可控就认定可以任意写入。
- 校验 Content-Type 就认为安全，或只看扩展名不看内容和解析配置。
- 文件写入 Web 目录就直接确认代码执行。
- 忽略服务器随机命名、对象存储隔离和下载响应的 Content-Disposition。
- 为验证上传向生产目录写入脚本、覆盖配置或触发解析器。

## 与路由分析协作（可选）

已有路由映射结果时，可用于定位入口和参数；没有时直接从源码、字节码和当前审计目标开始，不要求检查或生成任何上游文件。

### 已有路由结果时可利用的信息

| 信息 | 用途 |
|:-----|:-----|
| 路由路径 | 定位上传 Controller/Servlet 入口 |
| 参数名 + 类型 | 识别 MultipartFile / FileItem / fileName 参数 |
| JSON 内部字段 | 识别嵌套上传参数 |
| 参数用途描述 | 判断是否用于文件名或保存路径 |

---

## 工作流程（三阶段）

### 阶段1: 快速扫描（优先执行）

**目标：快速定位上传相关代码，不遗漏关键点。**

```bash
# 1.1 Servlet/Commons FileUpload
rg -n "ServletFileUpload|DiskFileItemFactory|FileItem|isMultipartContent" --glob="*.java"

# 1.2 Spring Boot MultipartFile
rg -n "MultipartFile|@RequestParam\\(\"file\"\\)|transferTo\\(" --glob="*.java"

# 1.3 文件名/路径相关
rg -n "getOriginalFilename|getName\\(\\)|getRealPath\\(\"/uploads\"\\)|uploadDir" --glob="*.java"
rg -n "new File\\(|Paths\\.get\\(|Path\\.of\\(|File\\.separator" --glob="*.java"

# 1.4 上传接口路由
rg -n "@PostMapping\\(|@RequestMapping\\(.*upload|/upload" --glob="*.java"
```

**输出：高危文件清单（按优先级排序）**

| 优先级 | 文件类型 | 审计重点 |
|:-------|:---------|:---------|
| P0 | `*Controller.java` / `*Servlet.java` 中包含 upload 逻辑 | MultipartFile/FileItem |
| P1 | `*Service.java`, `*ServiceImpl.java` | 文件保存路径/重命名 |
| P2 | `*Util.java`, `*Storage.java`, `*File*.java` | 通用存储封装 |
| P3 | `*Config.java`, `application.yml` | 文件大小/目录配置 |

### 阶段2: 参数-上传映射分析

**基于 route_mapper 输出，检查每个上传参数是否影响文件名或保存路径。**

#### 2.1 高危参数识别

| 参数来源 | 参数名 | 类型 | 漏洞等级 |
|:---------|:-------|:-----|:-----|
| @RequestParam | `file` | MultipartFile | **高危** - 直接上传 |
| FileItem | `item` | FileItem | **高危** - fileName 可控 |
| @RequestParam | `fileName` | String | **高危** - 文件名拼接 |
| JSON | `upload.path` | String | **高危** - 目录拼接 |

#### 2.2 参数追踪（示例）

```
HTTP 参数: file (MultipartFile)
    ↓
Controller.handleFileUpload(file)
    ↓
file.getOriginalFilename()  ← 文件名来源
    ↓
Paths.get(uploadDir).resolve(fileName)
    ↓
file.transferTo(filePath)   ← 上传写入点
```

#### 2.3 上传点检查

对每个上传写入点，检查：

1. **文件名来源是否可控？**
   - `getOriginalFilename()` / `item.getName()` → 高危
   - 服务器生成随机名 → 低危

2. **是否有路径规范化与目录限制？**
   - `getCanonicalPath()` + 固定上传目录 → 较安全
   - 直接拼接路径 → 高危

3. **是否做类型/内容校验？**
   - 白名单扩展名/Content-Type/魔数校验 → 安全
   - 仅检查非空或无校验 → 高危

4. **上传目录是否在 Web 根目录？**
   - `getRealPath("/uploads")` / `/uploads/` → 高危
   - 非 Web 可访问目录 → 较安全

### 阶段3: 深入检查与报告

当上传逻辑复杂或参数多层传递时，调用 java-route-tracer 获取完整调用链并补充校验路径分析。

---

## 上传实现识别（来自 Notion 资料的关键点）

### 1) Servlet/Commons FileUpload

**识别特征：**
- `ServletFileUpload.isMultipartContent(request)`
- `DiskFileItemFactory` / `ServletFileUpload`
- `upload.parseRequest(request)` → `List<FileItem>`
- `item.getName()` 作为文件名
- `item.write(storeFile)` 写入文件
- `getServletContext().getRealPath("/uploads")` 作为保存目录

**Notion 记录要点：**
- 示例未校验表单字段名，`name="file"` **不会被校验**。
- 仅设置了大小上限（如 `upload.setSizeMax(5MB)`），未见扩展名/类型/路径校验。

### 2) Spring Boot MultipartFile

**识别特征：**
- `@RequestParam("file") MultipartFile file`
- `file.getOriginalFilename()`
- `file.transferTo(filePath)`
- 固定上传目录 `uploadDir = "/uploads/"`

**Notion 记录要点：**
- `@RequestParam("file")` 会校验表单字段名，需要 `name="file"`。
- 示例未见文件名净化、类型白名单或目录隔离。

**详细检测规则参见** [UPLOAD_RULES.md](references/UPLOAD_RULES.md)

---

## 反编译阶段（CRITICAL）

**当源码不可用时，按运行环境中可用的反编译能力处理上传相关类（详见 `java-shared/DECOMPILE_STRATEGY.md`）。**

### 反编译工具调用

可使用运行环境中可用的反编译工具。内置 `java_decompile`、CFR、`javap` 等均可作为候选，按实际能力和结果选择。

### 必须反编译的类

| 类型 | 匹配模式 | 目的 |
|------|----------|------|
| Controller/Servlet | `*Upload*Controller.class`, `*Servlet.class` | 提取上传入口 |
| Service/Storage | `*Storage*.class`, `*FileService*.class` | 追踪保存路径 |
| 工具类 | `*UploadUtil*.class`, `*FileUtil*.class` | 查找通用校验 |
| 配置类 | `*Config*.class` | 获取上传目录/大小限制 |

**反编译输出要求：**
- 输出“反编译文件清单”，包含原始文件名与反编译输出路径
- 反编译文件路径需可定位到具体目录

---

## 执行条件分析（CRITICAL - 避免误报）

**发现上传逻辑后，必须检查该逻辑是否真的会被执行！**

| 检查项 | 说明 | 影响 |
|--------|------|------|
| 权限校验 | 仅管理员可访问 | 影响可利用性 |
| 参数校验 | 字段名/类型/大小校验 | 降低漏洞可利用性 |
| 目录限制 | 固定上传目录 | 降低路径穿越 |
| 可访问性 | 上传目录是否可 Web 访问 | 决定是否可执行 |

结论分级必须标注：✅ 已确认可利用 / ⚠️ 待验证 / ❌ 不可利用 / 🔍 环境依赖

---

