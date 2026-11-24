# Java 反编译工具使用指南（Sophon 共享）


---

## 1. 内置工具调用参考

以下内容描述内置工具的调用方式，不表示只能使用该工具；也可使用运行环境中可用的其他反编译工具。

- 工具名：`sophon-tool-runner__java_decompile`。
- `input_path` 必须是单个 JAR、WAR 或 CLASS 文件。
- 工具不接受目录或多个输入文件；批量审计必须逐个 artifact 调用。
- 单个包失败只影响该 artifact，不得据此挂起整个审计方向。

## 2. 调用方式

```json
{
  "tool_name": "sophon-tool-runner__java_decompile",
  "arguments_json": "{\"input_path\":\"{artifact_path}\",\"output_dir\":\"{output_path}/decompiled/{artifact_name}\"}"
}
```

例如按顺序处理多个 JAR：

```text
1. 扫描 jar 清单并记录 artifact 名称。
2. 对每个 JAR 使用独立 output_dir 调用 java_decompile。
3. 读取生成的 src/ 或类文件；不要一次把完整反编译结果放入上下文。
4. 失败时读取工具返回的原始 error，按输入类型、路径、资源限制或反编译能力分类。
```

---

## 3. 反编译策略

### 策略 1: 最小化反编译（推荐）

只反编译需要分析的目标 artifact，按需逐步扩展：

1. 优先读取源码、JAR 文件名、`META-INF/MANIFEST.MF` 和 `META-INF/maven/**/pom.properties`。
2. 选择包含入口类的 JAR 或单个 CLASS 调用 `java_decompile`。
3. 阅读反编译结果后，再处理其直接依赖的下一个 artifact。

### 策略 2: 层级反编译

1. 第一层：定位包含 Controller、Action、Servlet 的 JAR。
2. 第二层：定位其调用的 Service 实现所在 JAR。
3. 第三层：定位 DAO、Mapper、Repository 所在 JAR。
4. 每个 JAR 使用独立输出目录执行一次 `java_decompile`。

### 策略 3: 按包反编译

当目录中包含未打包的 CLASS 文件时：

1. 优先只处理与当前证据链相关的 CLASS。
2. 工具不支持目录输入时，可逐个 CLASS 调用。
3. 需要批量分析时，可以在工作区生成新的 JAR 后调用工具；不得修改用户原始产物。

---

## 4. 反编译与源码混合策略

当项目同时包含源码和编译文件时：

1. **优先使用源码** — 如果 `.java` 文件已存在，直接读取，不反编译
2. **源码不存在则反编译** — 仅对没有源码的 `.class` 文件执行反编译
3. **缓存利用** — 已反编译的文件保存在 `{output_path}/decompiled/` 目录下，避免重复反编译

---

## 5. 常见故障处理

### 故障 1: 输入是目录

工具只接受单个文件。逐个处理 artifact，或在工作区生成新的 JAR 后重试。

### 故障 2: 工具的 Java 运行时不可用


### 故障 3: 反编译失败（混淆代码或大方法）

- 注解、方法签名和类型信息通常仍然可用。
- 可改用 `javap -p -c`、`unzip -p`、字符串和字节码检索完成同一证据目标。

### 故障 4: 输出限制或超时

- 缩小到具体业务类、提高单次运行预算或拆分 artifact。

---

## 6. 反编译结果验证

### 验证清单

- [ ] 类路径与预期一致
- [ ] 注解信息完整（`@Controller`、`@RequestMapping` 等）
- [ ] 方法签名清晰
- [ ] 参数类型可解析

### 反编译结果标注

输出审计报告时，必须标注反编译来源：

```markdown
位置: UserController.getUser (UserController.java:25)
来源: **反编译 WEB-INF/classes/com/example/controller/UserController.class**
```
