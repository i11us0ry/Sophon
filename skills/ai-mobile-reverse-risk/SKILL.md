---
name: ai-mobile-reverse-risk
description: >-
  Android App 综合风险审计方法。用于汇总协议与 Native 证据，分析弱加密、认证授权、组件、WebView、JSBridge、数据安全和业务逻辑风险。
metadata:
  tags: [移动安全, app逆向, 风险审计, guardian]
---

# Agent: CryptoVulnAnalyzer（弱加密与高风险漏洞筛查 Agent）

## 适用场景

适合已有代码、协议或 Native 线索，需要评估弱加密、认证授权、组件、WebView、JSBridge、数据安全和业务逻辑风险。

## 不适用场景

## 核心判断

每条风险都应按证据层级评估：危险模式、调用可达、输入可控、静态可构造和动态已验证。Guardian L1-L5 衡量证据充分度；严重度则来自资源、权限和业务影响，两者不能混用。

## 证据标准

- 可确认：已有代码、协议、Native 位置、可达链和可控输入证据闭合。
- 待验证：危险模式或可达链存在，但缺少输入控制、运行时证据或后端行为。
- 判为否：代码不可达、输入受约束、安全机制实际生效，或只有密钥/算法名称而无安全影响。

## 决策树

- 加载前序产物：先确认覆盖率与缺失阶段。
- 识别候选：关联 Java、smali、native 和协议字段。
- 评估可达性：从真实组件或接口入口追踪到危险操作。
- 判断控制面：确认外部输入是否进入关键参数。
- 限制影响：静态判断与运行时验证分开记录。

## 常见误判

- 发现硬编码 key、弱算法或 `exported=true` 就直接确认高危漏洞。
- 把 Guardian L1/L2 模式命中当成 L4 可利用。
- 忽略后端鉴权、签名和服务端校验，仅凭客户端代码推断结果。
- 使用真实 Token、密钥或账号验证签名与接口。
- 将普通调试信息、版本指纹或占位配置纳入垃圾 Finding。

## Guardian 验证层定义

Guardian 五级表示证据充分度，不是风险等级。同一条问题可以是 Critical 严重度但只在 L2，也可以是 Medium 严重度但已有运行时证据。

| Level | 名称 | 判断标准 | 所需证据 | 证据类型 |
|-------|------|---------|---------|----------------|
| **L1** | PATTERN | 在代码中发现危险模式，但不确认是否被实际调用 | 文件路径 + 代码行号 + 匹配的危险模式（如 ECB、硬编码字符串、exported=true） | ✅ 可达 |
| **L2** | REACHABLE | 危险代码存在可达调用路径，不是死代码 | 从入口（Activity / Service / exported 方法 / BroadcastReceiver）到危险代码的完整调用链 | ✅ 可达 |
| **L3** | CONTROLLABLE | 外部可控输入（Intent extra / 网络参数 / ContentProvider query）能抵达危险代码 | 具体可控参数 + 静态 source→sink 追踪路径，证明攻击者数据可流入危险点 | ✅ 可达（部分需 jadx 追踪） |
| **L4** | EXPLOITABLE | 静态可构造完整攻击载荷，所有参数来源已明确 | 完整攻击链描述 + 每个参数的具体来源 | ✅ 静态证据 |
| **L5** | VERIFIED | 已有运行时验证 | 运行时证据（hook 输出、实际值、截图） | ✅ 运行时证据 |

**可按 Guardian Level 排验证优先级：**
- L4：直接写 PoC，材料齐全
- L3：先确认参数可控性（可能需要 Frida），再写 PoC
- L2：先建立调用链证据，再评估是否值得 PoC
- L1：暂不出 PoC，标记为待深入分析
- L5：已有运行时结果时直接引用

## 方法定位

把代码、协议、字段、Native 和已有事实中的线索合流，判断关键字段的加密、签名、编码、校验与可达性。可以从任何一类证据开始，分析中可以回看源码、反编译、抓包和 Native 材料补证；缺失部分只影响结论强度，不阻断其他分析。

## 执行步骤

### Step 1：加载输入材料并建立覆盖率视图

**第一步：复用已有分析基线**

若当前会话已有项目事实、分析状态或前序结论，可优先复用：

- 提取所有 `CONFIRMED` 及以上级别的 Fact，作为高可信基线直接使用
- 提取 `category = credential_leak` 的 Fact → 用于 secrets 评估，无需再翻 `step1/raw_secrets.json`
- 提取 `category = crypto_finding` 的 CONFIRMED Fact → 用于 sign/data 还原判断，以此为起点而非重新推导
- 提取 `category = native_target` 的 Fact → 补充 sign/data 分析的 native 证据基础
- 提取 `type = stall_warning` 的 Hint → 若存在，说明某上游阶段质量不足，需在输出中注明相关结论的可信度受限

若 blackboard 中存在 `CONFIRMED` 级别的 `crypto_finding`，本阶段直接以该发现为算法基线，不得将其退化为 unknown 或重新从字符串猜测，除非有更强反证。

**第二步：读取前序 JSON 产物（补充细节）**

在 blackboard 基线之上，从以下文件补充具体字段和路径信息：

- `step2/protocol_map.json`：`field_role`、`builder_path`、`crypto_entry_candidate`、`related_endpoint_group`、`matched_field_flows`
- `step3/crypto_native_analysis.json`：`java_entry`、`native_entry`、`key_derivation`、`iv_derivation`、`input_order`、`output_encoding`、`restoration_confidence`
- `step1/raw_secrets.json`、`step1/raw_env_guards.json`：补充 PATTERN 级别线索

若 Phase 2 / Phase 3 的核心字段存在，可优先以这些字段为主线，也可按证据需要重新分析代码。

**第三步：记录覆盖率状态**

在输出的 `coverage` 字段中记录：
- `blackboard_confirmed_facts`：blackboard 中 CONFIRMED 级别 Fact 数量
- `phase2_available`：true / false
- `phase3_available`：true / false
- `native_coverage`：full / partial / none（若 blackboard 有 CONFIRMED crypto_finding 视为 full）

### Step 2：建立 sign/data 综合还原基线

本步骤是本阶段的第一优先级。

可围绕以下关键字段重新建立综合视图：

- `sign`
- `signature`
- `sig`
- `data`
- `encryptData`
- `cipher`
- `payload`
- `token`
- `authorization`
- `timestamp`
- `nonce`
- `salt`

#### 2.1 第一层 — 加密库与实现特征识别

在开始字段还原前，先对整个项目做一次加密能力全局识别。  
识别范围不仅包括 Java 层，也包括 native 层和常见第三方库。

##### Java / Kotlin 层加密能力识别

| 类别 | 搜索特征 | 常见场景 |
|---|---|---|
| JCA / JCE | `Cipher.getInstance`、`SecretKeySpec`、`IvParameterSpec`、`KeyGenerator`、`KeyFactory`、`KeyPairGenerator` | AES / DES / RSA / SM4 等 |
| Hash / 摘要 | `MessageDigest.getInstance`、`MD5`、`SHA-1`、`SHA-256`、`SHA-512` | 密码摘要、签名摘要 |
| MAC / HMAC | `Mac.getInstance`、`HmacSHA1`、`HmacSHA256`、`HmacSHA512` | 接口签名、消息认证 |
| RSA / ECDSA / 签名 | `Signature.getInstance`、`SHA256withRSA`、`SHA256withECDSA` | 非对称签名 |
| AndroidKeyStore | `KeyStore.getInstance("AndroidKeyStore")`、`KeyGenParameterSpec` | 硬件或系统密钥管理 |
| Base64 | `Base64.encodeToString`、`Base64.decode`、`android.util.Base64` | 编码（非加密） |
| 第三方库 | `BouncyCastle`、`Tink`、`SpongyCastle`、`Hutool`、`SM2`、`SM3`、`SM4` | 第三方加密实现 |
| 自定义加密 | 异或、移位、取反、数组变换、字符重排、TEA/XXTEA 关键词 | 伪加密或轻量混淆 |

##### native / so 层加密能力识别

| 类别 | 搜索特征 | 常见场景 |
|---|---|---|
| OpenSSL EVP | `EVP_EncryptInit`、`EVP_DecryptInit`、`EVP_CipherInit`、`EVP_Digest*` | AES / SM4 / 摘要封装 |
| AES / DES / RC4 | `AES_set_encrypt_key`、`AES_cbc_encrypt`、`DES_*`、`RC4` | 对称加密 |
| RSA / ECC | `RSA_public_encrypt`、`RSA_private_decrypt`、`EC_KEY` | 非对称加密 |
| HMAC / Hash | `HMAC`、`SHA1`、`SHA256`、`MD5` | 签名摘要 |
| 国密 | `sm2`、`sm3`、`sm4` | 国密方案 |
| 自定义算法 | 常量表、轮函数、位运算、S-box、XOR 链 | 自定义签名或加密 |

##### 识别结果要求

对每一种命中的实现方式，都至少记录：

- 所属文件
- 所属函数
- 所属层级：
  - Java / Kotlin
  - smali
  - native / so
- 算法候选
- 是否与 `sign/data` 相关

#### 2.2 第二层 — 字段来源确认

从 `protocol_map.json`、`traffic_alignment.json`、`api_endpoints.json` 中梳理：

- 哪些接口中出现上述字段
- 它们出现在：
  - Header
  - Query
  - Body
  - multipart
  - 响应体
- 这些字段对应的代码位置

若 Phase 2 已给出 `field_role`、`builder_path`、`crypto_entry_candidate`、`related_endpoint_group`、`value_shape`、`related_native_candidate`，必须逐项吸收并归并到当前分析结果中。

归并规则：
- 同一 `related_endpoint_group` 下的字段优先按“同一套签名/加密方案”归并
- `field_role = sign/signature/sig` 的字段优先进入 `signature_findings`
- `field_role = data/encryptData/cipher/payload` 的字段优先进入 `crypto_findings` 与 `crypto_restoration`
- `related_native_candidate = true` 或存在具体 native 函数名时，必须继续查询 Phase 3 的对应链路
- `replay_relevant = true` 的字段，后续必须进入重放和业务逻辑风险判断

#### 2.3 第三层 — 参数提取与实现路径合流

对每一个识别到的加密 / 签名调用，提取以下参数：

##### 算法与模式

- 算法：
  - AES / DES / 3DES / RSA / ECDSA / SM2 / SM3 / SM4 / HMAC / MD5 / SHA1 / SHA256 / 自定义
- 模式：
  - ECB / CBC / CFB / OFB / CTR / GCM / 无模式 / 未知
- 填充：
  - PKCS5 / PKCS7 / ZeroPadding / NoPadding / OAEP / PKCS1Padding / 未知

##### 密钥（Key）

- `hardcoded`
- `dynamic`
- `derived`
- `service_provided`
- `native_generated`
- `unknown`

必须尽量提取：

- Key 值或可见片段
- Key 编码：
  - UTF-8
  - Hex
  - Base64
  - byte array
- Key 来源位置
- Key 生成或派生逻辑

##### 初始化向量（IV）/ nonce / Salt / AAD

必须尽量提取：

- IV 类型：
  - hardcoded
  - dynamic
  - derived
  - unknown
- IV 编码
- nonce
- salt
- AAD（若出现 GCM / AEAD）
- tag length（若可识别）

##### 输出编码

记录加密后或签名后输出方式：

- Base64
- Hex
- URL encode
- 自定义编码
- 原始字节数组

##### 公钥 / 私钥 / 证书

若是非对称加密或签名，尽量提取：

- 公钥位置
- 私钥位置
- PEM / DER / Base64 格式
- 密钥长度
- 是否疑似硬编码

#### 2.4 Java 与 native 路径合流

从 `crypto_native_analysis.json`、`jni_analysis.json` 中梳理：

- `sign` 对应的算法、排序、拼接、加盐、Hash、HMAC 逻辑
- `data` / `encryptData` 对应的加解密算法、模式、填充、编码
- 是否有：
  - Java 层直接实现
  - Java 调 native
  - native 内部再次派生 Key / IV / Salt
  - 仅编码不加密

可额外判断：

- Java 层是否只是做预处理，真正加密在 native 层
- native 层是否只是藏 Key，Java 层仍然掌握主要流程
- `sign` 和 `data` 是否共用相同参数源
- `token` 是否参与 `sign`

若 Phase 3 已提供以下字段，可优先直接使用：
- `java_entry`
- `native_entry`
- `related_fields`
- `related_endpoints`
- `crypto_algorithm_candidate`
- `key_derivation`
- `iv_derivation`
- `salt_derivation`
- `input_order`
- `output_encoding`
- `restoration_confidence`

消费要求：
- 不得把已有的 `crypto_algorithm_candidate` 重新退化成 “unknown”，除非有更强反证
- 不得丢失 `related_endpoints` 与 `related_fields`
- 若 `restoration_confidence = high`，当前阶段默认以“已基本还原”为基线继续评估
- 若 `restoration_confidence = medium/low`，当前阶段需要补代码证据，但不得夸大为完全还原

#### 2.5 第四层 — 还原状态判断

对每一个关键字段，都要给出以下状态之一：

- `restored`
  - 算法、模式、关键参数、输入顺序基本明确
- `partially_restored`
  - 只确定了部分算法或流程
- `observed_only`
  - 只看到了字段和调用点，还无法还原
- `not_applicable`
  - 当前项目中不存在该字段

#### 2.6 还原结果必须说明的内容

每个 `sign/data` 相关发现至少说明：

- 字段名
- 所属接口或接口集合
- Java 代码位置
- native 代码位置（如有）
- 算法类型
- 模式 / 填充 / 编码
- Key / IV / Salt 来源
- 输入顺序
- 还原状态
- 风险说明

此外，若这些信息来自前序结果，还必须说明：
- `source_phase_2_fields`: 当前结论直接使用了哪些 Phase 2 字段
- `source_phase_3_fields`: 当前结论直接使用了哪些 Phase 3 字段
- `gap_filled_by_phase4`: 哪些内容是 Phase 4 重新补分析得到的

### Step 3：弱加密与签名安全专项评估

本步骤只关注“加密与签名本身是否安全”，不混入业务漏洞。

#### 3.1 第一层 — 算法与模式检查

重点检查：

- DES / 3DES / RC4 / RC2 / MD4
- AES-ECB
- MD5
- SHA1
- 伪加密（Base64 充当加密）
- 弱 RSA 密钥长度（如 `< 2048`）
- SM2/SM4 使用中的固定参数问题
- `java.util.Random`
- 自定义但明显无安全设计的“异或/拼接/移位/取反”类方案

#### 3.2 第二层 — 密钥与参数检查

重点检查：

- 硬编码 Key
- 硬编码 IV
- 固定 Salt
- 固定时间戳模板
- Key 派生过于简单
- 前后端共用前端可见密钥
- 签名盐值固定且暴露在客户端
- 仅依赖客户端生成签名、无服务端校验线索

#### 3.3 第三层 — 签名逻辑专项检查

对 `sign/signature/sig` 相关流程，至少要判断以下 12 项：

- 签名算法：MD5 / SHA256 / HMAC / 自定义
- 摘要算法与 MAC 算法是否混用
- 是否存在固定盐值
- 盐值位置在哪里
- 参数是否排序
- 排序规则是什么
- 参数是否拼接
- 拼接分隔符是什么
- 是否有 `timestamp`
- `timestamp` 是否来自本地时间
- 是否有 `nonce`
- `nonce` 是否随机、是否可预测
- 是否有有效期或重放限制线索
- 是否可能被客户端重签

此外，还要回答：

- 签名字段是否覆盖了全部关键业务参数
- 签名字段是否覆盖了 `data` 密文本身
- 是否存在“只签 header 不签 body”或“只签部分字段”的情况
- 是否存在“签名算法安全，但客户端持有全部重签材料”的问题

#### 3.4 第四层 — 安全评估矩阵

参考规则如下：

| 风险场景 | 严重级别 | 说明 |
|---|---|---|
| Key 与 IV 均硬编码 | Critical | 一旦算法可还原，数据极易被解密 |
| 客户端完全持有可用签名密钥 | Critical | 客户端泄露即意味着可重签 |
| 仅 Key 硬编码 | Critical | 大多数情况下仍可重现方案 |
| `sign/data` 算法已完整还原且无额外服务端保护线索 | High | 后续验证阶段重点关注 |
| 使用 ECB | High | 模式不安全 |
| 使用 MD5/SHA1 作为核心签名或密码哈希 | High | 强度不足 |
| 仅 Base64 或简单编码 | High | 不具备保密性 |
| 随机数不可控且可预测 | High | 可降低方案有效性 |
| 使用时间戳但未见有效期/重放控制线索 | Medium | 需验证重放风险 |
| 动态 Key 来自服务端，但客户端仍暴露关键派生材料 | Medium | 仍可能被复现 |
| GCM/AEAD 但 IV/nonce 固定 | Critical | 现代模式被错误使用，安全性严重下降 |
| 使用 AndroidKeyStore 但仍把明文密钥写入代码 | High | KeyStore 形式存在但方案仍暴露 |
| native 仅隐藏密钥，算法和重签材料仍在客户端齐全 | High | 安全收益有限，仍可复现 |
| `data` 可解密但未见完整性保护 | High | 数据可被篡改后重新加密 |
| `sign` 与 `data` 分离，且 `data` 未被签名覆盖 | High | 可能造成内容被替换 |

### Step 4：源码侧 Top10 风险代码审计

本步骤是本阶段的第二优先级。  
这里的 Top10 不是死板照搬 Web 单一清单，而是面向当前 APP 源码、抓包、WebView/JSBridge、native 调用、文件处理能力，执行“高风险代码面”审计。

至少覆盖以下 10 类问题：

#### 4.1 注入类风险：SQL 注入

重点检查：

- `rawQuery`
- `execSQL`
- 字符串拼接 SQL
- `SQLiteDatabase.query` 中可控条件
- `ContentProvider` 查询条件可控

需要说明：

- 可控输入来自哪里
- SQL 组装点在哪里
- 是否使用参数化
- 是否属于本地数据库风险，或可能影响同步接口逻辑

#### 4.2 注入类风险：命令执行 / RCE

重点检查：

- `Runtime.getRuntime().exec`
- `ProcessBuilder`
- Shell 命令拼接
- 通过 `su`、`sh`、`busybox`、`toybox` 执行外部命令
- 通过 JSBridge / WebView / Intent / deeplink 把输入带到命令执行点

若出现上述调用，必须判断：

- 输入是否可控
- 执行上下文
- 是否可能构成客户端本地 RCE 或高危能力滥用

#### 4.3 路径穿越 / 任意文件处理

重点检查：

- 文件路径是否来自：
  - Intent
  - deeplink
  - JSBridge
  - WebView
  - 下载参数
  - 解压包内容
- 是否存在：
  - `../`
  - 外部存储读写
  - 任意文件下载 / 打开 / 导入 / 导出
  - Zip Slip 风险

#### 4.4 文件上传与下载风险

重点检查：

- 上传文件类型、大小、文件名是否只在前端限制
- 下载 URL 是否可控
- 下载后是否直接打开、安装、解析
- 是否存在任意 URL 下载、任意文件保存

#### 4.5 认证授权与会话控制

重点检查：

- 登录接口是否依赖前端传递关键身份字段
- token 是否无过期、无签名、无刷新策略
- 用户 ID、角色 ID、订单 ID 是否直接由前端提交
- 页面显隐是否代替服务端鉴权

对纯前端可见但后端未知的场景，要标注 `需验证`。

#### 4.6 数据暴露与隐私泄露

重点检查：

- 本地明文存储：
  - token
  - session
  - 密码
  - 个人信息
  - 设备信息
- 日志泄露：
  - token
  - cookie
  - sign
  - data 解密前后内容
- 调试、测试环境、内网地址、监控口令残留

#### 4.7 WebView / JSBridge 高危能力

重点检查：

- `addJavascriptInterface`
- `@JavascriptInterface`
- `evaluateJavascript`
- `loadUrl("javascript:...")`
- `setJavaScriptEnabled(true)`
- 文件访问相关高危配置
- URL 可控的 WebView 加载

判断是否可形成：

- 任意方法调用
- 本地文件访问
- Bridge 滥用
- H5 -> Native 高危能力穿透

#### 4.8 组件暴露 / Deeplink / Intent 风险

重点检查：

- 导出 Activity / Service / Receiver / Provider
- `android:exported="true"`
- `android:scheme/host/path`
- `BROWSABLE`
- Provider `authorities`
- 敏感 Intent 参数

需要明确：

- 是否可能造成未授权访问
- 是否可能造成 deeplink 劫持
- 是否可能造成参数注入

#### 4.9 动态加载 / 反序列化 / 代码完整性风险

重点检查：

- `DexClassLoader`
- `PathClassLoader`
- 动态加载插件、补丁、脚本
- `WebView` 加载远程 JS
- 反序列化入口
- 未校验的热更新包 / 资源包 / 补丁包

#### 4.10 业务逻辑与重放风险

重点检查：

- 支付金额
- 数量 / 折扣 / 优惠券
- 订单状态
- 验证码 / 短信
- 重放控制
- 签名与时间戳配合方式

这里必须结合 `sign/data` 还原结论一起分析，判断：

- 如果签名可还原，业务参数是否可能被重签
- 如果 data 可解密 / 重加密，哪些业务字段会受影响

### Step 5：数据包侧风险联动分析

本步骤要求把“源码问题”和“数据包问题”真正合并，而不是各写各的。

至少要回答以下问题：

1. 抓包中出现的 `data/sign/token` 是否与源码侧关键函数一一对应？
2. 哪些请求字段看起来被前端控制？
3. 哪些字段经过加密后仍然可能被重构或重签？
4. 哪些风险只从源码能看见，哪些风险只有结合抓包才能判断？
5. 哪些问题属于：
   - `纯源码侧已确认`
   - `源码+抓包共同支持`
   - `需后端验证`

输出中可单独给出 `packet_risks` 或等价字段，记录：

- 风险字段
- 对应接口
- 对应代码位置
- 风险类型
- 是否依赖 sign/data 还原

若 `traffic_alignment.json` 中存在 `matched_field_flows`，可优先使用该数组，把其中的：
- `field_role`
- `location`
- `traffic_value_shape`
- `code_builder_path`
- `crypto_entry_candidate`
- `related_native_candidate`
- `match_confidence`

显式带入 `packet_risks` 或 `crypto_restoration` 的证据链。

### Step 6：问题分级、利用条件与修复方案

对每个问题，都必须明确以下内容：

#### 6.1 利用条件

- 需要什么身份
- 需要什么前置数据
- 需要什么环境
- 是否依赖已还原的 `sign/data`

#### 6.2 攻击路径

- 输入从哪里进入
- 经过哪些函数或组件
- 到达哪个危险点
- 哪个环节缺乏保护

#### 6.3 影响范围

- 用户数据
- 支付数据
- 订单数据
- 本地文件
- 账号体系
- 客户端本地执行能力

#### 6.4 修复建议

至少包括：

- 代码改动点
- 配置改动点
- 设计层建议
- 回归验证点

### Step 6.5：Guardian 验证——为每条发现评定 L1-L5

对 `vulnerabilities[]` 中的每条发现，可参考以下判断流程，按需写入 `guardian_level` 和 `guardian_evidence`。

**判断规则（逐层确认，只能达到最高已满足层）：**

```
L1 PATTERN 判断：
  ✓ 有文件路径 + 行号
  ✓ 有具体危险代码片段
  → 满足以上两条 → guardian_level = "L1"

L2 REACHABLE 判断（在 L1 基础上）：
  ✓ 能从 Activity/Service/exported 方法/BroadcastReceiver 追踪到该危险代码
  ✓ 不是测试代码、不是条件永假的死分支
  → 有调用链证据 → guardian_level = "L2"

L3 CONTROLLABLE 判断（在 L2 基础上）：
  ✓ 攻击者可控的外部输入（Intent extra / 网络请求参数 / ContentProvider query / 用户输入）
    能作为参数流入该危险代码
  ✓ source → sink 路径静态可追踪
  → 有 source→sink 路径 → guardian_level = "L3"

L4 EXPLOITABLE 判断（在 L3 基础上）：
  ✓ 所有攻击所需参数来源已明确（Key 值、IV、接口参数、Intent 结构等）
  ✓ 可以写出完整 PoC 思路，不存在"还需要某个未知值"的空白
  ✓ Phase 2/3 证据已覆盖攻击链的每一环
  → 静态链路完整 → guardian_level = "L4"

L5 VERIFIED（Phase 4 不评定，留给 Phase 5 回写）：
  Phase 4 输出中写 guardian_level = "L4"（最高），
  Phase 5 Frida/运行时确认后可将对应条目升级为 "L5"。
```

**不允许跳级：** 如果 L3 不满足（source 不可控），不能写 L4，即使攻击思路完整。

**降级情形（必须写降级原因）：**

| 情形 | 降级规则 |
|------|---------|
| 调用链只在 Phase 2/3 推断，无代码级证据 | L2 → L1，注明"调用链待代码确认" |
| 参数来源部分来自 native 层未完全分析的 so | L3 → L2，注明"native 参数来源待 Frida 验证" |
| Key 或 IV 存在于 so 内未提取出具体值 | L4 → L3，注明"Key 值待运行时提取" |
| blackboard 中对应 Fact 为 PATTERN 级别 | 最高 L2，注明"上游仅静态推断" |
| blackboard 中对应 Fact 为 CONFIRMED 级别 | 可评至 L3/L4 |

### Step 7：归纳发现（可选）

可按需要整理风险结论、签名/加密还原判断、敏感信息线索、WebView/JSBridge 风险和待验证项。具体写回结构由运行时决定。

## 归纳检查

- 风险结论是否区分模式命中、调用可达、输入可控、静态可利用和动态验证。
- 关键字段的加密、签名、参数来源和 Native 关系是否有证据支持。
- 硬编码 Key、弱算法、组件导出和调试配置是否结合了实际影响。
- 认证、数据、组件、WebView、注入和业务逻辑方向是否按项目证据覆盖。
- 无法确认的内容是否保留为待验证，而不是写成已确认。

## 大文件处理策略

| 文件大小 | 处理方式 |
|---|---|
| ≤ 300KB | 直接阅读全文，重点看危险 API、签名/加密、文件处理、WebView、数据库调用 |
| 300KB ~ 800KB | 先按高危关键词定位，再读取命中区域上下文 |

优先级最高的文件类型与文件名包括：

- 文件名含 `crypto`、`encrypt`、`decrypt`、`sign`
- 文件名含 `api`、`service`、`network`、`client`
- 文件名含 `db`、`dao`、`repository`
- 文件名含 `webview`、`bridge`
- 文件名含 `auth`、`login`、`token`
- 文件名含 `pay`、`order`、`coupon`、`sms`

## 注意事项

- 混淆代码中的高危逻辑也要尝试识别，优先关注特征字符串、危险 API 和常量，而不是只依赖函数名
- 如果 `sign/data` 逻辑在多处复用，要以“加密方案”而不是“单一接口”来归并分析
- 如果抓包中出现可疑字段，但源码里还原不完整，必须标记为 `需验证` 或 `observed_only`
- Base64、URL 编码、Hex 编码不是加密，但若被当作“加密”方案使用，必须标记为风险
- SQL 注入、命令执行、路径穿越、JSBridge、动态加载等问题即使在移动端也必须检查，不能只盯着加密逻辑
