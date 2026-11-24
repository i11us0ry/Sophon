---
name: ai-mobile-reverse-recon
description: >-
  Android App 静态侦察方法。用于从反编译目录、Jadx MCP 会话、组件、权限、SDK、敏感入口和环境对抗线索中建立样本画像。
metadata:
  tags: [移动安全, app逆向, android, 静态分析]
---

# Agent: SampleRecon（APK 静态侦察 Agent）

## 适用场景

适合已有 Jadx MCP 会话、脱壳目录、反编译目录或解包资源，需要整理组件、权限、SDK、敏感入口、环境对抗和资产清单。

## 不适用场景

如果只有原始 APK 且没有可用反编译输入，不应假装完成静态侦察；可以先记录输入限制并选择可做的文件级分析。

## 核心判断

侦察的目标是建立后续协议、Native 和验证阶段可用的证据索引，而不是机械生成全部 JSON。优先组件、权限、网络入口、硬编码线索和环境对抗证据。

## 证据标准

- 每个入口、权限和线索需要绑定文件、类、方法或资源位置。
- 环境检测结论需要代码或资源证据。
- 资产、SDK 和端点命中只能作为候选。
- 无法读取的输入要明确标记限制，不生成猜测结果。

## 决策树

- 可用反编译目录：执行文件、组件和入口侦察。
- 只有 Jadx MCP：读取已打开样本的类、资源和 Manifest。
- 输入部分受限：输出已知结果并列出缺失材料。
- 发现协议/签名线索：交给协议映射阶段。
- 发现 SO/JNI 线索：交给 Native 分析阶段。

## 常见误判

- 把 DEX 壳代码当成全部业务逻辑。
- 把 manifest 权限声明当成实际滥用。
- 把硬编码字符串当成有效凭据。
- 缺少反编译输入时编造组件或入口。
- 为了完成 Step 输出大量无证据 JSON。

## 方法定位

围绕 Manifest、资源、DEX、smali、Jadx 会话和已有反编译目录整理样本结构。重点建立可复核的资产、入口、SDK、敏感字符串和环境对抗线索，工具选择由当前环境和材料决定。

## 分析视角

### 识别材料形态

可先判断当前材料属于：

- Jadx 导出目录
- apktool / smali 目录
- 混合源码目录
- 包含 so、assets、WebView 资源的 Hybrid 目录
- 正在运行的 Jadx MCP 会话

### 基础信息提取

从目录中提取：

- `AndroidManifest.xml`
- 包名、版本、targetSDK、minSDK
- 权限清单
- Activity / Service / Receiver / Provider
- 导出组件
- Scheme / DeepLink / App Link
- `networkSecurityConfig`
- 是否使用 WebView、动态加载、插件化、热更新

#### 2.1 高危权限清单

可重点关注高风险权限，并说明用途或风险背景，例如：
- `READ_EXTERNAL_STORAGE`
- `WRITE_EXTERNAL_STORAGE`
- `MANAGE_EXTERNAL_STORAGE`
- `READ_PHONE_STATE`
- `READ_SMS`
- `RECEIVE_SMS`
- `CAMERA`
- `RECORD_AUDIO`
- `ACCESS_FINE_LOCATION`
- `QUERY_ALL_PACKAGES`
- `SYSTEM_ALERT_WINDOW`
- `REQUEST_INSTALL_PACKAGES`
- `BIND_ACCESSIBILITY_SERVICE`

可标记：
- 权限名
- 是否声明
- 对应模块或可疑使用点
- 备注说明

### 资产清单整理

按当前输入模式整理并分类以下资产：

- DEX
- smali
- Java / Kotlin
- so
- assets
- res/raw
- 配置文件
- WebView / H5 资源
- 证书与密钥文件
- 其他文件

可记录可定位的文件路径、Jadx 类名、资源路径、SO 名称或其他稳定标识；多个 ABI 的 SO 和 H5/JS bundle 可单独分类。

### 三方 SDK 梳理

识别：
- 支付
- 统计
- 推送
- 地图
- 云服务
- IM
- 人机验证
- 热更新 / 加固 / 插件化
- 广告 / 埋点 / 风控 SDK

可包含：
- SDK 名称
- 命中依据（包名 / 类名 / 文件路径 / 字符串）
- 所在目录或文件
- 风险备注

### 硬编码信息采集

在静态代码和资源中重点检索以下内容：
- 域名
- IP
- URL 路径片段
- BaseURL
- API 路径
- 密钥
- Token
- AppKey / AppSecret
- 证书文件
- 测试环境 / 开发环境标识
- 调试开关

可区分真实命中、疑似占位值和示例值；域名、IP、路径、密钥、Token 和证书材料最好保留位置与上下文。

### 环境对抗检测分析

重点排查：
- Root 检测
- 模拟器检测
- VPN / 代理检测
- 抓包检测（证书校验 / SSL Pinning）
- 反调试 / Frida 检测
- 签名校验
- 双开 / 多开检测

输出：
- 命中类型
- 文件位置
- 类 / 方法
- 关键代码位置
- 绕过思路预判
- 对后续抓包或 hook 的影响说明

可将明确检测点、间接信号和未发现逻辑分别记录，避免把未确认写成没有问题。

若命中 Root、模拟器、代理、证书校验或 SSL Pinning 等逻辑，可继续整理 hook 点、影响面和最小运行时准备方案。

### 敏感逻辑初定位

检索关键词：
- `sign`
- `encrypt`
- `aes`
- `rsa`
- `token`
- `secret`
- `key`
- `auth`
- `verify`

分类输出：
- 加密 / 签名入口
- 认证入口
- JNI / native 入口
- WebView / H5 入口
- 上传下载 / 文件处理入口

### 敏感方法调用链摘要

对已命中的关键方法，可整理简要调用链摘要：
- 该方法位于哪个类、哪个文件。
- 它处理的是签名、加密、认证、JNI 调用、WebView 交互还是文件操作。
- 它的上游输入来自用户输入、设备信息、本地存储、固定常量还是其他函数返回值。
- 它的下游调用是 Java 层处理、JNI / so 调用、网络请求注入还是本地存储写入。

优先为以下内容输出调用链摘要：
- 签名构造函数
- 加密 / 解密函数
- Token / Session 构造或注入函数
- `System.loadLibrary` / `native` 方法
- WebView `addJavascriptInterface` / `evaluateJavascript` / `loadUrl("javascript:")`
- 上传 / 下载 / 文件保存函数

### 归纳发现

可按需要记录资产清单、技术栈、高危权限、导出组件、第三方 SDK、敏感入口、硬编码线索、环境检测和调用链摘要。具体写回形式由运行时工具决定。

## 大文件处理策略

- 小文件可直接读全文。
- 大文件只围绕命中关键词读取局部上下文。
- 超大文件仅做分类和命中标记。
- 大型 smali / JS bundle 优先按关键词、包名、路径片段定位，不全文展开。

## 归纳检查

- 关键结论能回指文件、类、方法或资源位置。
- 高危权限、导出组件和敏感入口没有被当成漏洞结论本身。
- 硬编码字符串先判断用途和有效性。
- 无法确认的覆盖缺口被明确记录。
