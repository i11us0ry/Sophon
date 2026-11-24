---
name: dotnet-deserialization-xml-audit
description: >-
  .NET / C# 反序列化与 XML 审计。覆盖 BinaryFormatter、LosFormatter、ObjectStateFormatter、JSON.NET TypeNameHandling、DataContractSerializer、ViewState 以及 XXE、DTD、XmlResolver 和外部实体。
metadata:
  tags: [dotnet, 反序列化, xxe, viewstate]
---

# .NET 反序列化与 XML 审计

## 适用场景

适合不可信二进制、JSON、ViewState、Session、消息或 XML 进入反序列化与解析器，需要判断输入控制、类型加载、实体解析和安全配置。

## 不适用场景

只发现 `BinaryFormatter`、`TypeNameHandling` 或 XML 解析器不能直接确认漏洞。输入可信、类型受限、外部实体禁用，或没有可达入口和安全效果时，应降级或判为否。

## 核心判断

反序列化与 XML 风险需要同时确认不可信来源、类型或实体控制、binder/parser 安全配置、运行环境和最终可观测影响。依赖中存在 gadget 只是候选条件。

## 证据标准

- 可确认：入口、输入映射、危险配置或类型控制缺口，以及反序列化/实体展开效果证据闭合。
- 待验证：存在危险 API 或 gadget，但输入、可达性、运行时保护或输出通道尚未确认。
- 判为否：输入固定、binder/白名单可靠、DTD 与外部实体禁用，或危险分支不可达。

## 决策树

- 找到序列化或 XML sink：确认最终调用和配置。
- 追踪不可信输入：区分请求、文件、Session、ViewState 和内部消息。
- 检查类型/实体控制：核对 binder、allowlist、TypeNameHandling、DtdProcessing 和 resolver。
- 检查运行环境：关联目标框架、machineKey、IIS 配置和版本差异。
- 只有命中 API：保留候选，不生成或执行真实 payload。

## 常见误判

- 依赖中存在 gadget 就认定反序列化可利用。
- 看到 `TypeNameHandling.Auto` 就忽略实际类型来源和 binder。
- 解析器调用存在就认定 DTD 或外部实体启用。
- 忽略 ViewState MachineKey、部署位置和运行时保护。
- 在验证时加载不可信程序集、访问外部 DTD 或执行真实 payload。

## 反序列化 Sink

重点检查：

- `BinaryFormatter.Deserialize`。
- `LosFormatter.Deserialize`、`ObjectStateFormatter.Deserialize`。
- `NetDataContractSerializer`、`DataContractSerializer` 动态类型。
- Newtonsoft.Json `TypeNameHandling.All/Objects/Auto`。
- `XmlSerializer` 动态类型加载。
- 自定义序列化封装、Session 序列化和缓存序列化。

## 二进制检索顺序

程序集审计必须逐步收窄范围：

1. 搜索源码和配置中的反序列化 API、封装类、配置开关和路由入口。
2. 使用 `rg -a -l "BinaryFormatter|LosFormatter|ObjectStateFormatter|TypeNameHandling" bin` 找出命中 DLL。
3. 只对命中 DLL 和确认有调用关系的业务程序集做 IL 或反编译分析。

禁止直接执行 `tools/callers.py ... "bin/*.dll"` 一类全目录扫描。

## Source

- HTTP body、Form、Query、Cookie、Header。
- `IFormFile`、上传文件、Base64 数据。
- Session、ViewState、Cache、Queue、数据库字段。
- 内部服务、gRPC、SignalR 和消息总线。

## Gadget 与类型控制

检查：

- 是否允许攻击者控制类型名称。
- 是否使用 `SerializationBinder`、`ISerializationBinder` 或类型白名单。
- 是否存在常见 gadget 类型、反序列化回调和危险 `OnDeserialized`。
- 是否将不安全反序列化封装在 Helper、扩展方法或第三方库中。
- Newtonsoft.Json 是否设置 `TypeNameHandling.None` 并禁用不安全 binder。

不能仅凭某个 gadget 存在于依赖中直接标记可利用，必须证明入口、类型控制和调用条件。

## ViewState

适用于 WebForms：

- ViewState 是否启用 MAC。
- `machineKey` 是否自动生成、弱密钥或跨机器共享。
- `enableViewStateMac`、`ViewStateEncryptionMode`。
- `__VIEWSTATE` 是否进入 LosFormatter/ObjectStateFormatter。
- 是否将用户可控数据写入 ViewState。

缺少 MachineKey 或部署配置时标记 `ENV_DEPENDENT` 或 `NEEDS_VALIDATION`。

## XML / XXE

检查：

- `XmlDocument.Load/LoadXml`。
- `XmlReaderSettings.DtdProcessing`。
- `XmlResolver`、`XmlUrlResolver`。
- `XDocument.Load`、`XPathDocument`。
- `DataSet.ReadXml`。
- `XmlSerializer` 和 `DataContractSerializer`。

安全条件：

- `DtdProcessing.Prohibit`。
- `XmlResolver = null`。
- 禁止外部实体和网络解析。
- 限制输入大小、深度和实体扩展。

