---
name: dotnet-deserialization-xml-audit
description: >-
  .NET / C# 反序列化与 XML 审计。覆盖 BinaryFormatter、LosFormatter、ObjectStateFormatter、JSON.NET TypeNameHandling、DataContractSerializer、ViewState 以及 XXE、DTD、XmlResolver 和外部实体。
metadata:
  tags: [dotnet, 反序列化, xxe, viewstate]
---

# .NET 反序列化与 XML 审计

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
4. 单批最多 50 个文件，并设置 60 到 120 秒执行上限。
5. 达到目标调用链、命中数量或时间预算后停止当前扫描，先输出已有证据。

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

## 输出

每条发现必须包含：

- 序列化/XML API。
- 输入来源。
- 类型或实体控制条件。
- 文件、行号、类和方法。
- 防护和部署依赖。
- 状态、置信度、影响和修复。

## 禁止

- 不生成或执行真实反序列化 payload。
- 不加载不可信程序集。
- 不访问外部 DTD、URL 或远程 schema。
