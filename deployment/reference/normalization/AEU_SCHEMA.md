# AEU schema v2（历史兼容格式）

AEU v2 描述 Model API **请求侧**的一个内容单元，供历史 Exact Detector 使用。当前
行为一致性链路使用 `EVENT_SCHEMA.md` 的 unified event v4；AEU 不表示 Provider 响应、
行为关联或最终判定。

## 顶层字段

| 字段 | 含义 |
| --- | --- |
| `schema_version` | 固定为 `2` |
| `aeu_id` | 转换生成的单元 ID |
| `run_id` / `flow_id` | 运行和 Flow 关联键 |
| `harness_id` / `proxy_principal` / `session_id` | 身份与会话 |
| `timestamp` / `protocol` | 请求时间和协议 |
| `semantic_type` / `content` | 内容用途和原文 |
| `carrier` | 消息、block、part 或工具定义容器 |
| `protocol_locator` | 原始 JSON 位置和协议索引 |
| `tool_context` | 真实 tool ID/name/定义与调用位置 |
| `sink` | Provider、API、host、port、path、model、flow_id |
| `unit_index` / `content_metadata` | 请求内顺序、长度、SHA-256、解析状态 |

`semantic_type`：`system_instruction`、`message_content`、`tool_arguments`、
`tool_result`、`tool_definition`、`inline_text`、`file_reference`、
`adapter_diagnostic`。

`content_metadata.parse_status`：

- `success`：正文成功恢复；
- `partial`：未知 block/part 或不支持的局部内容，诊断正文为空；
- `failed`：UTF-8、JSON 或顶层结构解析失败。

## 跨协议映射

| 协议内容 | AEU 语义 |
| --- | --- |
| OpenAI system/普通/tool message | system、message、tool_result |
| OpenAI `tool_calls[].function.arguments` | tool_arguments |
| Anthropic system/text/tool_use/tool_result | system、message、tool_arguments、tool_result |
| Gemini system/text/functionCall/functionResponse | system、message、tool_arguments、tool_result |
| 三种协议工具定义 | tool_definition |
| 文本 inline data / 文件 URI | inline_text / file_reference |

工具关联只使用协议实际提供的 ID。Gemini 没有调用 ID 时不会按名称伪造 ID；跨请求关联
不属于 AEU v2。

`protocol_locator` 只定位请求字段，不代表敏感 Source。`sink.path` 不含 query，Adapter
不读取认证头或 API key。`content` 的长度和 SHA-256 始终按 UTF-8 原文计算。

## 兼容边界

历史 AEU v1 仍可由 Exact Detector 读取，因为 Detector 只依赖 `aeu_id/run_id/content`。
新 Adapter 只生成 v2，不双写旧字段。AEU 不包含 source match、decision、allow/block
或一致性结论。
