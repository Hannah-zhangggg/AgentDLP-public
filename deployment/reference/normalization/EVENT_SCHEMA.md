# AgentDLP unified event schema v4

统一事件 v4 是 AEU v2 身份信封的兼容演进，用于“Provider 指令—Agent 实际行为一致性”
研究。AEU v2 仍是历史内容检测器的稳定输入；新的双向 Flow、MCP、通用 HTTP、端侧运行时
和网络控制事实输出 v4。v4 在 v3 上增加可见性、观测完整性、失败原因、证据来源和行为分类
字段，并正式纳入 TCP 连接生命周期事件。

## 事件类型

| `event_type` | 含义 | 当前来源 |
| --- | --- | --- |
| `provider_instruction` | Provider 响应中的结构化工具调用，或低确定性的文本响应 | Model API 响应 Adapter |
| `agent_behavior` | Agent、工具或子进程实际发出的 Model API、MCP 或可解析 HTTP 请求 | 请求 Adapter、端侧包装器 |
| `generic_traffic` | 已观察但没有更强业务语义的响应、二进制、TLS 失败或未知格式 | Generic/Fallback、WebSocket/TLS |
| `connect_observed` | 指定 Agent cgroup 选择 Socket 目标；不等于 TCP 已建立 | Endpoint eBPF `cgroup/connect4`、`connect6` |
| `connect_result` | `connect(2)` 立即结果，包括成功、`EINPROGRESS` 或失败 errno | Endpoint eBPF `sys_exit_connect` |
| `connect_established` | TCP 已建立，并取得本地源 IP/端口 | Endpoint eBPF cgroup sockops |
| `connect_closed` | TCP 已关闭，并取得 socket 累计收发计数 | Endpoint eBPF cgroup sockops |
| `udp_sendmsg_observed` | Agent workload 对 IPv4/IPv6 UDP 目标执行发送 | Endpoint eBPF cgroup hook / connected-UDP probe |
| `udp_sendmsg_result` | `sendto`、`sendmsg`、`sendmmsg` 的返回字节/消息数或失败 errno | Endpoint eBPF syscall-exit tracepoint |
| `bypass_network_attempt` | 防火墙或 DNS 日志观察到的 DNS、直连 TCP、UDP/QUIC 等尝试 | 网络日志导入器 |

普通 Provider 文本记录为 `provider_instruction` 时，
`correlation.instruction_certainty=low`；它不是已经确认的可执行工具指令。结构化
tool/function call 为 `high`。网关不会把纯本地 stdio MCP 或本地文件操作伪造成网络事件。

## 公共字段

每条事件固定包含：

```text
schema_version, event_id, event_type, flow_id, run_id, session_id,
workload, timestamp, direction, transport_protocol, application_protocol,
semantic_type, source, destination, carrier, request, response, content,
content_type, adapter_name, parse_status, visibility_level,
observation_status, failure_reason, evidence_sources,
behavior_classification, correlation, error
```

- `workload` 保存 `harness_id/workload_id/proxy_principal`；端侧 `process.workload_identity`
  进一步保存 cgroup ID、PID/start time、PID/mount/network namespace inode、UID/GID、
  container/Pod ID 与 socket cookie。无法读取的 `/proc`/runtime 字段保持为空并标记为
  best-effort，不能静默降级为等价的 UID-only 身份。
- `request/response` 保存方法、无查询字符串路径、状态码、Content-Type 和长度等元数据。
- `content` 固定保留字节长度和 SHA-256；JSON、表单、文本和 multipart 只保存受控结构或
  截断预览。认证头和常见 secret 字段不应进入事件正文。
- `parse_status` 只描述 Adapter 对这一条载荷的解析结果：
  `success/partial/unsupported/failed`。
- `visibility_level` 描述该证据对行为的最高可见层级：

  - `full_content`：取得可供语义比较的应用层正文或结构；
  - `endpoint_semantics`：由端侧包装器取得工具/进程语义，但没有网络应用正文；
  - `metadata_only`：仅有连接、TLS、长度、哈希或其他元数据；
  - `blocked`：策略已阻止动作完成；它不表示已取得被阻止载荷的正文。

- `observation_status` 描述采集是否完整：`success/partial/failed`。它与
  `visibility_level` 正交；例如完整记录一次被阻断连接是
  `visibility_level=blocked, observation_status=success`。
- `failure_reason` 在成功时为 `none`，否则保存稳定机器可读原因，例如
  `policy_blocked`、`partial_application_semantics`、`parse_failed` 或
  `connection_correlation_incomplete`。
- `evidence_sources` 是产生结论的非空来源列表，例如 `gateway`、`endpoint_ebpf`、
  `endpoint_runtime`、`network_policy`、`provider`。
- `behavior_classification` 的合法值为
  `NotAssessed/Consistent/Inconsistent/Uncertain`。单条原始事件默认 `NotAssessed`；
  只有跨 Provider、Agent、Endpoint、Gateway 的评估结果才能给出其余三类。
- 同一个 Mitmproxy Flow 产生的请求与响应事件共享
  `run_id/flow_id/session_id/workload`。

## 连接与 Flow 关联

v1.1 summary 使用 Endpoint established 事件的本地
`source.ip/source.port`、Gateway 固定目标和时间窗，把 Gateway HTTP flow 关联到
`socket_cookie`。Gateway 同一 TCP 连接可承载多个 HTTP flow，因此映射为：

```text
Endpoint socket_cookie 1 ── 0..N Gateway flow_id
Gateway flow_id         ── 恰好 1 个 Endpoint socket_cookie
```

若一个 flow 没有候选或有多个候选，关联分别标记为 `unmatched` 或 `ambiguous`；在
`--require-tcp-lifecycle` 模式下二者都会令观测状态变为 `partial`、失败原因为
`connection_correlation_incomplete`，行为分类为 `Uncertain`，不能误报
`Inconsistent`。当前关联采用源二元组和 1 秒时钟容差，不等于内核级分布式 tracing。

`connect_observed` 与 `connect_result` 时内核通常尚未分配可用本地源端口，因此
`source.port=null`；`connect_established` 与 `connect_closed` 才填写真实源端口。
`bytes_received/bytes_acked` 是 Linux TCP socket 累计计数，不是 HTTP 明文字节，也不是
pcap 双向线速字节。

UDP 路径覆盖 `sendto`、`sendmsg`、`sendmmsg` 和已连接 datagram。cgroup sockaddr hook
提供未连接发送的目标；已连接 IPv4 UDP 由限定 cgroup 的 probe 补充。`udp_sendmsg_result`
保存 syscall 返回值/errno。部分路径不能可靠取得 source port 或 socket cookie，因此只按
TID 和时间窗关联并保持 metadata/`Uncertain`；受控实验还需 Gateway tuple 与 External
receiver 独立佐证。

## Adapter 选择顺序

1. Model API：已知端点加 HTTP 方法、Content-Type 和协议结构；覆盖 OpenAI Chat
   Completions/Responses、Anthropic Messages、Gemini GenerateContent。
2. MCP/JSON-RPC：`jsonrpc=2.0` 结构，或受控 `/mcp` SSE/Streamable HTTP 入口。
3. Generic HTTP：GET/POST/PUT/PATCH/DELETE 等任意已进入 Mitmproxy 的 HTTP(S) Flow。
4. Fallback：任一 Adapter 抛出异常或返回空结果时，生成 `adapter_fallback`，不得终止
   Flow 处理链。

路径名称本身不能把普通请求识别为 Model API；MCP 未知方法保留为
`mcp_jsonrpc_request`。未知二进制只记录长度、哈希、目标和 `unsupported` 原因。

## 能力边界

v4 当前完整解释的是经 Mitmproxy 解密的 HTTP/HTTPS、三类 Model API 响应和 Remote
MCP JSON-RPC。SSE 支持 OpenAI、Anthropic、Gemini 以及 MCP JSON-RPC data。WebSocket
Addon 记录重组后的 text/JSON/JSON-RPC 消息；binary 只记录长度和哈希，不保留原始帧
边界。TLS 握手失败只记录可见端点、SNI/ALPN 和错误。

Endpoint CO-RE wrapper 直接输出自身 schema v1 的连接事实 JSONL；需要统一事件时，再由
`normalization.network_cli` 导入为 v4。stdio MCP、显式本地进程和 workspace 文件写入
经端侧包装器生成 `agent_behavior`。

本地包装器在 `correlation.tool_call_id` 中只写入调用端显式建立的 Provider/Agent
tool-call ID；MCP 的 `correlation.jsonrpc_id` 是另一种本地传输 ID，不能自动互换。
因此，同一 `tool_call_id` 的 process/MCP/file events 可以证明同一次已映射工具调用的
端侧效果；只有 JSON-RPC ID 或缺少包装器时必须保守地保持 `Uncertain`。文件写入事件
只保留解析路径、mode、长度和内容 SHA-256。未经包装的本地操作、任意原始 TCP/UDP
应用语义和未部署端侧传感器的进程归因仍不可见。

## 跨源行为一致性评估输出

`mismatch_type` 不属于单条 raw unified event，而是 `consistency/` 产生的跨源评估输出。
合法值固定为 `missing_action`、`extra_action`、`action_substitution`、`argument_mismatch`、
`destination_or_scope_mismatch`、`order_or_precondition_violation`、`effect_mismatch`、
`result_reporting_mismatch`。只有证据完整且结论为 `Inconsistent` 时可输出；`Uncertain`
必须为空。ground-truth 的 `expected_oracle` 仅供回归测试，运行时比较器不得读取。
详见 `../consistency/CASE_FORMAT.md`。
