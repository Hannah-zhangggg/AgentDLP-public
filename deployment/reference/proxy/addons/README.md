# Mitmproxy Addons

- `metadata.py`：脱敏头/query，写 metadata JSONL 和脱敏 `.flow`。
- `unified_events.py`：Model API → MCP → Generic/Fallback，写 unified event v4。
- `websocket_events.py`：记录已解密 WebSocket 文本、JSON/JSON-RPC 和二进制元数据。
- `tls_events.py`：记录客户端或上游 TLS 握手失败，不伪造 HTTP 语义。
- `egress_policy.py`：限制 CONNECT 目的端口并拒绝已配置公共 DoH 或
  `application/dns-message` / `application/dns-json`；应与 `rawtcp=false` 同时启用，
  防止把 SSH 等非 TLS 协议装入允许的代理 CONNECT。
- `anthropic_sse.py`、`gemini_sse.py`：可选 Provider SSE 重组证据。
- `mock_provider_route.py`：只对配置的受控 Gemini HTTPS 目标改写 HTTP 上游。
- `online_dlp.py`：历史 AEU 精确阻断回归，默认关闭。

统一事件身份来自 Run/Harness/Workload/Session 和代理 principal。认证头及常见 secret
字段脱敏；Adapter 异常产生 failed Generic 事件，不退出 Mitmproxy。

Addon 只能解释进入代理且可解密的 HTTP(S)/WebSocket。DNS、直连 TCP、UDP/QUIC 由
网络日志导入；TLS 失败事件只有目标和握手元数据。

Dataset v2 的 Mitmproxy 只观察并重建 Provider 指令，不修改 Provider response。实验
故障由 Endpoint 的闭集动作分发器注入；Gateway 捕获缺失时检测器不得从 dataset 回填。
