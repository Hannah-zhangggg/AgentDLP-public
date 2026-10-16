# Proxy

- `addons/`：Mitmproxy 元数据、统一事件、SSE 重组和历史阻断插件。
- `certs/`：只允许导出的公开 CA；私钥留在 Mitmproxy volume。

```bash
./scripts/bootstrap/export-ca.sh
```

三 VM 可通过 `AGENTDLP_COMPOSE_FILE` 和 `AGENTDLP_CERT_DIR` 复用导出脚本。禁止复制
Mitmproxy state、私钥或真实凭据。
