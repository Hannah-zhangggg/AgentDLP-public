# Gateway Host Firewall

The Gateway VM currently uses iptables and manages only AgentDLP-owned `INPUT`, `FORWARD` and `OUTPUT` chains. It never flushes unrelated host or Docker rules. The normal path is explicit proxy plus controlled DNS; Endpoint-to-External forwarding is denied unless a reviewed, time-bounded control explicitly enables it.

## Safety model

- INPUT permits management, established traffic and configured Agent-LAN proxy/DNS ports.
- When explicitly configured, INPUT additionally permits only the Endpoint Agent-LAN CIDR to the fixed synthetic remote-MCP relay port; the host relay has exactly one reviewed External upstream.
- FORWARD permits established traffic, Agent-LAN traffic DNATed to the proxy and proxy-container traffic only to reviewed External IP:port pairs.
- OUTPUT is observation-first by default; enforcing host output is only for a console-backed maintenance window.
- `apply` arms automatic rollback; only a separate SSH/health verification followed by `confirm` enables persistence.

## Deployment

```bash
cd /home/zhang/agentdlp/deployment/three-vm/gateway-vm/egress-policy
cp gateway-egress.env.example /tmp/gateway-egress.env
$EDITOR /tmp/gateway-egress.env
./agentdlp-gateway-egress render /tmp/gateway-egress.env
sudo ./agentdlp-gateway-egress install /tmp/gateway-egress.env
sudo /usr/local/sbin/agentdlp-gateway-egress preflight
sudo /usr/local/sbin/agentdlp-gateway-egress apply
```

Open a second SSH session, inspect `status` and proxy/upstream health, then `confirm`. If any check fails, do not confirm; use the rollback timer or run `rollback` from the console. Reboot validation similarly uses `arm-reboot-rollback` and `disarm-reboot-rollback`.

Earlier runs validated apply/rollback/confirm and selected proxy/upstream paths. The controlled redirect listener and temporary direct-forward controls are disabled historical fixtures, not part of dataset v2.

## Persistent synthetic remote MCP

Set `AGENTDLP_GATEWAY_REMOTE_MCP_PORT` and
`AGENTDLP_GATEWAY_REMOTE_MCP_UPSTREAM` together to deploy the bounded
remote-MCP relay described in `../remote-mcp/`. The first value is an
Endpoint-facing Gateway listener; the second is the relay's only host-side
destination. The policy manager rejects a configuration that supplies only
one. This is a fixed experiment capability, not a general Endpoint-to-External
forwarding rule.
