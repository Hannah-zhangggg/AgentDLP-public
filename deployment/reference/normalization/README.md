# Normalization

`normalization/` converts Gateway flows, Endpoint observations and policy/arrival logs into unified facts.

## Current outputs

- Unified event v4: Provider instructions, Agent/tool effects, generic traffic, TCP lifecycle, UDP sends, identity, visibility and observation status.
- AEU v2: historical content-detection compatibility format only.

## Evidence pipeline

```text
Gateway HTTPFlow -> protocol adapters/reassembly -> provider_instruction and traffic events
Endpoint wrappers -> file/process/MCP/HTTP effect events
Endpoint CO-RE -> TCP lifecycle + UDP send + workload identity events
nftables/DNS/Gateway/External logs -> block/forward/arrival events
all sources -> correlation/classification
```

Provider adapters cover OpenAI, Anthropic and Gemini normal/streaming calls. MCP, generic HTTP, WebSocket and TLS failures have separate adapters; malformed or unknown inputs produce explicit fallback/diagnostic events rather than disappearing.

Dataset v2 uses the Gateway `provider_instruction` as its runtime baseline. Public cases, fault plans and labels cannot substitute for capture. Incomplete reassembly, conflicting IDs or non-unique flow association yields `Uncertain`.

Endpoint network events cover TCP attempt/result/established/closed and UDP `sendto`/`sendmsg`/`sendmmsg`, including connected-datagram metadata. Identity enrichment includes cgroup ID, PID/start time, PID/mount/network namespace inode, UID/GID, container/Pod ID and socket cookie where available.

L3/L4 evidence does not prove arrival or application semantics. Gateway/External logs establish arrival; TLS termination, protocol adapters or Endpoint wrappers establish semantics. Unknown/encrypted traffic remains metadata-only, and missing best-effort identity fields are explicit.

Historical redirect fields remain schema-compatible but are not part of the current mechanism. New adapters must test valid, malformed, unknown and attribution-failure cases.

```bash
python3 -B -m unittest discover -s tests -v
```
