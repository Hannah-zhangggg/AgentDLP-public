from __future__ import annotations

import json
from typing import Any

from normalization.core.event_schema import content_evidence, make_observation_event
from normalization.core.models import UnifiedEvent


def tls_failure_to_event(
    *,
    side: str,
    timestamp: float | str | None,
    source: dict[str, Any],
    destination: dict[str, Any],
    transport_protocol: str,
    server_name: str | None,
    alpn: str | None,
    reason: str | None,
    defaults: dict[str, Any],
) -> UnifiedEvent:
    if side not in {"client", "server"}:
        raise ValueError("TLS side must be client or server")
    harness_id = str(defaults.get("harness_id") or "unknown")
    observed = {
        "side": side,
        "server_name": server_name,
        "alpn": alpn,
        "reason": (reason or "TLS handshake failed")[:1024],
    }
    body = json.dumps(observed, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return make_observation_event(
        event_type="generic_traffic",
        run_id=str(defaults.get("run_id") or "local"),
        session_id=defaults.get("session_id"),
        harness_id=harness_id,
        workload_id=str(defaults.get("workload_id") or harness_id),
        proxy_principal=defaults.get("proxy_principal"),
        timestamp=timestamp,
        direction="outbound",
        transport_protocol=transport_protocol,
        application_protocol="dtls" if transport_protocol == "udp" else "tls",
        semantic_type="tls_handshake_failed",
        source=source,
        destination=destination,
        carrier={"type": "tls_handshake", "direction": "outbound", "side": side},
        content=content_evidence(body, structured=observed),
        content_type="application/x-agentdlp-tls-metadata",
        adapter_name="tls_failure_observer",
        parse_status="failed",
        correlation={"tls_side": side},
        error={"code": "tls_handshake_failed", "detail": observed["reason"]},
    )
