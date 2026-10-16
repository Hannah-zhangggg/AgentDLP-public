from __future__ import annotations

import os
import time
from pathlib import Path

from mitmproxy import tls

from normalization.core.event_log import append_events
from normalization.tls_events import tls_failure_to_event


ENABLED = True


def load(loader):
    global ENABLED
    ENABLED = os.environ.get("AGENTDLP_TLS_FAILURE_LOG", "true").lower() == "true"


def _address(value):
    if value is None:
        return {"ip": None, "port": None}
    try:
        return {"ip": str(value[0]), "port": int(value[1])}
    except (TypeError, ValueError, IndexError):
        return {"ip": None, "port": None}


def _write(data: tls.TlsData, side: str):
    if not ENABLED:
        return
    context = data.context
    client = _address(
        getattr(context.client, "peername", None) or getattr(context.client, "address", None)
    )
    server = _address(
        getattr(context.server, "peername", None) or getattr(context.server, "address", None)
    )
    sni = context.client.sni or context.server.sni
    if sni:
        server["host"] = sni
    alpn_value = data.conn.alpn
    if isinstance(alpn_value, bytes):
        alpn_value = alpn_value.decode("ascii", errors="replace")
    run_id = os.environ.get("AGENTDLP_RUN_ID", "local")
    harness_id = os.environ.get("AGENTDLP_HARNESS_ID", "unknown")
    event = tls_failure_to_event(
        side=side,
        timestamp=time.time(),
        source=client,
        destination=server,
        transport_protocol=str(data.conn.transport_protocol or "tcp"),
        server_name=sni,
        alpn=alpn_value,
        reason=data.conn.error,
        defaults={
            "run_id": run_id,
            "session_id": os.environ.get("AGENTDLP_SESSION_ID") or None,
            "harness_id": harness_id,
            "workload_id": os.environ.get("AGENTDLP_WORKLOAD_ID", harness_id),
        },
    )
    output_dir = Path(os.environ.get("AGENTDLP_EVENT_DIR", "/artifacts/events"))
    append_events(output_dir / f"{run_id}.jsonl", [event])


def tls_failed_client(data: tls.TlsData):
    _write(data, "client")


def tls_failed_server(data: tls.TlsData):
    _write(data, "server")
