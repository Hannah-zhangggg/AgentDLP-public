from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

from mitmproxy import http

from normalization.core.event_log import append_events
from normalization.websocket_events import websocket_message_to_event


ENABLED = True


def load(loader):
    global ENABLED
    ENABLED = os.environ.get("AGENTDLP_WEBSOCKET_LOG", "true").lower() == "true"


def _address(value):
    if value is None:
        return {"ip": None, "port": None}
    try:
        return {"ip": str(value[0]), "port": int(value[1])}
    except (TypeError, ValueError, IndexError):
        return {"ip": None, "port": None}


def websocket_message(flow: http.HTTPFlow):
    if not ENABLED or flow.websocket is None or not flow.websocket.messages:
        return
    message = flow.websocket.messages[-1]
    sequence = int(flow.metadata.get("agentdlp_websocket_sequence", 0)) + 1
    flow.metadata["agentdlp_websocket_sequence"] = sequence
    run_id = os.environ.get("AGENTDLP_RUN_ID", "local")
    harness_id = os.environ.get("AGENTDLP_HARNESS_ID", "unknown")
    session_id = os.environ.get("AGENTDLP_SESSION_ID") or None
    if session_id is None:
        for name in ("x-agentdlp-session-id", "x-session-affinity", "x-session-id"):
            if flow.request.headers.get(name):
                session_id = flow.request.headers[name]
                break
    proxy_principal = flow.metadata.get("agentdlp_proxy_principal")
    client = _address(flow.client_conn.address)
    client.update({"identity": proxy_principal, "harness_id": harness_id})
    server = _address(getattr(flow.server_conn, "peername", None) or flow.server_conn.address)
    server.update({"host": flow.request.host, "port": flow.request.port})
    raw_type = getattr(message, "type", "unknown")
    message_type = str(getattr(raw_type, "name", raw_type)).lower()
    event = websocket_message_to_event(
        message.content,
        from_client=bool(message.from_client),
        message_type=message_type,
        timestamp=message.timestamp,
        flow_id=flow.id,
        source=client if message.from_client else server,
        destination=server if message.from_client else client,
        request={
            "method": flow.request.method,
            "scheme": flow.request.scheme,
            "host": flow.request.host,
            "port": flow.request.port,
            "path": urlsplit(flow.request.path).path,
        },
        sequence=sequence,
        defaults={
            "run_id": run_id,
            "session_id": session_id,
            "harness_id": harness_id,
            "workload_id": os.environ.get("AGENTDLP_WORKLOAD_ID", harness_id),
            "proxy_principal": proxy_principal,
        },
    )
    output_dir = Path(os.environ.get("AGENTDLP_EVENT_DIR", "/artifacts/events"))
    append_events(output_dir / f"{run_id}.jsonl", [event])
