from __future__ import annotations

import json
from typing import Any

from normalization.adapters.generic.http import sanitize_structured
from normalization.core.event_schema import content_evidence, make_observation_event
from normalization.core.models import UnifiedEvent


def websocket_message_to_event(
    content: bytes,
    *,
    from_client: bool,
    message_type: str,
    timestamp: float | str | None,
    flow_id: str,
    source: dict[str, Any],
    destination: dict[str, Any],
    request: dict[str, Any],
    sequence: int,
    defaults: dict[str, Any],
) -> UnifiedEvent:
    direction = "request" if from_client else "response"
    message_kind = message_type.lower()
    is_text = "text" in message_kind or message_kind == "1"
    application_protocol = "websocket"
    semantic_type = "websocket_text_message" if is_text else "websocket_binary_message"
    parse_status = "success" if is_text else "unsupported"
    structured = None
    preview = None
    error = None

    if is_text:
        try:
            decoded = content.decode("utf-8")
            preview = decoded
            try:
                value = json.loads(decoded)
            except json.JSONDecodeError:
                value = None
            if value is not None:
                structured = sanitize_structured(value)
                semantic_type = "websocket_json_message"
                if isinstance(value, dict) and value.get("jsonrpc") == "2.0":
                    application_protocol = "jsonrpc_over_websocket"
                    semantic_type = "websocket_jsonrpc_message"
        except UnicodeDecodeError as exc:
            parse_status = "partial"
            semantic_type = "websocket_invalid_text"
            error = {"code": "invalid_websocket_utf8", "detail": str(exc)}
    else:
        error = {"code": "unsupported_websocket_binary_semantics"}

    harness_id = str(defaults.get("harness_id") or "unknown")
    correlation = {
        "websocket_sequence": sequence,
        "websocket_from_client": from_client,
    }
    if structured and isinstance(structured, dict):
        correlation.update({
            "jsonrpc_id": structured.get("id"),
            "jsonrpc_method": structured.get("method"),
        })
    return make_observation_event(
        event_type="agent_behavior" if from_client else "generic_traffic",
        flow_id=flow_id,
        run_id=str(defaults.get("run_id") or "local"),
        session_id=defaults.get("session_id"),
        harness_id=harness_id,
        workload_id=str(defaults.get("workload_id") or harness_id),
        proxy_principal=defaults.get("proxy_principal"),
        timestamp=timestamp,
        direction=direction,
        transport_protocol="tcp",
        application_protocol=application_protocol,
        semantic_type=semantic_type,
        source=source,
        destination=destination,
        carrier={"type": "websocket", "direction": direction, "message_type": message_type},
        request=request,
        content=content_evidence(content, preview=preview, structured=structured),
        content_type="text/plain; charset=utf-8" if is_text else "application/octet-stream",
        adapter_name="websocket_message",
        parse_status=parse_status,
        correlation=correlation,
        error=error,
    )
