from __future__ import annotations

import hashlib
import uuid
from typing import Any
from urllib.parse import urlsplit

from normalization.core.models import CanonicalHTTPFlow, UnifiedEvent


EVENT_SCHEMA_VERSION = 4
EVENT_TYPES = frozenset({
    "provider_instruction",
    "agent_behavior",
    "generic_traffic",
    "connect_observed",
    "connect_result",
    "connect_established",
    "connect_closed",
    "udp_sendmsg_observed",
    "udp_sendmsg_result",
    "bypass_network_attempt",
})
PARSE_STATUSES = frozenset({"success", "partial", "unsupported", "failed"})
VISIBILITY_LEVELS = frozenset({
    "full_content",
    "endpoint_semantics",
    "metadata_only",
    "blocked",
})
OBSERVATION_STATUSES = frozenset({"success", "partial", "failed"})
BEHAVIOR_CLASSIFICATIONS = frozenset({
    "NotAssessed",
    "Consistent",
    "Inconsistent",
    "Uncertain",
})


def _observation_status(parse_status: str) -> str:
    if parse_status == "success":
        return "success"
    if parse_status in {"partial", "unsupported"}:
        return "partial"
    return "failed"


def _failure_reason(
    parse_status: str,
    error: dict[str, Any] | None,
    *,
    blocked: bool = False,
) -> str:
    if blocked:
        return "policy_blocked"
    if error and error.get("code"):
        return str(error["code"])
    if parse_status == "unsupported":
        return "unsupported_application_semantics"
    if parse_status == "partial":
        return "partial_application_semantics"
    if parse_status == "failed":
        return "parse_failed"
    return "none"


def _validate_visibility(
    *,
    visibility_level: str,
    observation_status: str,
    behavior_classification: str,
    evidence_sources: list[str],
) -> None:
    if visibility_level not in VISIBILITY_LEVELS:
        raise ValueError(f"unknown visibility level: {visibility_level}")
    if observation_status not in OBSERVATION_STATUSES:
        raise ValueError(f"unknown observation status: {observation_status}")
    if behavior_classification not in BEHAVIOR_CLASSIFICATIONS:
        raise ValueError(
            f"unknown behavior classification: {behavior_classification}"
        )
    if not evidence_sources or any(not source for source in evidence_sources):
        raise ValueError("evidence_sources must contain at least one non-empty source")


def content_evidence(
    body: bytes,
    *,
    preview: str | None = None,
    structured: Any = None,
    limit: int = 1024,
) -> dict[str, Any]:
    """Return bounded evidence without silently losing body size or integrity."""
    evidence: dict[str, Any] = {
        "byte_length": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "truncated": False,
    }
    if preview is not None:
        encoded = preview.encode("utf-8")
        if len(encoded) > limit:
            encoded = encoded[:limit]
            preview = encoded.decode("utf-8", errors="ignore")
            evidence["truncated"] = True
        evidence["preview"] = preview
    if structured is not None:
        evidence["structured"] = structured
    return evidence


def _address(value: tuple[str, int] | None) -> dict[str, Any]:
    if value is None:
        return {"ip": None, "port": None}
    return {"ip": value[0], "port": value[1]}


def make_http_event(
    flow: CanonicalHTTPFlow,
    *,
    event_type: str,
    direction: str,
    application_protocol: str,
    semantic_type: str,
    adapter_name: str,
    parse_status: str,
    content: dict[str, Any],
    content_type: str | None,
    carrier: dict[str, Any] | None = None,
    correlation: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
    visibility_level: str | None = None,
    observation_status: str | None = None,
    failure_reason: str | None = None,
    evidence_sources: list[str] | None = None,
    behavior_classification: str = "NotAssessed",
) -> UnifiedEvent:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type: {event_type}")
    if parse_status not in PARSE_STATUSES:
        raise ValueError(f"unknown parse status: {parse_status}")
    resolved_visibility = visibility_level or (
        "full_content" if parse_status == "success" else "metadata_only"
    )
    resolved_observation = observation_status or _observation_status(parse_status)
    resolved_failure = failure_reason or _failure_reason(parse_status, error)
    resolved_sources = list(evidence_sources or ["gateway"])
    _validate_visibility(
        visibility_level=resolved_visibility,
        observation_status=resolved_observation,
        behavior_classification=behavior_classification,
        evidence_sources=resolved_sources,
    )
    request_path = urlsplit(flow.request.path).path
    request_metadata = {
        "method": flow.request.method,
        "scheme": flow.request.scheme,
        "host": flow.request.host,
        "port": flow.request.port,
        "path": request_path,
        "content_type": flow.request.headers.get("content-type"),
        "body_bytes": len(flow.request.body),
    }
    response_metadata = None
    if flow.response_status is not None or flow.response_headers or flow.response_body:
        response_metadata = {
            "status_code": flow.response_status,
            "content_type": flow.response_headers.get("content-type"),
            "body_bytes": len(flow.response_body),
        }
    source = _address(flow.client_address)
    source.update({
        "identity": flow.proxy_principal,
        "harness_id": flow.harness_id,
        "workload_id": flow.workload_id,
    })
    destination = _address(flow.server_address)
    destination.update({
        "host": flow.request.host,
        "port": flow.request.port,
        "scheme": flow.request.scheme,
    })
    base_correlation = {
        "run_id": flow.run_id,
        "flow_id": flow.flow_id,
        "session_id": flow.session_id,
        "proxy_principal": flow.proxy_principal,
    }
    if correlation:
        base_correlation.update(correlation)
    return UnifiedEvent(
        schema_version=EVENT_SCHEMA_VERSION,
        event_id=f"evt_{uuid.uuid4().hex}",
        event_type=event_type,
        flow_id=flow.flow_id,
        run_id=flow.run_id,
        session_id=flow.session_id,
        workload={
            "harness_id": flow.harness_id,
            "workload_id": flow.workload_id,
            "proxy_principal": flow.proxy_principal,
        },
        timestamp=flow.timestamp_start if direction == "request" else flow.timestamp_end,
        direction=direction,
        transport_protocol=flow.transport_protocol,
        application_protocol=application_protocol,
        semantic_type=semantic_type,
        source=source,
        destination=destination,
        carrier=carrier or {"type": "http", "direction": direction},
        request=request_metadata,
        response=response_metadata,
        content=content,
        content_type=content_type,
        adapter_name=adapter_name,
        parse_status=parse_status,
        visibility_level=resolved_visibility,
        observation_status=resolved_observation,
        failure_reason=resolved_failure,
        evidence_sources=resolved_sources,
        behavior_classification=behavior_classification,
        correlation=base_correlation,
        error=error,
    )


def make_observation_event(
    *,
    event_type: str,
    run_id: str,
    session_id: str | None,
    harness_id: str,
    workload_id: str,
    timestamp: float | str | None,
    direction: str,
    transport_protocol: str,
    application_protocol: str,
    semantic_type: str,
    source: dict[str, Any],
    destination: dict[str, Any],
    carrier: dict[str, Any],
    content: dict[str, Any],
    content_type: str | None,
    adapter_name: str,
    parse_status: str,
    flow_id: str | None = None,
    proxy_principal: str | None = None,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    correlation: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
    event_id: str | None = None,
    visibility_level: str | None = None,
    observation_status: str | None = None,
    failure_reason: str | None = None,
    evidence_sources: list[str] | None = None,
    behavior_classification: str = "NotAssessed",
) -> UnifiedEvent:
    """Create a v4 event for evidence produced outside an HTTP flow.

    Endpoint sensors, firewall logs and local transports use the same identity
    envelope as proxy events.  Callers must describe only observed facts; this
    helper intentionally performs no protocol inference.
    """
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type: {event_type}")
    if parse_status not in PARSE_STATUSES:
        raise ValueError(f"unknown parse status: {parse_status}")
    carrier_type = str(carrier.get("type") or "unknown")
    structured = content.get("structured") if isinstance(content, dict) else None
    action = structured.get("action") if isinstance(structured, dict) else None
    blocked = action in {"drop", "blocked", "reject"}
    if visibility_level is None:
        if blocked:
            visibility_level = "blocked"
        elif carrier_type in {"stdio", "process_wrapper"} and parse_status == "success":
            visibility_level = "endpoint_semantics"
        elif carrier_type == "websocket" and parse_status == "success":
            visibility_level = "full_content"
        else:
            visibility_level = "metadata_only"
    if evidence_sources is None:
        if carrier_type == "endpoint_ebpf":
            evidence_sources = ["endpoint_ebpf"]
        elif carrier_type == "network_control_log":
            evidence_sources = ["network_policy"]
        elif carrier_type in {"stdio", "process_wrapper"}:
            evidence_sources = ["endpoint_runtime"]
        elif carrier_type in {"websocket", "tls_handshake"}:
            evidence_sources = ["gateway"]
        else:
            evidence_sources = ["observation_sensor"]
    resolved_observation = observation_status or _observation_status(parse_status)
    resolved_failure = failure_reason or _failure_reason(
        parse_status,
        error,
        blocked=blocked,
    )
    resolved_sources = list(evidence_sources)
    _validate_visibility(
        visibility_level=visibility_level,
        observation_status=resolved_observation,
        behavior_classification=behavior_classification,
        evidence_sources=resolved_sources,
    )
    base_correlation = {
        "run_id": run_id,
        "flow_id": flow_id,
        "session_id": session_id,
        "proxy_principal": proxy_principal,
    }
    if correlation:
        base_correlation.update(correlation)
    return UnifiedEvent(
        schema_version=EVENT_SCHEMA_VERSION,
        event_id=event_id or f"evt_{uuid.uuid4().hex}",
        event_type=event_type,
        flow_id=flow_id,
        run_id=run_id,
        session_id=session_id,
        workload={
            "harness_id": harness_id,
            "workload_id": workload_id,
            "proxy_principal": proxy_principal,
        },
        timestamp=timestamp,
        direction=direction,
        transport_protocol=transport_protocol,
        application_protocol=application_protocol,
        semantic_type=semantic_type,
        source=source,
        destination=destination,
        carrier=carrier,
        request=request,
        response=response,
        content=content,
        content_type=content_type,
        adapter_name=adapter_name,
        parse_status=parse_status,
        visibility_level=visibility_level,
        observation_status=resolved_observation,
        failure_reason=resolved_failure,
        evidence_sources=resolved_sources,
        behavior_classification=behavior_classification,
        correlation=base_correlation,
        error=error,
    )
