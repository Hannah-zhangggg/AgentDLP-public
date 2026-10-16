from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class CanonicalRequest:
    run_id: str
    flow_id: str
    harness_id: str
    proxy_principal: str | None
    timestamp: float | None
    method: str
    scheme: str
    host: str
    port: int
    path: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class CanonicalHTTPFlow:
    """Capture-tool-neutral representation of one bidirectional HTTP flow."""

    run_id: str
    flow_id: str
    harness_id: str
    workload_id: str
    proxy_principal: str | None
    session_id: str | None
    timestamp_start: float | None
    timestamp_end: float | None
    transport_protocol: str
    client_address: tuple[str, int] | None
    server_address: tuple[str, int] | None
    request: CanonicalRequest
    response_status: int | None
    response_headers: dict[str, str]
    response_body: bytes
    error: str | None = None


@dataclass(frozen=True)
class AgentEgressUnit:
    schema_version: int
    aeu_id: str
    run_id: str
    flow_id: str
    harness_id: str
    proxy_principal: str | None
    timestamp: float | None
    protocol: str
    session_id: str | None
    semantic_type: str
    content: str
    carrier: dict[str, Any]
    protocol_locator: dict[str, Any]
    tool_context: dict[str, Any] | None
    sink: dict[str, Any]
    unit_index: int
    content_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class UnifiedEvent:
    """Schema v4 event used by instruction/behavior consistency analysis.

    AEU v2 remains the compatibility format for the historical content detector.
    This envelope extends the same run/flow/session identity model to response-side
    instructions, generic HTTP, MCP, and network-control observations.
    """

    schema_version: int
    event_id: str
    event_type: str
    flow_id: str | None
    run_id: str
    session_id: str | None
    workload: dict[str, Any]
    timestamp: float | str | None
    direction: str
    transport_protocol: str
    application_protocol: str
    semantic_type: str
    source: dict[str, Any]
    destination: dict[str, Any]
    carrier: dict[str, Any]
    request: dict[str, Any] | None
    response: dict[str, Any] | None
    content: dict[str, Any]
    content_type: str | None
    adapter_name: str
    parse_status: str
    visibility_level: str
    observation_status: str
    failure_reason: str
    evidence_sources: list[str]
    behavior_classification: str
    correlation: dict[str, Any]
    error: dict[str, Any] | None = None

    def to_dict(self):
        return asdict(self)
