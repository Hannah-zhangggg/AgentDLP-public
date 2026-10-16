from __future__ import annotations

import hashlib
import json
from typing import Any

from normalization.adapters.generic.http import sanitize_structured
from normalization.adapters.tool_protocol.mcp_jsonrpc import KNOWN_METHODS
from normalization.core.event_schema import content_evidence, make_observation_event
from normalization.core.models import UnifiedEvent


def _identity(defaults: dict[str, Any]) -> dict[str, Any]:
    harness_id = str(defaults.get("harness_id") or "unknown")
    return {
        "run_id": str(defaults.get("run_id") or "local"),
        "session_id": defaults.get("session_id"),
        "harness_id": harness_id,
        "workload_id": str(defaults.get("workload_id") or harness_id),
        "proxy_principal": defaults.get("proxy_principal"),
    }


def stdio_mcp_message_to_event(
    message: bytes,
    *,
    direction: str,
    timestamp: float | str | None,
    process: dict[str, Any],
    defaults: dict[str, Any],
    tool_call_id: str | None = None,
) -> UnifiedEvent:
    """Normalize one newline-delimited MCP stdio message.

    The relay records malformed lines as generic evidence instead of dropping or
    modifying them.  Message bytes are still forwarded by the caller unchanged.
    """
    identity = _identity(defaults)
    error = None
    correlation: dict[str, Any] = {
        "pid": process.get("pid"),
        "ppid": process.get("ppid"),
        # A Provider/Agent tool-call id is supplied explicitly. JSON-RPC uses
        # its own local id below, which must not be mistaken for Provider
        # evidence when a caller has not established that mapping.
        "tool_call_id": tool_call_id,
    }
    semantic_type = "mcp_stdio_message"
    parse_status = "success"
    structured = None
    try:
        value = json.loads(message.decode("utf-8"))
        if not isinstance(value, (dict, list)):
            raise ValueError("JSON-RPC message must be an object or batch")
        structured = sanitize_structured(value)
        item = value if isinstance(value, dict) else (value[0] if value else {})
        if isinstance(item, dict):
            method = item.get("method")
            correlation.update({"jsonrpc_id": item.get("id"), "mcp_method": method})
            if method:
                semantic_type = KNOWN_METHODS.get(str(method), "mcp_jsonrpc_request")
            elif "result" in item or "error" in item:
                semantic_type = "mcp_jsonrpc_response"
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        parse_status = "failed"
        semantic_type = "mcp_stdio_parse_error"
        error = {"code": "invalid_stdio_jsonrpc", "detail": str(exc)[:512]}

    return make_observation_event(
        event_type="agent_behavior" if direction == "request" else "generic_traffic",
        run_id=identity["run_id"],
        session_id=identity["session_id"],
        harness_id=identity["harness_id"],
        workload_id=identity["workload_id"],
        proxy_principal=identity["proxy_principal"],
        timestamp=timestamp,
        direction=direction,
        transport_protocol="local",
        application_protocol="mcp_stdio",
        semantic_type=semantic_type,
        source={"type": "mcp_client" if direction == "request" else "mcp_server", "process": process},
        destination={"type": "mcp_server" if direction == "request" else "mcp_client"},
        carrier={"type": "stdio", "direction": direction},
        content=content_evidence(message, structured=structured),
        content_type="application/json",
        adapter_name="mcp_stdio_sensor",
        parse_status=parse_status,
        correlation=correlation,
        error=error,
    )


def local_process_event(
    *,
    executable: str,
    argv: list[str],
    pid: int,
    ppid: int,
    phase: str,
    timestamp: float | str | None,
    defaults: dict[str, Any],
    returncode: int | None = None,
    tool_call_id: str | None = None,
) -> UnifiedEvent:
    """Record a command launched through the explicit endpoint wrapper.

    Raw arguments are not persisted because command lines often contain tokens.
    The count and a deterministic hash retain correlation and audit value.
    """
    if phase not in {"start", "end"}:
        raise ValueError("process phase must be start or end")
    identity = _identity(defaults)
    argv_bytes = json.dumps(argv, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    observed = {
        "executable": executable,
        "argument_count": max(0, len(argv) - 1),
        "argv_sha256": hashlib.sha256(argv_bytes).hexdigest(),
        "pid": pid,
        "ppid": ppid,
        "phase": phase,
        "returncode": returncode,
    }
    body = json.dumps(observed, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return make_observation_event(
        event_type="agent_behavior",
        run_id=identity["run_id"],
        session_id=identity["session_id"],
        harness_id=identity["harness_id"],
        workload_id=identity["workload_id"],
        proxy_principal=identity["proxy_principal"],
        timestamp=timestamp,
        direction="local",
        transport_protocol="local",
        application_protocol="process",
        semantic_type=f"local_process_{phase}",
        source={"type": "endpoint_process", "pid": ppid},
        destination={"type": "local_executable", "path": executable, "pid": pid},
        carrier={"type": "process_wrapper", "direction": "local"},
        content=content_evidence(body, structured=observed),
        content_type="application/x-agentdlp-process-event",
        adapter_name="local_process_sensor",
        parse_status="success",
        correlation={
            "pid": pid,
            "ppid": ppid,
            "process_phase": phase,
            "tool_call_id": tool_call_id,
        },
    )


def local_file_write_event(
    *,
    path: str,
    content: bytes,
    pid: int,
    ppid: int,
    mode: str,
    timestamp: float | str | None,
    defaults: dict[str, Any],
    tool_call_id: str,
) -> UnifiedEvent:
    """Record a completed file write through the explicit endpoint wrapper.

    Only resolved path, byte length, and digest are retained. A command line
    alone is not treated as proof that the filesystem effect completed.
    """
    if not tool_call_id:
        raise ValueError("tool_call_id is required for a file-write effect")
    if mode not in {"create", "replace", "append"}:
        raise ValueError("file write mode must be create, replace, or append")
    identity = _identity(defaults)
    observed = {
        "effect_type": "file_write",
        "path": path,
        "mode": mode,
        "byte_length": len(content),
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "pid": pid,
        "ppid": ppid,
    }
    body = json.dumps(observed, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return make_observation_event(
        event_type="agent_behavior",
        run_id=identity["run_id"],
        session_id=identity["session_id"],
        harness_id=identity["harness_id"],
        workload_id=identity["workload_id"],
        proxy_principal=identity["proxy_principal"],
        timestamp=timestamp,
        direction="local",
        transport_protocol="local",
        application_protocol="file",
        semantic_type="local_file_write",
        source={"type": "endpoint_process", "pid": ppid},
        destination={"type": "local_file", "path": path, "pid": pid},
        carrier={"type": "process_wrapper", "direction": "local"},
        content=content_evidence(body, structured=observed),
        content_type="application/x-agentdlp-file-write-event",
        adapter_name="local_file_write_sensor",
        parse_status="success",
        correlation={
            "pid": pid,
            "ppid": ppid,
            "tool_call_id": tool_call_id,
            "effect_type": "file_write",
        },
    )
