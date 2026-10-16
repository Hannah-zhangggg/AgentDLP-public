from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from normalization.adapters.generic.http import sanitize_structured
from normalization.core.event_schema import content_evidence, make_http_event
from normalization.core.models import CanonicalHTTPFlow, UnifiedEvent
from normalization.reassembly.anthropic_sse import iter_sse_events


KNOWN_METHODS = {
    "initialize": "mcp_initialize",
    "notifications/initialized": "mcp_initialized_notification",
    "tools/list": "mcp_tools_list",
    "tools/call": "mcp_tools_call",
    "resources/list": "mcp_resources_list",
    "resources/read": "mcp_resources_read",
    "prompts/list": "mcp_prompts_list",
    "prompts/get": "mcp_prompts_get",
}


def _bounded(value: Any, limit: int = 4096) -> dict[str, Any]:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    safe_value = sanitize_structured(value)
    safe_raw = json.dumps(safe_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return content_evidence(
        raw,
        preview=safe_raw[:limit].decode("utf-8", errors="ignore"),
        structured=safe_value if len(safe_raw) <= limit else None,
        limit=limit,
    )


def _jsonrpc_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    return []


class MCPJSONRPCAdapter:
    name = "mcp_jsonrpc"

    def _request_value(self, flow: CanonicalHTTPFlow) -> Any:
        return json.loads(flow.request.body.decode("utf-8") or "{}")

    def matches(self, flow: CanonicalHTTPFlow) -> bool:
        path = urlsplit(flow.request.path).path.rstrip("/").lower()
        if flow.request.method.upper() == "GET" and path.endswith(("/mcp", "/sse")):
            return "text/event-stream" in flow.request.headers.get("accept", "").lower()
        if flow.request.method.upper() != "POST":
            return False
        try:
            items = _jsonrpc_items(self._request_value(flow))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return path.endswith("/mcp") and "json" in flow.request.headers.get("content-type", "").lower()
        return bool(items) and all(item.get("jsonrpc") == "2.0" for item in items)

    def adapt(self, flow: CanonicalHTTPFlow) -> list[UnifiedEvent]:
        events: list[UnifiedEvent] = []
        path = urlsplit(flow.request.path).path.rstrip("/").lower()
        if flow.request.method.upper() == "GET":
            events.append(self._event(
                flow,
                direction="request",
                event_type="agent_behavior",
                semantic_type="mcp_sse_connect",
                value={"path": path},
                parse_status="success",
            ))
        else:
            try:
                request_value = self._request_value(flow)
                request_items = _jsonrpc_items(request_value)
                if not request_items:
                    raise ValueError("JSON-RPC request must be an object or object array")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                events.append(make_http_event(
                    flow,
                    event_type="generic_traffic",
                    direction="request",
                    application_protocol="mcp_jsonrpc",
                    semantic_type="mcp_parse_error",
                    adapter_name=self.name,
                    parse_status="failed",
                    content=content_evidence(flow.request.body),
                    content_type=flow.request.headers.get("content-type"),
                    error={"code": "invalid_jsonrpc_request", "detail": str(exc)},
                ))
                return events
            for index, item in enumerate(request_items):
                method = item.get("method")
                semantic = KNOWN_METHODS.get(method, "mcp_jsonrpc_request")
                events.append(self._event(
                    flow,
                    direction="request",
                    event_type="agent_behavior",
                    semantic_type=semantic,
                    value=item,
                    parse_status="success",
                    correlation={
                        "jsonrpc_id": item.get("id"),
                        "mcp_method": method,
                        "batch_index": index if len(request_items) > 1 else None,
                    },
                ))

        if flow.response_status is None and not flow.response_body and not flow.error:
            return events
        try:
            response_items = self._response_items(flow)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            events.append(make_http_event(
                flow,
                event_type="generic_traffic",
                direction="response",
                application_protocol="mcp_jsonrpc",
                semantic_type="mcp_response_parse_error",
                adapter_name=self.name,
                parse_status="failed",
                content=content_evidence(flow.response_body),
                content_type=flow.response_headers.get("content-type"),
                error={"code": "invalid_jsonrpc_response", "detail": str(exc)},
            ))
            return events
        for index, item in enumerate(response_items):
            events.append(self._event(
                flow,
                direction="response",
                event_type="generic_traffic",
                semantic_type="mcp_jsonrpc_response",
                value=item,
                parse_status="success",
                correlation={
                    "jsonrpc_id": item.get("id"),
                    "batch_index": index if len(response_items) > 1 else None,
                },
            ))
        return events

    def _response_items(self, flow: CanonicalHTTPFlow) -> list[dict[str, Any]]:
        content_type = flow.response_headers.get("content-type", "").lower()
        if not flow.response_body:
            return []
        if "text/event-stream" in content_type:
            items = []
            for event in iter_sse_events(flow.response_body):
                value = json.loads(event["data"])
                items.extend(_jsonrpc_items(value))
            if not items or not all(item.get("jsonrpc") == "2.0" for item in items):
                raise ValueError("SSE response contained no JSON-RPC 2.0 object")
            return items
        value = json.loads(flow.response_body.decode("utf-8"))
        items = _jsonrpc_items(value)
        if not items or not all(item.get("jsonrpc") == "2.0" for item in items):
            raise ValueError("JSON-RPC 2.0 response object or object array required")
        return items

    def _event(
        self,
        flow: CanonicalHTTPFlow,
        *,
        direction: str,
        event_type: str,
        semantic_type: str,
        value: Any,
        parse_status: str,
        correlation: dict[str, Any] | None = None,
    ) -> UnifiedEvent:
        content_type = (
            flow.request.headers.get("content-type")
            if direction == "request"
            else flow.response_headers.get("content-type")
        )
        return make_http_event(
            flow,
            event_type=event_type,
            direction=direction,
            application_protocol="mcp_jsonrpc",
            semantic_type=semantic_type,
            adapter_name=self.name,
            parse_status=parse_status,
            content=_bounded(value),
            content_type=content_type,
            carrier={"type": "json_rpc", "direction": direction},
            correlation=correlation,
        )
