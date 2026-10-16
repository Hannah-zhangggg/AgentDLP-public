from __future__ import annotations

import json
import re
from email import policy
from email.parser import BytesParser
from typing import Any
from urllib.parse import parse_qsl

from normalization.core.event_schema import content_evidence, make_http_event
from normalization.core.models import CanonicalHTTPFlow, UnifiedEvent


SENSITIVE_FIELD = re.compile(r"(?:token|secret|password|passwd|api[_-]?key|authorization|cookie)", re.I)


def _bounded_text(value: str, limit: int = 1024) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", errors="ignore")


def sanitize_structured(value: Any, *, depth: int = 0) -> Any:
    if depth > 5:
        return "[DEPTH_LIMIT]"
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SENSITIVE_FIELD.search(str(key)) else sanitize_structured(child, depth=depth + 1)
            for key, child in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [sanitize_structured(child, depth=depth + 1) for child in value[:100]]
    if isinstance(value, str):
        return _bounded_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(type(value).__name__)


def summarize_http_body(
    body: bytes,
    content_type: str | None,
) -> tuple[dict[str, Any], str, str, dict[str, Any] | None]:
    """Return evidence, parse status, body semantic, and optional error."""
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if not body:
        return content_evidence(body), "success", "empty_body", None

    if media_type == "application/json" or media_type.endswith("+json"):
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            preview = body[:1024].decode("utf-8", errors="replace")
            return (
                content_evidence(body, preview=preview),
                "partial",
                "json_body",
                {"code": "invalid_json", "detail": str(exc)},
            )
        return content_evidence(body, structured=sanitize_structured(value)), "success", "json_body", None

    if media_type == "application/x-www-form-urlencoded":
        try:
            fields = parse_qsl(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False)
        except UnicodeDecodeError as exc:
            return content_evidence(body), "partial", "form_submission", {
                "code": "invalid_form_encoding", "detail": str(exc),
            }
        structured = {
            name: "[REDACTED]" if SENSITIVE_FIELD.search(name) else _bounded_text(value)
            for name, value in fields[:100]
        }
        return content_evidence(body, structured=structured), "success", "form_submission", None

    if media_type == "multipart/form-data":
        try:
            message = BytesParser(policy=policy.default).parsebytes(
                f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
            )
            parts = []
            for part in message.iter_parts():
                payload = part.get_payload(decode=True) or b""
                name = part.get_param("name", header="content-disposition")
                filename = part.get_filename()
                item = {
                    "name": name,
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "byte_length": len(payload),
                    "sha256": content_evidence(payload)["sha256"],
                }
                if filename is None and part.get_content_maintype() == "text":
                    item["preview"] = "[REDACTED]" if name and SENSITIVE_FIELD.search(name) else _bounded_text(
                        payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    )
                parts.append(item)
        except Exception as exc:  # malformed MIME must stay visible as a generic event
            return content_evidence(body), "partial", "multipart_upload", {
                "code": "invalid_multipart", "detail": f"{type(exc).__name__}: {exc}",
            }
        semantic = "file_upload" if any(part.get("filename") for part in parts) else "form_submission"
        return content_evidence(body, structured={"parts": parts}), "success", semantic, None

    textual = media_type.startswith("text/") or media_type in {
        "application/xml", "application/graphql", "application/javascript",
    }
    if textual:
        try:
            preview = body.decode("utf-8")
            status = "success"
            error = None
        except UnicodeDecodeError as exc:
            preview = body.decode("utf-8", errors="replace")
            status = "partial"
            error = {"code": "invalid_text_encoding", "detail": str(exc)}
        return content_evidence(body, preview=preview), status, "text_body", error

    if not media_type:
        try:
            preview = body.decode("utf-8")
        except UnicodeDecodeError:
            return content_evidence(body), "unsupported", "unknown_binary_body", {
                "code": "missing_content_type_binary_body",
            }
        return content_evidence(body, preview=preview), "partial", "unknown_text_body", {
            "code": "missing_content_type",
        }

    return content_evidence(body), "unsupported", "binary_body", {
        "code": "unsupported_media_type", "media_type": media_type,
    }


class GenericHTTPAdapter:
    name = "generic_http"

    def matches(self, flow: CanonicalHTTPFlow) -> bool:
        return True

    def adapt(self, flow: CanonicalHTTPFlow) -> list[UnifiedEvent]:
        request_type = flow.request.headers.get("content-type")
        request_content, request_status, body_semantic, request_error = summarize_http_body(
            flow.request.body, request_type
        )
        semantic = "http_request" if body_semantic == "empty_body" else body_semantic
        request_event_type = "generic_traffic" if request_status == "unsupported" else "agent_behavior"
        events = [make_http_event(
            flow,
            event_type=request_event_type,
            direction="request",
            application_protocol="http",
            semantic_type=semantic,
            adapter_name=self.name,
            parse_status=request_status,
            content=request_content,
            content_type=request_type,
            error=request_error,
        )]
        if flow.response_status is not None or flow.response_body or flow.error:
            response_type = flow.response_headers.get("content-type")
            response_content, response_status, response_semantic, response_error = summarize_http_body(
                flow.response_body, response_type
            )
            if flow.error:
                response_status = "failed"
                response_error = {"code": "flow_error", "detail": flow.error}
            events.append(make_http_event(
                flow,
                event_type="generic_traffic",
                direction="response",
                application_protocol="http",
                semantic_type="http_response" if response_semantic == "empty_body" else response_semantic,
                adapter_name=self.name,
                parse_status=response_status,
                content=response_content,
                content_type=response_type,
                error=response_error,
            ))
        return events

    def adapt_error(
        self,
        flow: CanonicalHTTPFlow,
        failed_adapter: str,
        exc: Exception,
    ) -> list[UnifiedEvent]:
        return [make_http_event(
            flow,
            event_type="generic_traffic",
            direction="request",
            application_protocol="http",
            semantic_type="adapter_fallback",
            adapter_name=self.name,
            parse_status="failed",
            content=content_evidence(flow.request.body),
            content_type=flow.request.headers.get("content-type"),
            correlation={"failed_adapter": failed_adapter},
            error={
                "code": "adapter_exception",
                "adapter": failed_adapter,
                "exception_type": type(exc).__name__,
                "detail": _bounded_text(str(exc), 512),
            },
        )]
