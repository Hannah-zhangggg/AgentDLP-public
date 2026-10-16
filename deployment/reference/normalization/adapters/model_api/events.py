from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from normalization.adapters.generic.http import sanitize_structured, summarize_http_body
from normalization.core.event_schema import content_evidence, make_http_event
from normalization.core.models import CanonicalHTTPFlow, UnifiedEvent
from normalization.core.registry import AdapterRegistry
from normalization.reassembly.anthropic_sse import reconstruct_anthropic_sse
from normalization.reassembly.gemini_sse import reconstruct_gemini_sse
from normalization.reassembly.openai_sse import reconstruct_openai_sse


def _bounded_json(value: Any, limit: int = 4096) -> tuple[dict[str, Any], bytes]:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    safe_value = sanitize_structured(value)
    safe_raw = json.dumps(safe_value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    preview = safe_raw[:limit].decode("utf-8", errors="ignore")
    return content_evidence(
        raw,
        preview=preview,
        structured=safe_value if len(safe_raw) <= limit else None,
        limit=limit,
    ), raw


class ModelAPIEventAdapter:
    name = "model_api_events"

    def __init__(self) -> None:
        self.request_registry = AdapterRegistry()

    def matches(self, flow: CanonicalHTTPFlow) -> bool:
        if self.request_registry.select(flow.request) is not None:
            return True
        path = urlsplit(flow.request.path).path.rstrip("/")
        return (
            flow.request.method.upper() == "POST"
            and path.endswith("/v1/responses")
            and "json" in flow.request.headers.get("content-type", "application/json").lower()
        )

    def _protocol(self, flow: CanonicalHTTPFlow) -> str:
        path = urlsplit(flow.request.path).path.rstrip("/")
        if path.endswith("/chat/completions"):
            return "openai_chat_completions"
        if path.endswith("/v1/responses"):
            return "openai_responses"
        if path.endswith("/v1/messages"):
            return "anthropic_messages"
        return "gemini_generate_content"

    def adapt(self, flow: CanonicalHTTPFlow) -> list[UnifiedEvent]:
        protocol = self._protocol(flow)
        request_content, request_status, _, request_error = summarize_http_body(
            flow.request.body, flow.request.headers.get("content-type")
        )
        events = [make_http_event(
            flow,
            event_type="agent_behavior",
            direction="request",
            application_protocol=protocol,
            semantic_type="model_api_request",
            adapter_name=self.name,
            parse_status=request_status,
            content=request_content,
            content_type=flow.request.headers.get("content-type"),
            carrier={"type": "model_api", "direction": "request", "protocol": protocol},
            error=request_error,
        )]
        if flow.response_status is None and not flow.response_body and not flow.error:
            return events
        try:
            response = self._response_object(flow, protocol)
            instructions = list(self._instruction_items(protocol, response))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            events.append(make_http_event(
                flow,
                event_type="generic_traffic",
                direction="response",
                application_protocol=protocol,
                semantic_type="provider_response_parse_error",
                adapter_name=self.name,
                parse_status="failed",
                content=content_evidence(flow.response_body),
                content_type=flow.response_headers.get("content-type"),
                carrier={"type": "model_api", "direction": "response", "protocol": protocol},
                error={"code": "invalid_provider_response", "detail": f"{type(exc).__name__}: {exc}"},
            ))
            return events
        if not instructions:
            events.append(make_http_event(
                flow,
                event_type="generic_traffic",
                direction="response",
                application_protocol=protocol,
                semantic_type="provider_response_without_instruction",
                adapter_name=self.name,
                parse_status="partial",
                content=content_evidence(flow.response_body),
                content_type=flow.response_headers.get("content-type"),
                carrier={"type": "model_api", "direction": "response", "protocol": protocol},
                error={"code": "no_supported_instruction_field"},
            ))
            return events
        for index, item in enumerate(instructions):
            content, _ = _bounded_json(item["value"])
            events.append(make_http_event(
                flow,
                event_type="provider_instruction",
                direction="response",
                application_protocol=protocol,
                semantic_type=item["semantic_type"],
                adapter_name=self.name,
                parse_status="success",
                content=content,
                content_type=flow.response_headers.get("content-type"),
                carrier={
                    "type": item["carrier"],
                    "direction": "response",
                    "protocol": protocol,
                    "index": index,
                    "locator": item.get("locator"),
                },
                correlation={
                    "tool_call_id": item.get("tool_call_id"),
                    "tool_name": item.get("tool_name"),
                    "instruction_certainty": item.get("certainty", "high"),
                },
            ))
        return events

    def _response_object(self, flow: CanonicalHTTPFlow, protocol: str) -> dict[str, Any]:
        content_type = flow.response_headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            if protocol == "anthropic_messages":
                result = reconstruct_anthropic_sse(flow.response_body)
                if result["message"] is None:
                    raise ValueError(f"Anthropic SSE incomplete: {result['diagnostics']}")
                return result["message"]
            if protocol == "gemini_generate_content":
                result = reconstruct_gemini_sse(flow.response_body)
                if not result["response"]:
                    raise ValueError(f"Gemini SSE incomplete: {result['diagnostics']}")
                return result["response"]
            result = reconstruct_openai_sse(flow.response_body)
            response = result["response"] if protocol == "openai_responses" else result["chat_completion"]
            if response is None:
                raise ValueError(f"OpenAI SSE incomplete: {result['diagnostics']}")
            return response
        value = json.loads(flow.response_body.decode("utf-8") or "{}")
        if not isinstance(value, dict):
            raise ValueError("Provider response must be a JSON object")
        return value

    def _instruction_items(self, protocol: str, response: dict[str, Any]):
        if protocol == "anthropic_messages":
            for index, block in enumerate(response.get("content", [])):
                if not isinstance(block, dict):
                    continue
                if block.get("type") in {"tool_use", "server_tool_use"}:
                    yield {
                        "semantic_type": "tool_call_instruction",
                        "carrier": "content_block",
                        "locator": f"$.content[{index}]",
                        "tool_call_id": block.get("id"),
                        "tool_name": block.get("name"),
                        "value": {"name": block.get("name"), "arguments": block.get("input", {})},
                    }
                elif block.get("type") == "text" and isinstance(block.get("text"), str):
                    yield self._text_item(block["text"], "content_block", f"$.content[{index}].text")
            return

        if protocol == "gemini_generate_content":
            for candidate_index, candidate in enumerate(response.get("candidates", [])):
                if not isinstance(candidate, dict):
                    continue
                content = candidate.get("content", {})
                for part_index, part in enumerate(content.get("parts", []) if isinstance(content, dict) else []):
                    if not isinstance(part, dict):
                        continue
                    call = part.get("functionCall")
                    locator = f"$.candidates[{candidate_index}].content.parts[{part_index}]"
                    if isinstance(call, dict):
                        yield {
                            "semantic_type": "tool_call_instruction",
                            "carrier": "part",
                            "locator": locator + ".functionCall",
                            "tool_call_id": call.get("id"),
                            "tool_name": call.get("name"),
                            "value": {"name": call.get("name"), "arguments": call.get("args", {})},
                        }
                    elif isinstance(part.get("text"), str):
                        yield self._text_item(part["text"], "part", locator + ".text")
            return

        if protocol == "openai_responses":
            for index, item in enumerate(response.get("output", [])):
                if not isinstance(item, dict):
                    continue
                if item.get("type") in {"function_call", "computer_call", "custom_tool_call"}:
                    yield {
                        "semantic_type": "tool_call_instruction",
                        "carrier": "output_item",
                        "locator": f"$.output[{index}]",
                        "tool_call_id": item.get("call_id") or item.get("id"),
                        "tool_name": item.get("name") or item.get("type"),
                        "value": {"name": item.get("name"), "arguments": item.get("arguments", {})},
                    }
                for content_index, part in enumerate(item.get("content", [])):
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        yield self._text_item(
                            part["text"], "output_item",
                            f"$.output[{index}].content[{content_index}].text",
                        )
            return

        for choice_index, choice in enumerate(response.get("choices", [])):
            if not isinstance(choice, dict):
                continue
            message = choice.get("message", {})
            if not isinstance(message, dict):
                continue
            for call_index, call in enumerate(message.get("tool_calls", [])):
                if not isinstance(call, dict):
                    continue
                function = call.get("function", {})
                arguments: Any = function.get("arguments", {}) if isinstance(function, dict) else {}
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except json.JSONDecodeError:
                        pass
                yield {
                    "semantic_type": "tool_call_instruction",
                    "carrier": "message",
                    "locator": f"$.choices[{choice_index}].message.tool_calls[{call_index}]",
                    "tool_call_id": call.get("id"),
                    "tool_name": function.get("name") if isinstance(function, dict) else None,
                    "value": {"name": function.get("name"), "arguments": arguments},
                }
            if isinstance(message.get("content"), str) and message["content"]:
                yield self._text_item(
                    message["content"], "message", f"$.choices[{choice_index}].message.content"
                )

    @staticmethod
    def _text_item(text: str, carrier: str, locator: str) -> dict[str, Any]:
        return {
            "semantic_type": "provider_text_response",
            "carrier": carrier,
            "locator": locator,
            "value": {"text": text},
            "certainty": "low",
        }
