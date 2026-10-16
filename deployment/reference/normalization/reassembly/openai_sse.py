from __future__ import annotations

import copy
import json
from typing import Any

from normalization.reassembly.anthropic_sse import iter_sse_events


def reconstruct_openai_sse(body: bytes | str) -> dict[str, Any]:
    """Reconstruct Chat Completions chunks or retain Responses API SSE items."""
    choices: dict[int, dict[str, Any]] = {}
    responses_items: list[dict[str, Any]] = []
    completed_response: dict[str, Any] | None = None
    diagnostics: list[dict[str, Any]] = []
    event_count = 0
    done = False
    try:
        events = iter_sse_events(body)
        for sequence, event in enumerate(events):
            raw = event["data"]
            if raw.strip() == "[DONE]":
                done = True
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                diagnostics.append({"code": "invalid_event_json", "sequence": sequence, "detail": str(exc)})
                continue
            if not isinstance(payload, dict):
                diagnostics.append({"code": "non_object_event", "sequence": sequence})
                continue
            event_count += 1
            event_type = payload.get("type") or event.get("event")
            if event_type == "response.completed" and isinstance(payload.get("response"), dict):
                completed_response = copy.deepcopy(payload["response"])
            elif event_type in {"response.output_item.added", "response.output_item.done"}:
                item = payload.get("item")
                if isinstance(item, dict):
                    responses_items.append(copy.deepcopy(item))

            for position, choice in enumerate(payload.get("choices", [])):
                if not isinstance(choice, dict):
                    continue
                index = choice.get("index", position)
                if not isinstance(index, int):
                    continue
                target = choices.setdefault(index, {
                    "index": index,
                    "message": {"role": "assistant", "content": "", "tool_calls": []},
                    "finish_reason": None,
                })
                delta = choice.get("delta", {})
                if not isinstance(delta, dict):
                    continue
                if isinstance(delta.get("role"), str):
                    target["message"]["role"] = delta["role"]
                if isinstance(delta.get("content"), str):
                    target["message"]["content"] += delta["content"]
                for call_position, call in enumerate(delta.get("tool_calls", [])):
                    if not isinstance(call, dict):
                        continue
                    call_index = call.get("index", call_position)
                    calls = target["message"]["tool_calls"]
                    while len(calls) <= call_index:
                        calls.append({"id": None, "type": "function", "function": {"name": "", "arguments": ""}})
                    merged = calls[call_index]
                    if isinstance(call.get("id"), str):
                        merged["id"] = call["id"]
                    function = call.get("function", {})
                    if isinstance(function, dict):
                        if isinstance(function.get("name"), str):
                            merged["function"]["name"] += function["name"]
                        if isinstance(function.get("arguments"), str):
                            merged["function"]["arguments"] += function["arguments"]
                if isinstance(choice.get("finish_reason"), str):
                    target["finish_reason"] = choice["finish_reason"]
    except UnicodeDecodeError as exc:
        diagnostics.append({"code": "invalid_utf8", "detail": str(exc)})

    if completed_response is None and responses_items:
        completed_response = {"output": responses_items}
    chat = {"choices": [choices[index] for index in sorted(choices)]} if choices else None
    complete_chat = bool(choices) and all(choice["finish_reason"] is not None for choice in choices.values())
    return {
        "schema_version": 1,
        "protocol": "openai_sse",
        "complete": (done or complete_chat or completed_response is not None) and not diagnostics,
        "chat_completion": chat,
        "response": completed_response,
        "event_count": event_count,
        "diagnostics": diagnostics,
    }
