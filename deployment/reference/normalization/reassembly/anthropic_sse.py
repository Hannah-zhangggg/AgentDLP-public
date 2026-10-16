from __future__ import annotations

import copy
import json
from typing import Any, Iterator


def iter_sse_events(body: bytes | str) -> Iterator[dict[str, str]]:
    """Parse an SSE body, including CRLF and multi-line data fields."""
    if isinstance(body, bytes):
        text = body.decode("utf-8")
    else:
        text = body
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    event_name = "message"
    data_lines: list[str] = []

    def finish():
        nonlocal event_name, data_lines
        if not data_lines:
            event_name = "message"
            return None
        event = {"event": event_name, "data": "\n".join(data_lines)}
        event_name = "message"
        data_lines = []
        return event

    for line in text.split("\n"):
        if line == "":
            event = finish()
            if event is not None:
                yield event
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "event":
            event_name = value
        elif field == "data":
            data_lines.append(value)
    event = finish()
    if event is not None:
        yield event


class AnthropicSSEReconstructor:
    """Reconstruct one Anthropic streaming Message response from SSE events."""

    def __init__(self) -> None:
        self.message: dict[str, Any] | None = None
        self.blocks: dict[int, dict[str, Any]] = {}
        self.partial_json: dict[int, str] = {}
        self.complete = False
        self.errors: list[dict[str, Any]] = []
        self.diagnostics: list[dict[str, Any]] = []
        self.event_counts: dict[str, int] = {}

    def diagnostic(self, code: str, **details: Any) -> None:
        self.diagnostics.append({"code": code, **details})

    def consume(self, event_name: str, payload: dict[str, Any]) -> None:
        payload_type = payload.get("type")
        actual_name = payload_type if isinstance(payload_type, str) else event_name
        if event_name not in {"message", actual_name}:
            self.diagnostic(
                "event_type_mismatch",
                event_name=event_name,
                payload_type=payload_type,
            )
        self.event_counts[actual_name] = self.event_counts.get(actual_name, 0) + 1

        if actual_name == "message_start":
            message = payload.get("message")
            if not isinstance(message, dict):
                self.diagnostic("invalid_message_start")
                return
            self.message = copy.deepcopy(message)
            initial_content = self.message.pop("content", [])
            if isinstance(initial_content, list):
                for index, block in enumerate(initial_content):
                    if isinstance(block, dict):
                        self.blocks[index] = copy.deepcopy(block)
            return

        if actual_name == "content_block_start":
            index = payload.get("index")
            block = payload.get("content_block")
            if not isinstance(index, int) or not isinstance(block, dict):
                self.diagnostic("invalid_content_block_start", index=index)
                return
            if index in self.blocks:
                self.diagnostic("duplicate_content_block_start", index=index)
            self.blocks[index] = copy.deepcopy(block)
            if block.get("type") in {"tool_use", "server_tool_use"}:
                self.partial_json[index] = ""
            return

        if actual_name == "content_block_delta":
            self._consume_delta(payload)
            return

        if actual_name == "content_block_stop":
            index = payload.get("index")
            if not isinstance(index, int) or index not in self.blocks:
                self.diagnostic("content_block_stop_without_start", index=index)
                return
            if index in self.partial_json:
                raw_input = self.partial_json.pop(index)
                try:
                    parsed_input = json.loads(raw_input) if raw_input else {}
                except json.JSONDecodeError as error:
                    self.blocks[index]["input_json"] = raw_input
                    self.diagnostic(
                        "invalid_tool_input_json",
                        index=index,
                        error=str(error),
                    )
                else:
                    self.blocks[index]["input"] = parsed_input
            return

        if actual_name == "message_delta":
            if self.message is None:
                self.diagnostic("message_delta_before_start")
                return
            delta = payload.get("delta")
            if isinstance(delta, dict):
                self.message.update(copy.deepcopy(delta))
            else:
                self.diagnostic("invalid_message_delta")
            usage = payload.get("usage")
            if isinstance(usage, dict):
                current_usage = self.message.setdefault("usage", {})
                if isinstance(current_usage, dict):
                    current_usage.update(copy.deepcopy(usage))
                else:
                    self.message["usage"] = copy.deepcopy(usage)
            return

        if actual_name == "message_stop":
            self.complete = True
            return

        if actual_name == "error":
            error = payload.get("error")
            self.errors.append(copy.deepcopy(error) if isinstance(error, dict) else copy.deepcopy(payload))
            return

        if actual_name == "ping":
            return

        self.diagnostic("unknown_event", event_name=actual_name, payload=copy.deepcopy(payload))

    def _consume_delta(self, payload: dict[str, Any]) -> None:
        index = payload.get("index")
        delta = payload.get("delta")
        if not isinstance(index, int) or index not in self.blocks or not isinstance(delta, dict):
            self.diagnostic("invalid_content_block_delta", index=index)
            return
        block = self.blocks[index]
        delta_type = delta.get("type")
        if delta_type == "text_delta" and isinstance(delta.get("text"), str):
            block["text"] = str(block.get("text", "")) + delta["text"]
        elif delta_type == "input_json_delta" and isinstance(delta.get("partial_json"), str):
            self.partial_json[index] = self.partial_json.get(index, "") + delta["partial_json"]
        elif delta_type == "thinking_delta" and isinstance(delta.get("thinking"), str):
            block["thinking"] = str(block.get("thinking", "")) + delta["thinking"]
        elif delta_type == "signature_delta" and isinstance(delta.get("signature"), str):
            block["signature"] = str(block.get("signature", "")) + delta["signature"]
        elif delta_type == "citations_delta" and isinstance(delta.get("citation"), dict):
            citations = block.setdefault("citations", [])
            if isinstance(citations, list):
                citations.append(copy.deepcopy(delta["citation"]))
        else:
            self.diagnostic(
                "unknown_content_block_delta",
                index=index,
                delta=copy.deepcopy(delta),
            )

    def result(self) -> dict[str, Any]:
        message = copy.deepcopy(self.message)
        if message is not None:
            message["content"] = [copy.deepcopy(self.blocks[index]) for index in sorted(self.blocks)]
        return {
            "schema_version": 1,
            "protocol": "anthropic_messages_sse",
            "complete": self.complete,
            "message": message,
            "errors": copy.deepcopy(self.errors),
            "diagnostics": copy.deepcopy(self.diagnostics),
            "event_counts": dict(sorted(self.event_counts.items())),
        }


def reconstruct_anthropic_sse(body: bytes | str) -> dict[str, Any]:
    reconstructor = AnthropicSSEReconstructor()
    try:
        events = iter_sse_events(body)
        for sequence, event in enumerate(events):
            try:
                payload = json.loads(event["data"])
            except json.JSONDecodeError as error:
                reconstructor.diagnostic("invalid_event_json", sequence=sequence, error=str(error))
                continue
            if not isinstance(payload, dict):
                reconstructor.diagnostic(
                    "non_object_event_payload",
                    sequence=sequence,
                    observed_type=type(payload).__name__,
                )
                continue
            reconstructor.consume(event["event"], payload)
    except UnicodeDecodeError as error:
        reconstructor.diagnostic("invalid_utf8", error=str(error))
    return reconstructor.result()
