"""Central vocabulary and structured-field builders for AEU schema v2."""

from typing import Any


SCHEMA_VERSION = 2
ADAPTER_VERSION = 2

SEMANTIC_TYPES = frozenset({
    "system_instruction",
    "message_content",
    "tool_arguments",
    "tool_result",
    "tool_definition",
    "inline_text",
    "file_reference",
    "adapter_diagnostic",
})

CARRIER_TYPES = frozenset({
    "system_instruction",
    "message",
    "content_block",
    "part",
    "tool_definition",
    "request_diagnostic",
})

CARRIER_DIRECTIONS = frozenset({"request", "response"})

MODEL_API_TYPES = frozenset({
    "chat_completions",
    "messages",
    "generate_content",
    "stream_generate_content",
})

MODEL_API_PROVIDERS = frozenset({"openai", "anthropic", "google_gemini"})


def make_carrier(
    carrier_type: str,
    *,
    direction: str = "request",
    role: str | None = None,
    message_index: int | None = None,
    content_block_index: int | None = None,
    part_index: int | None = None,
    tool_definition_index: int | None = None,
    tool_call_index: int | None = None,
) -> dict[str, Any]:
    if carrier_type not in CARRIER_TYPES:
        raise ValueError(f"Unknown AEU carrier type: {carrier_type}")
    if direction not in CARRIER_DIRECTIONS:
        raise ValueError(f"Unknown AEU carrier direction: {direction}")
    return {
        "type": carrier_type,
        "direction": direction,
        "role": role,
        "message_index": message_index,
        "content_block_index": content_block_index,
        "part_index": part_index,
        "tool_definition_index": tool_definition_index,
        "tool_call_index": tool_call_index,
    }


def make_protocol_locator(
    json_path: str,
    *,
    message_index: int | None = None,
    content_block_index: int | None = None,
    part_index: int | None = None,
    tool_index: int | None = None,
    tool_definition_index: int | None = None,
    tool_call_index: int | None = None,
    leaf_path: list[str | int] | None = None,
    **protocol_fields: Any,
) -> dict[str, Any]:
    locator = {
        "json_path": json_path,
        "message_index": message_index,
        "content_block_index": content_block_index,
        "part_index": part_index,
        "tool_index": tool_index,
        "tool_definition_index": tool_definition_index,
        "tool_call_index": tool_call_index,
        "leaf_path": leaf_path,
    }
    locator.update(protocol_fields)
    return locator


def make_tool_context(
    *,
    tool_call_id: str | None = None,
    tool_name: str | None = None,
    tool_index: int | None = None,
    tool_definition_index: int | None = None,
    tool_call_message_index: int | None = None,
    tool_call_content_block_index: int | None = None,
    tool_call_part_index: int | None = None,
    tool_call_index: int | None = None,
) -> dict[str, Any]:
    return {
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "tool_index": tool_index,
        "tool_definition_index": tool_definition_index,
        "tool_call_message_index": tool_call_message_index,
        "tool_call_content_block_index": tool_call_content_block_index,
        "tool_call_part_index": tool_call_part_index,
        "tool_call_index": tool_call_index,
    }
