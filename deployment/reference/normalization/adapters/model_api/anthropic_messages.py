import base64
import binascii
import json
from typing import Any

from normalization.adapters.model_api.common import ModelAPIAdapter
from normalization.core.models import AgentEgressUnit, CanonicalRequest
from normalization.core.vocabulary import make_carrier, make_protocol_locator, make_tool_context


class AnthropicMessagesAdapter(ModelAPIAdapter):
    protocol = "anthropic_messages"
    provider = "anthropic"
    api_type = "messages"
    session_header = "x-session-id"

    def matches(self, request: CanonicalRequest) -> bool:
        content_type = request.headers.get("content-type", "").lower()
        path = request.path.split("?", 1)[0].rstrip("/")
        return (
            request.method.upper() == "POST"
            and path.endswith("/v1/messages")
            and ("application/json" in content_type or not content_type)
        )

    def adapt(self, request: CanonicalRequest) -> list[AgentEgressUnit]:
        payload = json.loads(request.body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Anthropic Messages body must be a JSON object")

        model = self._optional_string(payload.get("model"))
        session_id = self.request_session_id(request)
        audit = {
            "anthropic_version": request.headers.get("anthropic-version"),
            "stream": payload.get("stream") if isinstance(payload.get("stream"), bool) else None,
        }
        units: list[AgentEgressUnit] = []
        messages = payload.get("messages", [])
        tools = payload.get("tools", [])
        tool_definitions = self._index_tool_definitions(tools)
        tool_uses = self._index_tool_uses(messages)

        self._append_content(
            units, request, model, session_id, None, None, payload.get("system"),
            "$.system", audit, tool_uses, tool_definitions, system=True,
        )

        if isinstance(messages, list):
            for message_index, message in enumerate(messages):
                message_path = f"$.messages[{message_index}]"
                if not isinstance(message, dict):
                    self._diagnostic(
                        units, request, model=model, session_id=session_id,
                        json_path=message_path, code="invalid_message",
                        observed_type=type(message).__name__, metadata=audit,
                        carrier=make_carrier("message", message_index=message_index),
                        protocol_locator=make_protocol_locator(message_path, message_index=message_index),
                    )
                    continue
                role = self._optional_string(message.get("role"))
                self._append_content(
                    units, request, model, session_id, role, message_index,
                    message.get("content"), f"{message_path}.content", audit,
                    tool_uses, tool_definitions,
                )
        elif messages is not None:
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path="$.messages", code="invalid_messages",
                observed_type=type(messages).__name__, metadata=audit,
            )

        if isinstance(tools, list):
            for tool_index, tool in enumerate(tools):
                path = f"$.tools[{tool_index}]"
                carrier = make_carrier("tool_definition", tool_definition_index=tool_index)
                locator = make_protocol_locator(
                    path, tool_index=tool_index, tool_definition_index=tool_index,
                )
                if not isinstance(tool, dict):
                    self._diagnostic(
                        units, request, model=model, session_id=session_id,
                        json_path=path, code="invalid_tool_definition",
                        observed_type=type(tool).__name__, metadata=audit,
                        carrier=carrier, protocol_locator=locator,
                    )
                    continue
                tool_name = self._optional_string(tool.get("name"))
                self._append(
                    units, request, model=model, session_id=session_id,
                    semantic_type="tool_definition", content=self._compact_json(tool),
                    carrier=carrier, protocol_locator=locator,
                    tool_context=make_tool_context(
                        tool_name=tool_name, tool_index=tool_index,
                        tool_definition_index=tool_index,
                    ),
                    media_type="application/json", metadata=audit,
                )
        elif tools is not None:
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path="$.tools", code="invalid_tools",
                observed_type=type(tools).__name__, metadata=audit,
            )
        return units

    def _append_content(
        self,
        units: list[AgentEgressUnit],
        request: CanonicalRequest,
        model: str | None,
        session_id: str | None,
        role: str | None,
        message_index: int | None,
        content: Any,
        path: str,
        audit: dict[str, Any],
        tool_uses: dict[str, dict[str, Any]],
        tool_definitions: dict[str, int],
        *,
        system: bool = False,
    ) -> None:
        if isinstance(content, str):
            semantic_type = "system_instruction" if system else "message_content"
            carrier_type = "system_instruction" if system else "message"
            self._append(
                units, request, model=model, session_id=session_id,
                semantic_type=semantic_type, content=content,
                carrier=make_carrier(carrier_type, role=role, message_index=message_index),
                protocol_locator=make_protocol_locator(path, message_index=message_index),
                metadata=audit,
            )
            return
        if content is None:
            return
        if not isinstance(content, list):
            carrier_type = "system_instruction" if system else "message"
            self._diagnostic(
                units, request, model=model, session_id=session_id, json_path=path,
                code="invalid_content", observed_type=type(content).__name__, metadata=audit,
                carrier=make_carrier(carrier_type, role=role, message_index=message_index),
                protocol_locator=make_protocol_locator(path, message_index=message_index),
            )
            return
        for block_index, block in enumerate(content):
            block_path = f"{path}[{block_index}]"
            carrier_type = "system_instruction" if system else "content_block"
            carrier = make_carrier(
                carrier_type, role=role, message_index=message_index,
                content_block_index=block_index,
            )
            locator = make_protocol_locator(
                block_path, message_index=message_index, content_block_index=block_index,
            )
            if not isinstance(block, dict):
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=block_path, code="invalid_content_block",
                    observed_type=type(block).__name__, metadata=audit,
                    carrier=carrier, protocol_locator=locator,
                )
                continue
            block_type = self._optional_string(block.get("type"))
            if block_type == "text" and isinstance(block.get("text"), str):
                semantic_type = "system_instruction" if system else "message_content"
                text_path = f"{block_path}.text"
                self._append(
                    units, request, model=model, session_id=session_id,
                    semantic_type=semantic_type, content=block["text"], carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        text_path, message_index=message_index,
                        content_block_index=block_index,
                    ),
                    metadata=audit,
                )
            elif block_type == "tool_use" and not system:
                tool_name = self._optional_string(block.get("name"))
                tool_call_id = self._optional_string(block.get("id"))
                context = make_tool_context(
                    tool_call_id=tool_call_id, tool_name=tool_name,
                    tool_index=tool_definitions.get(tool_name) if tool_name else None,
                    tool_definition_index=tool_definitions.get(tool_name) if tool_name else None,
                    tool_call_message_index=message_index,
                    tool_call_content_block_index=block_index,
                )
                for leaf_json_path, leaf_path, text in self._iter_string_leaves(
                    block.get("input"), f"{block_path}.input"
                ):
                    self._append(
                        units, request, model=model, session_id=session_id,
                        semantic_type="tool_arguments", content=text, carrier=carrier,
                        protocol_locator=make_protocol_locator(
                            leaf_json_path, message_index=message_index,
                            content_block_index=block_index, leaf_path=leaf_path,
                        ),
                        tool_context=context, metadata=audit,
                    )
            elif block_type == "tool_result" and not system:
                self._append_tool_result(
                    units, request, model, session_id, role, message_index,
                    block_index, block, block_path, carrier, audit,
                    tool_uses, tool_definitions,
                )
            elif block_type in {"image", "document"}:
                self._append_source(
                    units, request, model, session_id, block, block_path,
                    message_index, block_index, carrier, audit,
                )
            elif block_type in {"thinking", "redacted_thinking"}:
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=block_path, code="non_detected_reasoning_block",
                    observed_type=block_type, metadata=audit,
                    carrier=carrier, protocol_locator=locator,
                )
            else:
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=block_path, code="unknown_content_block",
                    observed_type=block_type or "missing", metadata=audit,
                    carrier=carrier, protocol_locator=locator,
                )

    def _append_tool_result(
        self, units, request, model, session_id, role, message_index, block_index,
        block, path, carrier, audit, tool_uses, tool_definitions,
    ):
        result = block.get("content")
        tool_call_id = self._optional_string(block.get("tool_use_id"))
        linked = tool_uses.get(tool_call_id, {}) if tool_call_id else {}
        tool_name = linked.get("tool_name")
        context = make_tool_context(
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            tool_index=tool_definitions.get(tool_name) if tool_name else None,
            tool_definition_index=tool_definitions.get(tool_name) if tool_name else None,
            tool_call_message_index=linked.get("message_index"),
            tool_call_content_block_index=linked.get("content_block_index"),
        )
        if isinstance(result, str):
            result_path = f"{path}.content"
            self._append(
                units, request, model=model, session_id=session_id,
                semantic_type="tool_result", content=result, carrier=carrier,
                protocol_locator=make_protocol_locator(
                    result_path, message_index=message_index,
                    content_block_index=block_index,
                ),
                tool_context=context, metadata=audit,
            )
        elif isinstance(result, list):
            for result_index, child in enumerate(result):
                child_path = f"{path}.content[{result_index}]"
                if isinstance(child, dict) and child.get("type") == "text" and isinstance(child.get("text"), str):
                    text_path = f"{child_path}.text"
                    self._append(
                        units, request, model=model, session_id=session_id,
                        semantic_type="tool_result", content=child["text"], carrier=carrier,
                        protocol_locator=make_protocol_locator(
                            text_path, message_index=message_index,
                            content_block_index=block_index,
                            leaf_path=[result_index, "text"],
                            result_content_index=result_index,
                        ),
                        tool_context=context, metadata=audit,
                    )
                else:
                    self._diagnostic(
                        units, request, model=model, session_id=session_id,
                        json_path=child_path, code="unsupported_tool_result_block",
                        observed_type=type(child).__name__, metadata=audit,
                        carrier=carrier,
                        protocol_locator=make_protocol_locator(
                            child_path, message_index=message_index,
                            content_block_index=block_index,
                            result_content_index=result_index,
                        ),
                    )
        else:
            result_path = f"{path}.content"
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path=result_path, code="invalid_tool_result",
                observed_type=type(result).__name__, metadata=audit,
                carrier=carrier,
                protocol_locator=make_protocol_locator(
                    result_path, message_index=message_index,
                    content_block_index=block_index,
                ),
            )

    def _append_source(
        self, units, request, model, session_id, block, path,
        message_index, block_index, carrier, audit,
    ):
        source = block.get("source")
        source_path = f"{path}.source"
        if not isinstance(source, dict):
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path=source_path, code="invalid_inline_source",
                observed_type=type(source).__name__, metadata=audit,
                carrier=carrier,
                protocol_locator=make_protocol_locator(
                    source_path, message_index=message_index,
                    content_block_index=block_index,
                ),
            )
            return
        media_type = self._optional_string(source.get("media_type"))
        source_type = self._optional_string(source.get("type"))
        if source_type == "base64" and media_type and media_type.startswith("text/") and isinstance(source.get("data"), str):
            data_path = f"{source_path}.data"
            try:
                text = base64.b64decode(source["data"], validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=data_path, code="invalid_text_inline_data",
                    observed_type=media_type, metadata=audit, carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        data_path, message_index=message_index,
                        content_block_index=block_index,
                    ),
                )
            else:
                self._append(
                    units, request, model=model, session_id=session_id,
                    semantic_type="inline_text", content=text, carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        data_path, message_index=message_index,
                        content_block_index=block_index,
                    ),
                    media_type=media_type,
                    metadata={**audit, "decoded_from": "base64"},
                )
        elif source_type in {"url", "file"}:
            field = "url" if isinstance(source.get("url"), str) else "file_id"
            reference = source.get(field)
            if isinstance(reference, str):
                reference_path = f"{source_path}.{field}"
                self._append(
                    units, request, model=model, session_id=session_id,
                    semantic_type="file_reference", content=reference, carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        reference_path, message_index=message_index,
                        content_block_index=block_index,
                    ),
                    media_type="text/uri-list", metadata=audit,
                )
        else:
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path=source_path, code="unsupported_inline_data",
                observed_type=media_type or source_type, metadata=audit,
                carrier=carrier,
                protocol_locator=make_protocol_locator(
                    source_path, message_index=message_index,
                    content_block_index=block_index,
                ),
            )

    def _index_tool_definitions(self, tools: Any) -> dict[str, int]:
        result = {}
        if not isinstance(tools, list):
            return result
        for index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                continue
            name = self._optional_string(tool.get("name"))
            if name is not None and name not in result:
                result[name] = index
        return result

    def _index_tool_uses(self, messages: Any) -> dict[str, dict[str, Any]]:
        result = {}
        if not isinstance(messages, list):
            return result
        for message_index, message in enumerate(messages):
            if not isinstance(message, dict) or not isinstance(message.get("content"), list):
                continue
            for block_index, block in enumerate(message["content"]):
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                tool_call_id = self._optional_string(block.get("id"))
                if tool_call_id is not None and tool_call_id not in result:
                    result[tool_call_id] = {
                        "tool_name": self._optional_string(block.get("name")),
                        "message_index": message_index,
                        "content_block_index": block_index,
                    }
        return result
