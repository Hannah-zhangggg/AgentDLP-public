import json
from typing import Any

from normalization.adapters.model_api.common import ModelAPIAdapter
from normalization.core.models import AgentEgressUnit, CanonicalRequest
from normalization.core.vocabulary import make_carrier, make_protocol_locator, make_tool_context


class OpenAIChatAdapter(ModelAPIAdapter):
    protocol = "openai_chat_completions"
    provider = "openai"
    api_type = "chat_completions"
    session_header = "x-session-affinity"

    def matches(self, request: CanonicalRequest) -> bool:
        content_type = request.headers.get("content-type", "").lower()
        return (
            request.method.upper() == "POST"
            and request.path.split("?", 1)[0].endswith("/chat/completions")
            and ("application/json" in content_type or not content_type)
        )

    def adapt(self, request: CanonicalRequest) -> list[AgentEgressUnit]:
        payload = json.loads(request.body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("OpenAI Chat Completions body must be a JSON object")

        model = self._optional_string(payload.get("model"))
        session_id = self.request_session_id(request)
        units: list[AgentEgressUnit] = []
        messages = payload.get("messages", [])
        tools = payload.get("tools", [])
        tool_definitions = self._index_tool_definitions(tools)
        tool_calls = self._index_tool_calls(messages)

        if isinstance(messages, list):
            for message_index, message in enumerate(messages):
                message_path = f"$.messages[{message_index}]"
                if not isinstance(message, dict):
                    self._diagnostic(
                        units, request, model=model, session_id=session_id,
                        json_path=message_path, code="invalid_message",
                        observed_type=type(message).__name__,
                        carrier=make_carrier("message", message_index=message_index),
                        protocol_locator=make_protocol_locator(message_path, message_index=message_index),
                    )
                    continue
                role = self._optional_string(message.get("role"))
                self._append_message_content(
                    units, request, model, session_id, role, message_index, message, tool_calls,
                    tool_definitions,
                )
                self._append_tool_calls(
                    units, request, model, session_id, role, message_index,
                    message.get("tool_calls"), tool_definitions,
                )
        elif messages is not None:
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path="$.messages", code="invalid_messages",
                observed_type=type(messages).__name__,
            )

        if isinstance(tools, list):
            for tool_index, tool in enumerate(tools):
                tool_path = f"$.tools[{tool_index}]"
                if not isinstance(tool, dict):
                    self._diagnostic(
                        units, request, model=model, session_id=session_id,
                        json_path=tool_path, code="invalid_tool_definition",
                        observed_type=type(tool).__name__,
                        carrier=make_carrier("tool_definition", tool_definition_index=tool_index),
                        protocol_locator=make_protocol_locator(
                            tool_path, tool_index=tool_index, tool_definition_index=tool_index,
                        ),
                    )
                    continue
                function = tool.get("function") if isinstance(tool.get("function"), dict) else {}
                tool_name = self._optional_string(function.get("name"))
                self._append(
                    units, request, model=model, session_id=session_id,
                    semantic_type="tool_definition", content=self._compact_json(tool),
                    carrier=make_carrier("tool_definition", tool_definition_index=tool_index),
                    protocol_locator=make_protocol_locator(
                        tool_path, tool_index=tool_index, tool_definition_index=tool_index,
                    ),
                    tool_context=make_tool_context(
                        tool_name=tool_name, tool_index=tool_index,
                        tool_definition_index=tool_index,
                    ),
                    media_type="application/json",
                )
        elif tools is not None:
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path="$.tools", code="invalid_tools",
                observed_type=type(tools).__name__,
            )

        return units

    def _append_message_content(
        self,
        units: list[AgentEgressUnit],
        request: CanonicalRequest,
        model: str | None,
        session_id: str | None,
        role: str | None,
        message_index: int,
        message: dict[str, Any],
        tool_calls: dict[str, dict[str, Any]],
        tool_definitions: dict[str, int],
    ) -> None:
        content = message.get("content")
        if content is None:
            return
        semantic_type = self._message_semantic_type(role)
        result_context = self._tool_result_context(message, tool_calls, tool_definitions)
        if isinstance(content, str):
            path = f"$.messages[{message_index}].content"
            self._append(
                units, request, model=model, session_id=session_id,
                semantic_type=semantic_type, content=content,
                carrier=make_carrier("message", role=role, message_index=message_index),
                protocol_locator=make_protocol_locator(path, message_index=message_index),
                tool_context=result_context,
            )
            return
        if not isinstance(content, list):
            path = f"$.messages[{message_index}].content"
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path=path, code="invalid_content",
                observed_type=type(content).__name__,
                carrier=make_carrier("message", role=role, message_index=message_index),
                protocol_locator=make_protocol_locator(path, message_index=message_index),
            )
            return
        for block_index, part in enumerate(content):
            part_path = f"$.messages[{message_index}].content[{block_index}]"
            carrier = make_carrier(
                "message", role=role, message_index=message_index,
                content_block_index=block_index,
            )
            if not isinstance(part, dict):
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=part_path, code="invalid_content_block",
                    observed_type=type(part).__name__, carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        part_path, message_index=message_index,
                        content_block_index=block_index,
                    ),
                )
                continue
            if isinstance(part.get("text"), str):
                text, field = part["text"], "text"
            elif isinstance(part.get("content"), str):
                text, field = part["content"], "content"
            else:
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=part_path, code="unknown_content_block",
                    observed_type=self._optional_string(part.get("type")) or next(iter(part), "empty"),
                    carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        part_path, message_index=message_index,
                        content_block_index=block_index,
                    ),
                )
                continue
            path = f"{part_path}.{field}"
            self._append(
                units, request, model=model, session_id=session_id,
                semantic_type=semantic_type, content=text, carrier=carrier,
                protocol_locator=make_protocol_locator(
                    path, message_index=message_index, content_block_index=block_index,
                ),
                tool_context=result_context,
            )

    def _append_tool_calls(
        self,
        units: list[AgentEgressUnit],
        request: CanonicalRequest,
        model: str | None,
        session_id: str | None,
        role: str | None,
        message_index: int,
        tool_calls: Any,
        tool_definitions: dict[str, int],
    ) -> None:
        if tool_calls is None:
            return
        if not isinstance(tool_calls, list):
            path = f"$.messages[{message_index}].tool_calls"
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path=path, code="invalid_tool_calls",
                observed_type=type(tool_calls).__name__,
                carrier=make_carrier("message", role=role, message_index=message_index),
                protocol_locator=make_protocol_locator(path, message_index=message_index),
            )
            return
        for call_index, call in enumerate(tool_calls):
            call_path = f"$.messages[{message_index}].tool_calls[{call_index}]"
            carrier = make_carrier(
                "message", role=role, message_index=message_index, tool_call_index=call_index,
            )
            locator = make_protocol_locator(
                call_path, message_index=message_index, tool_call_index=call_index,
            )
            if not isinstance(call, dict):
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=call_path, code="invalid_tool_call",
                    observed_type=type(call).__name__, carrier=carrier,
                    protocol_locator=locator,
                )
                continue
            function = call.get("function") if isinstance(call.get("function"), dict) else {}
            arguments = function.get("arguments")
            tool_name = self._optional_string(function.get("name"))
            tool_call_id = self._optional_string(call.get("id"))
            if not isinstance(arguments, str):
                path = f"{call_path}.function.arguments"
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=path, code="invalid_tool_arguments",
                    observed_type=type(arguments).__name__, carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        path, message_index=message_index, tool_call_index=call_index,
                    ),
                )
                continue
            path = f"{call_path}.function.arguments"
            self._append(
                units, request, model=model, session_id=session_id,
                semantic_type="tool_arguments", content=arguments, carrier=carrier,
                protocol_locator=make_protocol_locator(
                    path, message_index=message_index, tool_call_index=call_index,
                ),
                tool_context=make_tool_context(
                    tool_call_id=tool_call_id, tool_name=tool_name,
                    tool_index=tool_definitions.get(tool_name) if tool_name else None,
                    tool_definition_index=tool_definitions.get(tool_name) if tool_name else None,
                    tool_call_message_index=message_index, tool_call_index=call_index,
                ),
                media_type="application/json",
            )

    @staticmethod
    def _message_semantic_type(role: str | None) -> str:
        if role == "system":
            return "system_instruction"
        if role == "tool":
            return "tool_result"
        return "message_content"

    def _tool_result_context(
        self,
        message: dict[str, Any],
        tool_calls: dict[str, dict[str, Any]],
        tool_definitions: dict[str, int],
    ) -> dict[str, Any] | None:
        if message.get("role") != "tool":
            return None
        tool_call_id = self._optional_string(message.get("tool_call_id"))
        linked = tool_calls.get(tool_call_id, {}) if tool_call_id else {}
        tool_name = self._optional_string(message.get("name")) or linked.get("tool_name")
        return make_tool_context(
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            tool_index=tool_definitions.get(tool_name) if tool_name else None,
            tool_definition_index=tool_definitions.get(tool_name) if tool_name else None,
            tool_call_message_index=linked.get("message_index"),
            tool_call_index=linked.get("tool_call_index"),
        )

    def _index_tool_definitions(self, tools: Any) -> dict[str, int]:
        result = {}
        if not isinstance(tools, list):
            return result
        for index, tool in enumerate(tools):
            if not isinstance(tool, dict) or not isinstance(tool.get("function"), dict):
                continue
            name = self._optional_string(tool["function"].get("name"))
            if name is not None and name not in result:
                result[name] = index
        return result

    def _index_tool_calls(self, messages: Any) -> dict[str, dict[str, Any]]:
        result = {}
        if not isinstance(messages, list):
            return result
        for message_index, message in enumerate(messages):
            if not isinstance(message, dict) or not isinstance(message.get("tool_calls"), list):
                continue
            for call_index, call in enumerate(message["tool_calls"]):
                if not isinstance(call, dict):
                    continue
                tool_call_id = self._optional_string(call.get("id"))
                function = call.get("function") if isinstance(call.get("function"), dict) else {}
                if tool_call_id is not None and tool_call_id not in result:
                    result[tool_call_id] = {
                        "tool_name": self._optional_string(function.get("name")),
                        "message_index": message_index,
                        "tool_call_index": call_index,
                    }
        return result
