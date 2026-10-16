import base64
import binascii
import json
import re
from typing import Any
from urllib.parse import unquote

from normalization.adapters.model_api.common import ModelAPIAdapter
from normalization.core.models import AgentEgressUnit, CanonicalRequest
from normalization.core.vocabulary import make_carrier, make_protocol_locator, make_tool_context


GEMINI_PATH = re.compile(r"/models/([^/:]+):(streamGenerateContent|generateContent)$")


class GeminiGenerateContentAdapter(ModelAPIAdapter):
    protocol = "gemini_generate_content"
    provider = "google_gemini"
    api_type = "generate_content"
    session_header = "x-session-id"

    def matches(self, request: CanonicalRequest) -> bool:
        content_type = request.headers.get("content-type", "").lower()
        path = request.path.split("?", 1)[0].rstrip("/")
        return (
            request.method.upper() == "POST"
            and GEMINI_PATH.search(path) is not None
            and ("application/json" in content_type or not content_type)
        )

    def adapt(self, request: CanonicalRequest) -> list[AgentEgressUnit]:
        payload = json.loads(request.body.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Gemini GenerateContent body must be a JSON object")
        path = request.path.split("?", 1)[0].rstrip("/")
        match = GEMINI_PATH.search(path)
        if match is None:
            raise ValueError("Gemini GenerateContent path does not contain a model")
        model, operation = unquote(match.group(1)), match.group(2)
        session_id = self.request_session_id(request)
        audit = {
            "api_version": self._api_version(path),
            "operation": operation,
            "stream": operation == "streamGenerateContent",
        }
        units: list[AgentEgressUnit] = []
        contents = payload.get("contents", [])
        tools = payload.get("tools", [])
        tool_definitions = self._index_tool_definitions(tools)
        function_calls = self._index_function_calls(contents)

        self._append_content(
            units, request, model, session_id, None, None,
            payload.get("systemInstruction"), "$.systemInstruction",
            "system_instruction", audit, function_calls, tool_definitions,
            system=True,
        )

        if isinstance(contents, list):
            for content_index, content in enumerate(contents):
                path_prefix = f"$.contents[{content_index}]"
                if not isinstance(content, dict):
                    self._diagnostic(
                        units, request, model=model, session_id=session_id,
                        json_path=path_prefix, code="invalid_content",
                        observed_type=type(content).__name__, metadata=audit,
                        carrier=make_carrier("message", message_index=content_index),
                        protocol_locator=make_protocol_locator(
                            path_prefix, message_index=content_index,
                        ),
                    )
                    continue
                self._append_content(
                    units, request, model, session_id,
                    self._optional_string(content.get("role")), content_index,
                    content, path_prefix, "message_content", audit,
                    function_calls, tool_definitions,
                )
        elif contents is not None:
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path="$.contents", code="invalid_contents",
                observed_type=type(contents).__name__, metadata=audit,
            )

        if isinstance(tools, list):
            for tool_index, tool in enumerate(tools):
                tool_path = f"$.tools[{tool_index}]"
                if not isinstance(tool, dict):
                    self._diagnostic(
                        units, request, model=model, session_id=session_id,
                        json_path=tool_path, code="invalid_tool_definition",
                        observed_type=type(tool).__name__, metadata=audit,
                        carrier=make_carrier("tool_definition"),
                        protocol_locator=make_protocol_locator(tool_path, tool_index=tool_index),
                    )
                    continue
                declarations_key = "functionDeclarations"
                declarations = tool.get(declarations_key)
                if not isinstance(declarations, list):
                    declarations_key = "function_declarations"
                    declarations = tool.get(declarations_key)
                if not isinstance(declarations, list):
                    self._diagnostic(
                        units, request, model=model, session_id=session_id,
                        json_path=tool_path, code="unknown_tool_definition",
                        observed_type=type(tool).__name__, metadata=audit,
                        carrier=make_carrier("tool_definition"),
                        protocol_locator=make_protocol_locator(tool_path, tool_index=tool_index),
                    )
                    continue
                for declaration_index, declaration in enumerate(declarations):
                    declaration_path = f"{tool_path}.{declarations_key}[{declaration_index}]"
                    carrier = make_carrier(
                        "tool_definition", tool_definition_index=declaration_index,
                    )
                    locator = make_protocol_locator(
                        declaration_path, tool_index=tool_index,
                        tool_definition_index=declaration_index,
                    )
                    if not isinstance(declaration, dict):
                        self._diagnostic(
                            units, request, model=model, session_id=session_id,
                            json_path=declaration_path, code="invalid_tool_definition",
                            observed_type=type(declaration).__name__, metadata=audit,
                            carrier=carrier, protocol_locator=locator,
                        )
                        continue
                    tool_name = self._optional_string(declaration.get("name"))
                    self._append(
                        units, request, model=model, session_id=session_id,
                        semantic_type="tool_definition",
                        content=self._compact_json(declaration), carrier=carrier,
                        protocol_locator=locator,
                        tool_context=make_tool_context(
                            tool_name=tool_name, tool_index=tool_index,
                            tool_definition_index=declaration_index,
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
        self, units, request, model, session_id, role, message_index,
        content, path, text_type, audit, function_calls, tool_definitions,
        *, system=False,
    ):
        if content is None:
            return
        if isinstance(content, str):
            carrier_type = "system_instruction" if system else "message"
            self._append(
                units, request, model=model, session_id=session_id,
                semantic_type=text_type, content=content,
                carrier=make_carrier(carrier_type, role=role, message_index=message_index),
                protocol_locator=make_protocol_locator(path, message_index=message_index),
                metadata=audit,
            )
            return
        if not isinstance(content, dict):
            carrier_type = "system_instruction" if system else "message"
            self._diagnostic(
                units, request, model=model, session_id=session_id, json_path=path,
                code="invalid_content", observed_type=type(content).__name__, metadata=audit,
                carrier=make_carrier(carrier_type, role=role, message_index=message_index),
                protocol_locator=make_protocol_locator(path, message_index=message_index),
            )
            return
        parts = content.get("parts", [])
        if not isinstance(parts, list):
            parts_path = f"{path}.parts"
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path=parts_path, code="invalid_parts",
                observed_type=type(parts).__name__, metadata=audit,
                carrier=make_carrier(
                    "system_instruction" if system else "message",
                    role=role, message_index=message_index,
                ),
                protocol_locator=make_protocol_locator(parts_path, message_index=message_index),
            )
            return
        for part_index, part in enumerate(parts):
            part_path = f"{path}.parts[{part_index}]"
            carrier = make_carrier(
                "system_instruction" if system else "part",
                role=role, message_index=message_index, part_index=part_index,
            )
            locator = make_protocol_locator(
                part_path, message_index=message_index, part_index=part_index,
            )
            if not isinstance(part, dict):
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=part_path, code="invalid_part",
                    observed_type=type(part).__name__, metadata=audit,
                    carrier=carrier, protocol_locator=locator,
                )
            elif isinstance(part.get("text"), str):
                text_path = f"{part_path}.text"
                self._append(
                    units, request, model=model, session_id=session_id,
                    semantic_type=text_type, content=part["text"], carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        text_path, message_index=message_index, part_index=part_index,
                    ),
                    metadata=audit,
                )
            elif isinstance(part.get("functionCall"), dict) and not system:
                call = part["functionCall"]
                tool_call_id = self._optional_string(call.get("id"))
                tool_name = self._optional_string(call.get("name"))
                context = make_tool_context(
                    tool_call_id=tool_call_id, tool_name=tool_name,
                    tool_index=self._definition_indices(tool_definitions, tool_name)[0],
                    tool_definition_index=self._definition_indices(tool_definitions, tool_name)[1],
                    tool_call_message_index=message_index,
                    tool_call_part_index=part_index,
                )
                for leaf_json_path, leaf_path, text in self._iter_string_leaves(
                    call.get("args"), f"{part_path}.functionCall.args"
                ):
                    self._append(
                        units, request, model=model, session_id=session_id,
                        semantic_type="tool_arguments", content=text, carrier=carrier,
                        protocol_locator=make_protocol_locator(
                            leaf_json_path, message_index=message_index,
                            part_index=part_index, leaf_path=leaf_path,
                        ),
                        tool_context=context, metadata=audit,
                    )
            elif isinstance(part.get("functionResponse"), dict) and not system:
                response = part["functionResponse"]
                tool_call_id = self._optional_string(response.get("id"))
                linked = function_calls.get(tool_call_id, {}) if tool_call_id else {}
                tool_name = self._optional_string(response.get("name")) or linked.get("tool_name")
                context = make_tool_context(
                    tool_call_id=tool_call_id, tool_name=tool_name,
                    tool_index=self._definition_indices(tool_definitions, tool_name)[0],
                    tool_definition_index=self._definition_indices(tool_definitions, tool_name)[1],
                    tool_call_message_index=linked.get("message_index"),
                    tool_call_part_index=linked.get("part_index"),
                )
                for leaf_json_path, leaf_path, text in self._iter_string_leaves(
                    response.get("response"), f"{part_path}.functionResponse.response"
                ):
                    self._append(
                        units, request, model=model, session_id=session_id,
                        semantic_type="tool_result", content=text, carrier=carrier,
                        protocol_locator=make_protocol_locator(
                            leaf_json_path, message_index=message_index,
                            part_index=part_index, leaf_path=leaf_path,
                        ),
                        tool_context=context, metadata=audit,
                    )
            elif isinstance(part.get("inlineData"), dict):
                self._append_inline_data(
                    units, request, model, session_id, part["inlineData"],
                    f"{part_path}.inlineData", message_index, part_index,
                    carrier, audit,
                )
            elif isinstance(part.get("fileData"), dict):
                file_data = part["fileData"]
                uri = file_data.get("fileUri")
                if isinstance(uri, str):
                    uri_path = f"{part_path}.fileData.fileUri"
                    self._append(
                        units, request, model=model, session_id=session_id,
                        semantic_type="file_reference", content=uri, carrier=carrier,
                        protocol_locator=make_protocol_locator(
                            uri_path, message_index=message_index, part_index=part_index,
                        ),
                        media_type="text/uri-list",
                        metadata={**audit, "referenced_media_type": file_data.get("mimeType")},
                    )
                else:
                    self._diagnostic(
                        units, request, model=model, session_id=session_id,
                        json_path=f"{part_path}.fileData.fileUri",
                        code="invalid_file_reference", observed_type=type(uri).__name__,
                        metadata=audit, carrier=carrier, protocol_locator=locator,
                    )
            else:
                observed = next(iter(part), "empty")
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=part_path, code="unknown_part",
                    observed_type=observed, metadata=audit,
                    carrier=carrier, protocol_locator=locator,
                )

    def _append_inline_data(
        self, units, request, model, session_id, inline, path,
        message_index, part_index, carrier, audit,
    ):
        media_type = inline.get("mimeType")
        data = inline.get("data")
        data_path = f"{path}.data"
        if isinstance(media_type, str) and media_type.startswith("text/") and isinstance(data, str):
            try:
                text = base64.b64decode(data, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                self._diagnostic(
                    units, request, model=model, session_id=session_id,
                    json_path=data_path, code="invalid_text_inline_data",
                    observed_type=media_type, metadata=audit, carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        data_path, message_index=message_index, part_index=part_index,
                    ),
                )
            else:
                self._append(
                    units, request, model=model, session_id=session_id,
                    semantic_type="inline_text", content=text, carrier=carrier,
                    protocol_locator=make_protocol_locator(
                        data_path, message_index=message_index, part_index=part_index,
                    ),
                    media_type=media_type,
                    metadata={**audit, "decoded_from": "base64"},
                )
        else:
            self._diagnostic(
                units, request, model=model, session_id=session_id,
                json_path=path, code="unsupported_inline_data",
                observed_type=media_type or type(data).__name__, metadata=audit,
                carrier=carrier,
                protocol_locator=make_protocol_locator(
                    path, message_index=message_index, part_index=part_index,
                ),
            )

    def _request_api_type(self, request: CanonicalRequest) -> str:
        path = request.path.split("?", 1)[0].rstrip("/")
        return "stream_generate_content" if path.endswith(":streamGenerateContent") else "generate_content"

    def diagnostic_model(self, request: CanonicalRequest) -> str | None:
        path = request.path.split("?", 1)[0].rstrip("/")
        match = GEMINI_PATH.search(path)
        return unquote(match.group(1)) if match is not None else None

    def _index_tool_definitions(self, tools: Any) -> dict[str, tuple[int, int]]:
        result = {}
        if not isinstance(tools, list):
            return result
        for tool_index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                continue
            declarations = tool.get("functionDeclarations")
            if not isinstance(declarations, list):
                declarations = tool.get("function_declarations")
            if not isinstance(declarations, list):
                continue
            for declaration_index, declaration in enumerate(declarations):
                if isinstance(declaration, dict):
                    name = self._optional_string(declaration.get("name"))
                    if name is not None and name not in result:
                        result[name] = (tool_index, declaration_index)
        return result

    @staticmethod
    def _definition_indices(
        definitions: dict[str, tuple[int, int]],
        tool_name: str | None,
    ) -> tuple[int | None, int | None]:
        return definitions.get(tool_name, (None, None)) if tool_name else (None, None)

    def _index_function_calls(self, contents: Any) -> dict[str, dict[str, Any]]:
        result = {}
        if not isinstance(contents, list):
            return result
        for message_index, content in enumerate(contents):
            if not isinstance(content, dict) or not isinstance(content.get("parts"), list):
                continue
            for part_index, part in enumerate(content["parts"]):
                if not isinstance(part, dict) or not isinstance(part.get("functionCall"), dict):
                    continue
                call = part["functionCall"]
                tool_call_id = self._optional_string(call.get("id"))
                if tool_call_id is not None and tool_call_id not in result:
                    result[tool_call_id] = {
                        "tool_name": self._optional_string(call.get("name")),
                        "message_index": message_index,
                        "part_index": part_index,
                    }
        return result

    @staticmethod
    def _api_version(path: str) -> str | None:
        for component in path.split("/"):
            if re.fullmatch(r"v\d+(?:beta\d*)?", component):
                return component
        return None
