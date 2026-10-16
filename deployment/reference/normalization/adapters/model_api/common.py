import hashlib
import json
import uuid
from typing import Any
from urllib.parse import urlsplit

from normalization.core.models import AgentEgressUnit, CanonicalRequest
from normalization.core.vocabulary import (
    ADAPTER_VERSION,
    MODEL_API_PROVIDERS,
    MODEL_API_TYPES,
    SCHEMA_VERSION,
    SEMANTIC_TYPES,
    make_carrier,
    make_protocol_locator,
)



class ModelAPIAdapter:
    protocol: str
    provider: str
    api_type: str
    session_header: str | None = None

    def _append(
        self,
        units: list[AgentEgressUnit],
        request: CanonicalRequest,
        *,
        model: str | None,
        session_id: str | None,
        semantic_type: str,
        content: str,
        carrier: dict[str, Any],
        protocol_locator: dict[str, Any],
        tool_context: dict[str, Any] | None = None,
        media_type: str = "text/plain",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if self.provider not in MODEL_API_PROVIDERS:
            raise ValueError(f"Unknown model API provider: {self.provider}")
        api_type = self._request_api_type(request)
        if api_type not in MODEL_API_TYPES:
            raise ValueError(f"Unknown model API type: {api_type}")
        if semantic_type not in SEMANTIC_TYPES:
            raise ValueError(f"Unknown AEU semantic type: {semantic_type}")
        encoded = content.encode("utf-8")
        content_metadata = {
            "media_type": media_type,
            "encoding": "utf-8",
            "byte_length": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "adapter_version": ADAPTER_VERSION,
            "parse_status": "success",
        }
        if metadata:
            content_metadata.update(metadata)
        units.append(
            AgentEgressUnit(
                schema_version=SCHEMA_VERSION,
                aeu_id=f"aeu_{uuid.uuid4().hex}",
                run_id=request.run_id,
                flow_id=request.flow_id,
                harness_id=request.harness_id,
                proxy_principal=request.proxy_principal,
                timestamp=request.timestamp,
                protocol=self.protocol,
                session_id=session_id,
                semantic_type=semantic_type,
                content=content,
                carrier=carrier,
                protocol_locator=protocol_locator,
                tool_context=tool_context,
                sink=self._sink(request, model),
                unit_index=len(units),
                content_metadata=content_metadata,
            )
        )

    def _diagnostic(
        self,
        units: list[AgentEgressUnit],
        request: CanonicalRequest,
        *,
        model: str | None,
        session_id: str | None,
        json_path: str,
        code: str,
        parse_status: str = "partial",
        observed_type: str | None = None,
        metadata: dict[str, Any] | None = None,
        carrier: dict[str, Any] | None = None,
        protocol_locator: dict[str, Any] | None = None,
    ) -> None:
        details = {"diagnostic_code": code, "parse_status": parse_status}
        if observed_type is not None:
            details["observed_type"] = observed_type
        if metadata:
            details.update(metadata)
        self._append(
            units,
            request,
            model=model,
            session_id=session_id,
            semantic_type="adapter_diagnostic",
            content="",
            carrier=carrier or make_carrier("request_diagnostic"),
            protocol_locator=protocol_locator or make_protocol_locator(json_path),
            media_type="application/x-agentdlp-diagnostic",
            metadata=details,
        )

    def _sink(self, request: CanonicalRequest, model: str | None) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "api_type": self._request_api_type(request),
            "host": request.host,
            "port": request.port,
            "path": urlsplit(request.path).path,
            "model": model,
            "flow_id": request.flow_id,
        }

    def _request_api_type(self, request: CanonicalRequest) -> str:
        return self.api_type

    def diagnostic_model(self, request: CanonicalRequest) -> str | None:
        return None

    def request_session_id(self, request: CanonicalRequest) -> str | None:
        if self.session_header is None:
            return None
        return request.headers.get(self.session_header)

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        return value if isinstance(value, str) else None

    @staticmethod
    def _compact_json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _iter_string_leaves(
        cls,
        value: Any,
        json_path: str,
        leaf_path: tuple[str | int, ...] = (),
    ):
        if isinstance(value, str):
            yield json_path, list(leaf_path), value
        elif isinstance(value, dict):
            for key, child in value.items():
                yield from cls._iter_string_leaves(child, f"{json_path}.{key}", (*leaf_path, key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                yield from cls._iter_string_leaves(child, f"{json_path}[{index}]", (*leaf_path, index))
