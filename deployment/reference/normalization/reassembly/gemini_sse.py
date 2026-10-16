from __future__ import annotations

import copy
import json
from typing import Any

from normalization.reassembly.anthropic_sse import iter_sse_events


class GeminiSSEReconstructor:
    """Merge Gemini streamGenerateContent SSE chunks into one response object."""

    def __init__(self) -> None:
        self.candidates: dict[int, dict[str, Any]] = {}
        self.top_level: dict[str, Any] = {}
        self.errors: list[dict[str, Any]] = []
        self.diagnostics: list[dict[str, Any]] = []
        self.event_count = 0

    def diagnostic(self, code: str, **details: Any) -> None:
        self.diagnostics.append({"code": code, **details})

    def consume(self, payload: dict[str, Any]) -> None:
        self.event_count += 1
        error = payload.get("error")
        if isinstance(error, dict):
            self.errors.append(copy.deepcopy(error))
            return

        candidates = payload.get("candidates", [])
        if not isinstance(candidates, list):
            self.diagnostic("invalid_candidates", observed_type=type(candidates).__name__)
            candidates = []
        for position, candidate in enumerate(candidates):
            if not isinstance(candidate, dict):
                self.diagnostic("invalid_candidate", position=position)
                continue
            index = candidate.get("index", position)
            if not isinstance(index, int):
                self.diagnostic("invalid_candidate_index", position=position, value=index)
                continue
            target = self.candidates.setdefault(index, {"index": index, "content": {"parts": []}})
            self._merge_candidate(target, candidate)

        for key, value in payload.items():
            if key in {"candidates", "error"}:
                continue
            if key == "usageMetadata" and isinstance(value, dict):
                usage = self.top_level.setdefault("usageMetadata", {})
                if isinstance(usage, dict):
                    usage.update(copy.deepcopy(value))
                else:
                    self.top_level[key] = copy.deepcopy(value)
            else:
                self.top_level[key] = copy.deepcopy(value)

    def _merge_candidate(self, target: dict[str, Any], source: dict[str, Any]) -> None:
        for key, value in source.items():
            if key in {"index", "content"}:
                continue
            target[key] = copy.deepcopy(value)
        content = source.get("content")
        if not isinstance(content, dict):
            return
        target_content = target.setdefault("content", {"parts": []})
        if not isinstance(target_content, dict):
            target_content = {"parts": []}
            target["content"] = target_content
        role = content.get("role")
        if isinstance(role, str):
            target_content["role"] = role
        parts = content.get("parts", [])
        if not isinstance(parts, list):
            self.diagnostic("invalid_candidate_parts", index=target["index"])
            return
        target_parts = target_content.setdefault("parts", [])
        if not isinstance(target_parts, list):
            target_parts = []
            target_content["parts"] = target_parts
        for part in parts:
            if not isinstance(part, dict):
                self.diagnostic("invalid_candidate_part", index=target["index"])
                continue
            if self._can_merge_text(target_parts, part):
                target_parts[-1]["text"] += part["text"]
            else:
                target_parts.append(copy.deepcopy(part))

    @staticmethod
    def _can_merge_text(parts: list[dict[str, Any]], part: dict[str, Any]) -> bool:
        if not parts or not isinstance(part.get("text"), str):
            return False
        previous = parts[-1]
        if not isinstance(previous, dict) or not isinstance(previous.get("text"), str):
            return False
        previous_meta = {key: value for key, value in previous.items() if key != "text"}
        part_meta = {key: value for key, value in part.items() if key != "text"}
        return previous_meta == part_meta

    def result(self) -> dict[str, Any]:
        response = copy.deepcopy(self.top_level)
        response["candidates"] = [copy.deepcopy(self.candidates[index]) for index in sorted(self.candidates)]
        terminal = bool(self.candidates) and all(
            isinstance(candidate.get("finishReason"), str)
            for candidate in self.candidates.values()
        )
        return {
            "schema_version": 1,
            "protocol": "gemini_generate_content_sse",
            "complete": self.event_count > 0 and terminal and not self.errors,
            "response": response,
            "errors": copy.deepcopy(self.errors),
            "diagnostics": copy.deepcopy(self.diagnostics),
            "event_count": self.event_count,
        }


def reconstruct_gemini_sse(body: bytes | str) -> dict[str, Any]:
    reconstructor = GeminiSSEReconstructor()
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
            reconstructor.consume(payload)
    except UnicodeDecodeError as error:
        reconstructor.diagnostic("invalid_utf8", error=str(error))
    return reconstructor.result()
