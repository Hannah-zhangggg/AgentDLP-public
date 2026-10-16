"""Versioned, structured behavior classification, NOT a consistency detector.

Input facts are supplied by an annotation/adapter. This module validates the
contract, derives graph features, and separates behavior from evidence axes.
It does not infer arbitrary tool semantics from names, shell text or packets.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
from pathlib import Path
from typing import Any

VERSION = "behavior-matrix-v1"
VOCABULARIES = {
    "operation": {"read", "query", "create", "update", "delete", "execute", "transfer", "control", "unknown"},
    "resource": {"file", "process", "database_object", "business_object", "message", "application_state", "unknown"},
    "interface": {"native", "cli", "mcp", "direct_api", "browser", "unknown"},
    "protocol": {"none", "stdio", "http1", "http2", "websocket", "json_rpc", "unknown"},
    "placement": {"in_process", "same_host", "cross_host", "unknown"},
    "effect": {"read_only", "mutating", "unknown"},
    "idempotency": {"idempotent", "non_idempotent", "not_applicable", "unknown"},
    "retry": {"forbidden", "transport_only", "idempotency_required", "allowed", "unknown"},
    "completion": {"attempt", "response", "commit", "unknown"},
    "atomicity": {"atomic", "partial_allowed", "not_applicable", "unknown"},
    "cache": {"forbidden", "freshness_checked", "allowed", "unknown"},
    "result_mode": {"value", "error", "stream", "async_handle", "none", "unknown"},
    "transform": {"exact", "lossless", "bounded_truncation", "unknown"},
    "relation": {"data", "order", "spawn", "callback"},
    "execution_pattern": {"retry", "batch", "delegation", "callback"},
    "state": {"completed", "failed", "partial", "pending", "unknown"},
    "timing": {"immediate", "deferred", "not_applicable", "unknown"},
    "representation": {"structured", "shell", "utf8", "base64", "binary", "encrypted", "unknown"},
    "semantic_status": {"exact", "partial", "ambiguous", "unsupported", "unknown"},
    "association": {"unique", "multiple", "conflicted", "unlinked", "unknown"},
    "verdict_identifiability": {"determinate", "indeterminate", "not_assessed", "unknown"},
    "effect_visibility": {"intent", "attempt", "arrival", "commit", "unknown", "not_applicable"},
    "integrity": {"complete", "loss", "open_window", "duplicate", "conflict", "unknown"},
    "provenance": {"verified", "unverified", "unknown"},
}


class MatrixError(ValueError):
    """Malformed annotations are rejected; unknown semantics remain explicit."""


def _keys(value: Any, expected: set[str], path: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise MatrixError(f"{path}: expected fields {sorted(expected)}")


def _text(value: Any, path: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise MatrixError(f"{path}: non-empty text required")


def _enum(value: Any, vocabulary: str, path: str) -> None:
    if not isinstance(value, str) or value not in VOCABULARIES[vocabulary]:
        raise MatrixError(f"{path}: unsupported {vocabulary}; annotate unknown explicitly")


def _unique(values: list[Any]) -> list[Any]:
    indexed = {json.dumps(value, sort_keys=True, ensure_ascii=False): value for value in values}
    return [deepcopy(indexed[key]) for key in sorted(indexed)]


def classify_behavior(record: dict[str, Any]) -> dict[str, Any]:
    """Classify a complete workflow and retain per-action annotations.

    Coverage coordinates omit literal IDs/paths/payloads, but retain scope-field
    names and resource classes. Concrete scopes remain in action_annotations.
    Observed executions/reports are attached separately from behavior contracts.
    No final Consistent/Inconsistent/Uncertain verdict is produced here.
    """
    _keys(record, {"schema_version", "actions", "dependencies", "execution_patterns", "observations", "evidence"}, "record")
    if record["schema_version"] != VERSION:
        raise MatrixError("unsupported schema_version")
    if not isinstance(record["actions"], list) or not record["actions"]:
        raise MatrixError("actions: non-empty list required")
    actions: dict[str, dict[str, Any]] = {}
    unknowns = []
    for action in record["actions"]:
        _keys(action, {"id", "operation", "resource", "pathway", "execution_contract", "result_contract", "unknown_reason"}, "action")
        aid = action["id"]
        _text(aid, "action.id")
        if aid in actions:
            raise MatrixError(f"duplicate action id: {aid}")
        _enum(action["operation"], "operation", aid)
        _keys(action["resource"], {"kind", "scope"}, f"{aid}.resource")
        _enum(action["resource"]["kind"], "resource", aid)
        scope = action["resource"]["scope"]
        if not isinstance(scope, dict) or not scope:
            raise MatrixError(f"{aid}.resource.scope: non-empty mapping required")
        for key, value in scope.items():
            _text(key, f"{aid}.scope.key")
            _text(value, f"{aid}.scope.{key}")
        _keys(action["pathway"], {"interface", "protocol", "placement"}, f"{aid}.pathway")
        for field, value in action["pathway"].items():
            _enum(value, field, f"{aid}.pathway.{field}")
        contract = action["execution_contract"]
        _keys(contract, {"effect", "idempotency", "retry", "completion", "atomicity", "cache", "required_effect_count"}, f"{aid}.execution_contract")
        for field, value in contract.items():
            if field != "required_effect_count":
                _enum(value, field, f"{aid}.contract.{field}")
        count = contract["required_effect_count"]
        if count is not None and (type(count) is not int or count < 0):
            raise MatrixError(f"{aid}: required_effect_count must be nonnegative int or null")
        if contract["effect"] == "read_only" and count not in (None, 0):
            raise MatrixError(f"{aid}: read-only contract cannot require mutations")
        if action["operation"] in {"create", "update", "delete"} and contract["effect"] == "read_only":
            raise MatrixError(f"{aid}: state-changing operation cannot have a read-only contract")
        _keys(action["result_contract"], {"mode", "transform", "binding"}, f"{aid}.result_contract")
        _enum(action["result_contract"]["mode"], "result_mode", aid)
        _enum(action["result_contract"]["transform"], "transform", aid)
        if action["result_contract"]["binding"] not in ("invocation", "aggregate", "none", "unknown"):
            raise MatrixError(f"{aid}: invalid result binding")
        fields = {"operation": action["operation"], "resource.kind": action["resource"]["kind"],
                  **{f"pathway.{k}": v for k, v in action["pathway"].items()},
                  **{f"contract.{k}": v for k, v in contract.items()},
                  **{f"result.{k}": v for k, v in action["result_contract"].items()}}
        missing = sorted(key for key, value in fields.items() if value == "unknown")
        if missing:
            _text(action["unknown_reason"], f"{aid}.unknown_reason")
            unknowns.append({"action": aid, "fields": missing, "reason": action["unknown_reason"]})
        elif action["unknown_reason"] is not None:
            raise MatrixError(f"{aid}: unknown_reason without unknown coordinate")
        actions[aid] = action

    if not isinstance(record["dependencies"], list):
        raise MatrixError("dependencies: list required")
    adjacency = {aid: set() for aid in actions}
    indegree = dict.fromkeys(actions, 0)
    edges = set()
    for edge in record["dependencies"]:
        _keys(edge, {"parent", "child", "relation"}, "dependency")
        parent, child = edge["parent"], edge["child"]
        _text(parent, "dependency.parent")
        _text(child, "dependency.child")
        _enum(edge["relation"], "relation", "dependency")
        if parent not in actions or child not in actions or parent == child:
            raise MatrixError("dependency must connect two distinct existing actions")
        identity = (parent, child, edge["relation"])
        if identity in edges:
            raise MatrixError("duplicate dependency")
        edges.add(identity)
        if child not in adjacency[parent]:
            adjacency[parent].add(child)
            indegree[child] += 1
    ready = [aid for aid, degree in indegree.items() if degree == 0]
    ordered, work_degrees = [], dict(indegree)
    while ready:
        aid = ready.pop()
        ordered.append(aid)
        for child in adjacency[aid]:
            work_degrees[child] -= 1
            if work_degrees[child] == 0:
                ready.append(child)
    if len(ordered) != len(actions):
        raise MatrixError("dependencies contain a cycle")
    descendants = {aid: set() for aid in actions}
    for aid in reversed(ordered):
        for child in adjacency[aid]:
            descendants[aid].add(child)
            descendants[aid].update(descendants[child])
    pairs = [(a, b) for a in sorted(actions) for b in sorted(actions) if a < b]
    unordered = [(a, b) for a, b in pairs if b not in descendants[a] and a not in descendants[b]]
    patterns = record["execution_patterns"]
    if not isinstance(patterns, list):
        raise MatrixError("execution_patterns: list required")
    for pattern in patterns:
        _enum(pattern, "execution_pattern", "execution_patterns")
    if len(set(patterns)) != len(patterns):
        raise MatrixError("duplicate execution pattern")

    observations = record["observations"]
    if not isinstance(observations, list):
        raise MatrixError("observations: list required")
    observed_ids = set()
    for observation in observations:
        _keys(observation, {"action", "attempts", "effects", "state", "timing", "reported_for", "report_value"}, "observation")
        aid = observation["action"]
        _text(aid, "observation.action")
        if aid not in actions or aid in observed_ids:
            raise MatrixError("observation must refer to one unique existing action")
        observed_ids.add(aid)
        for field in ("attempts", "effects"):
            value = observation[field]
            if value is not None and (type(value) is not int or value < 0):
                raise MatrixError(f"observation.{field}: nonnegative int or null required")
        _enum(observation["state"], "state", "observation.state")
        _enum(observation["timing"], "timing", "observation.timing")
        owner = observation["reported_for"]
        if owner is not None:
            _text(owner, "observation.reported_for")
        if observation["report_value"] is not None:
            _text(observation["report_value"], "observation.report_value")

    evidence = record["evidence"]
    _keys(evidence, {"representation", "semantic_status", "association", "verdict_identifiability", "effect_visibility", "integrity", "provenance"}, "evidence")
    for field, value in evidence.items():
        _enum(value, field, f"evidence.{field}")
    # An annotator may explicitly assert aggregate verdict identifiability even
    # without unique identities. We neither infer nor forbid that assertion.
    behavior = {
        "D1_operation": sorted({action["operation"] for action in actions.values()}),
        "D2_resource_scope": _unique([{"kind": action["resource"]["kind"],
                    "scope_fields": sorted(action["resource"]["scope"])} for action in actions.values()]),
        "D3_pathway": _unique([action["pathway"] for action in actions.values()]),
        "D4_orchestration": {"action_count": len(actions), "dependency_count": len(edges),
                    "relations": sorted({relation for _, _, relation in edges}),
                    "unordered_pair_count": len(unordered), "parallel_permitted": bool(unordered),
                    "fan_out": any(len(children) > 1 for children in adjacency.values()),
                    "fan_in": any(degree > 1 for degree in indegree.values()),
                    "patterns": sorted(patterns)},
        "D5_execution_contract": _unique([action["execution_contract"] for action in actions.values()]),
        "D6_result_contract": _unique([action["result_contract"] for action in actions.values()]),
    }
    evidence_axes = {
        "E1_semantics": {key: evidence[key] for key in ("representation", "semantic_status")},
        "E2_causality": {key: evidence[key] for key in ("association", "verdict_identifiability")},
        "E3_effect": evidence["effect_visibility"],
        "E4_integrity": {key: evidence[key] for key in ("integrity", "provenance")},
    }
    return {"schema_version": VERSION, "behavior": behavior, "evidence": evidence_axes,
            "action_annotations": [deepcopy(actions[aid]) for aid in sorted(actions)],
            "dependency_annotations": [dict(parent=a, child=b, relation=r) for a, b, r in sorted(edges)],
            "observations": sorted(deepcopy(observations), key=lambda row: row["action"]),
            "unobserved_actions": sorted(set(actions) - observed_ids),
            "taxonomy_status": "partial" if unknowns else "classified", "unknowns": unknowns}


def compare_classifications(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Separate coordinate changes, concrete changes and observed outcomes."""
    return {
        "behavior_axes": sorted(key for key in left["behavior"] if left["behavior"][key] != right["behavior"][key]),
        "evidence_axes": sorted(key for key in left["evidence"] if left["evidence"][key] != right["evidence"][key]),
        "concrete_annotations_changed": (left["action_annotations"] != right["action_annotations"]
                                         or left["dependency_annotations"] != right["dependency_annotations"]),
        "observations_changed": left["observations"] != right["observations"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="One structured workflow annotation")
    parser.add_argument("--output", type=Path, help="New output file; otherwise print JSON")
    args = parser.parse_args()
    result = classify_behavior(json.loads(args.input.read_text(encoding="utf-8")))
    serialized = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(serialized)
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
