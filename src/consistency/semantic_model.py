"""Semantic IR v1: typed facts, not a universal tool-language normalizer.

Profiles specify required comparison fields. Parsing/validation never certifies
truth: evidence_matrix separately requires loader-pinned observations. Existing
behavior-matrix-v1 and deployed classifiers are intentionally unchanged.
"""
from __future__ import annotations

from copy import deepcopy
import json
import math

VERSION = "semantic-ir-v1"
STATUSES = {"known", "unknown", "ambiguous", "unsupported", "not_applicable"}
OPERATIONS = {"read", "query", "create", "update", "delete", "execute", "transfer", "control", "unknown"}
TYPES = {"text", "integer", "number", "boolean", "resource", "text_list", "json"}
# These are representation profiles, not promises of SQL/DOM/business inference.
PROFILES = {
    "file.read@1": {"source": "resource", "range": "json"},
    "file.write@1": {"target": "resource", "content": "text", "overwrite": "boolean"},
    "file.move@1": {"source": "resource", "target": "resource", "overwrite": "boolean"},
    "message.send@1": {"recipient": "resource", "channel": "text", "content": "text"},
    "database.statement@1": {"database": "resource", "dialect": "text", "statement": "text", "statement_kinds": "text_list"},
    "browser.event@1": {"document": "resource", "frame": "text", "snapshot": "text", "event": "text", "target": "text", "value": "json"},
    "git.change@1": {"repository": "resource", "ref": "text", "base_revision": "text", "change": "json"},
    "document.tree@1": {"container": "resource", "children": "json", "position": "json", "mutation": "text"},
    "business.mutation@1": {"subject": "resource", "object": "resource", "mutation": "text", "parameters": "json"},
    "value.transform@1": {"input": "json", "transformation": "text", "output_schema": "json"},
}
COMPARISON_CONTEXTS = {
    "browser.event@1": {"target": ("document", "frame", "snapshot")},
    "database.statement@1": {"statement": ("database", "dialect")},
    "git.change@1": {"change": ("repository", "ref", "base_revision")},
    "document.tree@1": {"children": ("container", "position", "mutation")},
    "business.mutation@1": {"parameters": ("subject", "object", "mutation")},
}


class SemanticError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise SemanticError(message)


def text(value):
    return isinstance(value, str) and bool(value.strip())


def canonical(value):
    # Exact JSON identity: bool != int, array order matters, object order does not.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def slot(value=None, *, type="text", status="known", reason=None, refs=()):
    result = dict(type=type, status=status, value=value, reason=reason, refs=list(refs))
    validate_slot(result)
    return result


def validate_slot(item):
    require(isinstance(item, dict) and set(item) == {"type", "status", "value", "reason", "refs"}, "invalid semantic slot")
    require(item["type"] in TYPES and item["status"] in STATUSES, "unknown slot type/status")
    require(isinstance(item["refs"], list) and all(text(x) for x in item["refs"]), "refs must be source locators")
    value, kind = item["value"], item["type"]
    if item["status"] != "known":
        require(value is None and text(item["reason"]), "non-known slots require reason and no fabricated value")
        return
    require(item["reason"] is None, "known slot cannot carry unknown reason")
    valid = {
        "text": lambda: isinstance(value, str),
        "integer": lambda: type(value) is int,
        "number": lambda: type(value) in (int, float) and math.isfinite(value),
        "boolean": lambda: type(value) is bool,
        "text_list": lambda: isinstance(value, list) and all(isinstance(x, str) for x in value),
        "resource": lambda: isinstance(value, dict) and set(value) == {"kind", "namespace", "key"} and all(text(x) for x in value.values()),
        "json": lambda: True,
    }[kind]()
    require(valid, f"invalid {kind} value")
    try:
        canonical(value)
    except (TypeError, ValueError) as exc:
        raise SemanticError("value is not finite JSON") from exc


def new_action(aid, profile, *, plane="observed", stage="invocation", operation="unknown", run="run-1", session="session-1"):
    require(profile in PROFILES or profile == "unsupported", "unregistered profile")
    return dict(schema_version=VERSION, id=aid, scope=dict(run=run, session=session), plane=plane,
                stage=stage, invocation_id=None, profile=profile, operation=operation,
                structure="opaque" if profile == "unsupported" else "atomic",
                fields={key: slot(type=kind, status="unknown", reason="not_observed") for key, kind in PROFILES.get(profile, {}).items()},
                contracts={"provider_requirement": {}, "task_requirement": {}, "tool_declaration": {}, "runtime_observation": {}},
                fragments=[], pathway={"interface": "unknown", "actuator": "unknown", "protocol": "unknown", "placement": "unknown"})


def validate_action(action):
    require(isinstance(action, dict) and set(action) == {"schema_version", "id", "scope", "plane", "stage", "invocation_id", "profile", "operation", "structure", "fields", "contracts", "fragments", "pathway"}, "invalid action fields")
    require(action["schema_version"] == VERSION and text(action["id"]), "invalid action version/id")
    require(isinstance(action["scope"], dict) and set(action["scope"]) == {"run", "session"} and all(text(x) for x in action["scope"].values()), "run/session required")
    require(action["plane"] in {"expected", "observed"}, "invalid plane")
    require(action["stage"] in {"instruction", "invocation", "attempt", "effect", "result"}, "invalid stage")
    require((action["plane"] == "expected") == (action["stage"] == "instruction"), "instruction and observation planes must remain separate")
    require(action["invocation_id"] is None or text(action["invocation_id"]), "invalid invocation id")
    require(action["operation"] in OPERATIONS and action["structure"] in {"atomic", "composite", "opaque"}, "invalid operation/structure")
    require(action["profile"] in PROFILES or action["profile"] == "unsupported", "unregistered profile")
    require(isinstance(action["fields"], dict), "fields must be a mapping")
    for key, item in action["fields"].items():
        require(text(key), "empty field name")
        validate_slot(item)
    for key, kind in PROFILES.get(action["profile"], {}).items():
        require(key in action["fields"] and action["fields"][key]["type"] == kind, f"profile requires typed {key}, use unknown if absent")
    require(isinstance(action["contracts"], dict) and set(action["contracts"]) == {"provider_requirement", "task_requirement", "tool_declaration", "runtime_observation"}, "contract sources must be separate")
    for contract in action["contracts"].values():
        require(isinstance(contract, dict), "invalid contract")
        for key, item in contract.items():
            require(text(key), "empty contract field")
            validate_slot(item)
    require(isinstance(action["pathway"], dict) and set(action["pathway"]) in ({"interface", "protocol", "placement"}, {"interface", "actuator", "protocol", "placement"}), "invalid pathway")
    from consistency.behavior_matrix import VOCABULARIES
    for key, value in action["pathway"].items():
        if key == "actuator":
            require(value in {"filesystem", "process", "browser", "database", "application_api", "value_transform", "unknown"}, "invalid actuator")
        else:
            require(value in VOCABULARIES[key], f"invalid pathway {key}")
    require(isinstance(action["fragments"], list), "fragments must be a list")
    seen = set()
    for fragment in action["fragments"]:
        require(isinstance(fragment, dict) and set(fragment) == {"id", "operation", "source_ref", "basis"}, "invalid fragment")
        require(text(fragment["id"]) and fragment["id"] not in seen, "duplicate/empty fragment id")
        seen.add(fragment["id"])
        require(fragment["operation"] in OPERATIONS and text(fragment["source_ref"]), "fragment needs operation and source")
        require(fragment["basis"] in {"submitted_program", "observed_execution", "inferred"}, "invalid fragment basis")
    require(not seen or action["structure"] == "composite", "fragments require composite invocation")
    return deepcopy(action)


def field_comparison(left, right, field):
    """Content-only comparison. Never interpreted as an evidence-backed verdict."""
    validate_action(left)
    validate_action(right)
    if left["profile"] != right["profile"] or left["profile"] == "unsupported":
        return "unknown"
    comparisons = []
    for key in (field, *COMPARISON_CONTEXTS.get(left["profile"], {}).get(field, ())):
        a, b = left["fields"].get(key), right["fields"].get(key)
        if not a or not b or a["status"] != "known" or b["status"] != "known":
            return "unknown"
        comparisons.append(a["type"] == b["type"] and canonical(a["value"]) == canonical(b["value"]))
    return "equal" if all(comparisons) else "different"


def behavior_projection(actions, edges=()):
    """Six-axis view of IR, retaining role/level and edge basis. Not v1 relabeling.

    Empty observed windows are legal; no fake 'no-op action' is inserted.
    Inferred edges do not become verified dependencies or imply concurrency.
    """
    items = [validate_action(a) for a in actions]
    ids = {a["id"] for a in items}
    require(len(ids) == len(items), "duplicate action id")
    by_id = {a["id"]: a for a in items}
    clean_edges = []
    for edge in edges:
        require(isinstance(edge, dict) and set(edge) == {"source", "target", "relation", "basis", "refs"}, "invalid edge")
        require(edge["source"] in ids and edge["target"] in ids and edge["source"] != edge["target"], "dangling/self edge")
        require(by_id[edge["source"]]["scope"] == by_id[edge["target"]]["scope"], "cross-scope edge")
        require(edge["relation"] in {"observed_sequence", "data", "spawn", "callback", "retry_of", "member_of"}, "invalid relation")
        require(edge["basis"] in {"observed", "declared", "inferred"}, "edge basis required")
        require(isinstance(edge["refs"], list) and edge["refs"] and all(text(x) for x in edge["refs"]), "edge source refs required")
        clean_edges.append(deepcopy(edge))
    unique = lambda xs: [json.loads(x) for x in sorted({canonical(x) for x in xs})]
    return {"schema_version": "behavior-projection-v1", "empty": not items,
            "D1_operation": unique({"operation": a["operation"], "stage": a["stage"], "structure": a["structure"], "plane": a["plane"]} for a in items),
            "D2_resource_scope": unique({"profile": a["profile"], "role": k, "kind": v["value"]["kind"] if v["status"] == "known" else "unknown"} for a in items for k, v in a["fields"].items() if v["type"] == "resource"),
            "D3_pathway": unique(a["pathway"] for a in items),
            "D4_orchestration": sorted(clean_edges, key=canonical),
            "D5_execution_contract": unique({"plane": a["plane"], "sources": a["contracts"]} for a in items),
            "D6_result_contract": unique({"profile": a["profile"], "fields": {k: v for k, v in a["fields"].items() if k.startswith("result_")}} for a in items)}
