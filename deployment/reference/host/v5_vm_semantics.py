"""Pilot loader: SSH-authenticated raw files -> IR, behavior graph, claim matrix.

The Windows-host retrieval manifest is TCB input, not a self-signed tool claim.
Fixed role grants authorize observations; a file hash alone is not authority.
Private oracle/state files and fault plans are never inputs to this module.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from consistency.behavior_matrix_v2 import classify_behavior
from consistency.evidence_matrix import TrustPolicy, assess, digest
from consistency.semantic_adapters import adapt_tool_call
from consistency.semantic_model import canonical, slot, validate_action

KEYS = {
    "gateway": "246fa47e239319d1cfa56897460699e8b602827c00e3aed046a403dae7930fff",
    "endpoint": "cc029db163b4caa4165c1d8d1b49f4f99f32792e3bcb3c6de243177073e6d65b",
}
GRANTS = frozenset({
    ("gateway-capture", "gateway", "expected", "field"),
    ("endpoint-tool-observer", "endpoint", "observed", "field"),
    ("endpoint-tool-observer", "endpoint", "observed", "commit"),
    ("endpoint-tool-observer", "endpoint", "observed", "window_closed"),
    ("harness-dispatch", "harness", "observed", "bound_to"),
})
FILES = {"gateway-capture.json": "gateway", "endpoint-observations.json": "endpoint",
         "harness-bindings.json": "endpoint", "harness-reports.json": "endpoint", "ebpf-events.jsonl": "endpoint"}


def read_authenticated(directory):
    manifest = json.loads((directory / "retrieval.json").read_text())
    if manifest.get("retriever") != "windows-host-pinned-ssh" or manifest.get("stage_verified") is not True:
        raise ValueError("Trusted retrieval manifest required")
    result = {}
    for name, role in FILES.items():
        entry = manifest["files"][name]
        if entry["role"] != role or entry["host_key_sha256"] != KEYS[role]:
            raise ValueError("Role/host-key mismatch")
        raw = (directory / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("Retrieved artifact changed: " + name)
        result[name] = raw
    return result, manifest


def analyze(directory):
    raw, manifest = read_authenticated(directory)
    run = manifest["run_id"]
    capture, observed, binding = (json.loads(raw[name]) for name in
        ("gateway-capture.json", "endpoint-observations.json", "harness-bindings.json"))
    if any(v["run_id"] != run for v in (capture, observed, binding)):
        raise ValueError("Run mismatch")
    if len(capture["flows"]) != 1 or capture["flows"][0]["status"] != 200:
        raise ValueError("Exactly one successful Gateway Provider capture required")
    flow = capture["flows"][0]
    if flow["request"].get("run_id") != run or flow["client_peer"][0] != "192.168.10.10" or flow["server_peer"][0] != "192.168.20.10":
        raise ValueError("Provider capture topology/run mismatch")
    message = flow["response"]["choices"][0]["message"]
    calls = [{"id": c["id"], "tool": c["function"]["name"], "arguments": json.loads(c["function"]["arguments"])} for c in message["tool_calls"]]
    contract = message["agentdlp_contract"]
    if calls != [{k: c[k] for k in ("id", "tool", "arguments")} for c in contract["calls"]]:
        raise ValueError("Captured Provider contract/wire disagreement")
    expected_contracts = {c["id"]: c for c in contract["calls"]}
    records = observed["records"]
    ids = [r["event_id"] for r in records]
    closed = observed["closure"].get("complete") is True and observed["closure"].get("event_ids") == ids and len(ids) == len(set(ids))
    if not closed:
        raise ValueError("Endpoint receipt closure incomplete/conflicting; loader refuses complete pilot view")
    bindings = {b["event_id"]: b["call_ref"] for b in binding["bindings"]}
    if len(bindings) != len(binding["bindings"]):
        raise ValueError("Conflicting bindings")
    actions, evidence, claims, edges = [], [], [], []

    def project(aid, call, expected, ref):
        action = adapt_tool_call(aid, call["tool"], call["arguments"], run=run, source_ref=ref)
        action.update(plane="expected" if expected else "observed", stage="instruction" if expected else "invocation")
        action["pathway"].update(interface="native", protocol="stdio", placement="same_host")
        action["fields"]["tool_version"] = slot("v5.0.1-pinned-worker", refs=["retrieval.json#stage"])
        # These facts follow the pinned native implementation, not tool names.
        if action["profile"] == "file.read@1":
            action["fields"]["range"] = slot({"mode": "whole_file"}, type="json", refs=[ref])
        if action["profile"] == "file.write@1":
            action["fields"]["overwrite"] = slot(True, type="boolean", refs=[ref])
        if action["profile"] == "file.move@1":
            action["fields"]["overwrite"] = slot(True, type="boolean", refs=[ref])
        if not expected:
            action["invocation_id"] = aid
        return action

    def fact(action, predicate, value, filename, observer, layer, index):
        item = {"id": "e-" + str(len(evidence)), "subject": action["id"], "scope": deepcopy(action["scope"]),
            "window_id": run, "predicate": predicate, "value": deepcopy(value),
            "source": {"observer": observer, "layer": layer, "raw_ref": filename + "#" + str(index),
                       "raw_sha256": manifest["files"][filename]["sha256"]},
            "position": {"clock": "gateway" if layer == "gateway" else "endpoint", "sequence": index, "timestamp": None},
            "basis": "direct", "integrity": {"loss": False, "duplicate": False, "conflict": False}}
        evidence.append(item)

    expected_by_call = {}
    for i, call in enumerate(calls):
        action = project("instruction-" + call["id"], call, True, "gateway-capture.json#" + str(i))
        requirement = expected_contracts[call["id"]]
        action["contracts"]["provider_requirement"] = {
            "completion": slot("success" if requirement["require_success"] else "attempt"),
            "result_transform": slot("exact"), "result_binding": slot("invocation"), "result_channel": slot("tool_return")}
        if call["tool"] in {"write_file", "move_file", "set_object", "send_message"} and requirement["require_success"]:
            action["fields"]["required_effect_count"] = slot(1, type="integer")
        action = validate_action(action)
        expected_by_call[call["id"]] = action
        actions.append(action)
        for field, value in action["fields"].items():
            if value["status"] == "known" and field != "tool_version":
                fact(action, "field:" + field, {"type": value["type"], "value": value["value"]},
                     "gateway-capture.json", "gateway-capture", "gateway", i)
    for src, dst in contract["required_order"]:
        edges.append({"source": "instruction-" + src, "target": "instruction-" + dst,
                      "relation": "order", "basis": "declared", "refs": ["gateway-capture.json"]})
    observed_actions = []
    for i, record in enumerate(records):
        action = project("invocation-" + record["event_id"], record["actual_call"], False, "endpoint-observations.json#" + str(i))
        action["fields"]["result_value"] = slot(record["return_value"], type="json", refs=["endpoint-observations.json#" + str(i)])
        action["fields"]["result_mode"] = slot("value" if record["outcome"] == "success" else "error")
        actions.append(validate_action(action))
        observed_actions.append(action)
        for field, value in action["fields"].items():
            if value["status"] == "known" and field != "tool_version":
                fact(action, "field:" + field, {"type": value["type"], "value": value["value"]},
                     "endpoint-observations.json", "endpoint-tool-observer", "endpoint", i)
        parent = bindings.get(record["event_id"])
        if parent is not None:
            fact(action, "bound_to", "instruction-" + parent, "harness-bindings.json", "harness-dispatch", "harness", i)
        fields = set(action["fields"]) | set(expected_by_call.get(parent, {}).get("fields", {}))
        for field in sorted(fields - {"tool_version", "result_value", "result_mode", "required_effect_count"}):
            claims.append({"id": action["id"] + ":" + field, "kind": "field_matches_instruction",
                           "observed_id": action["id"], "field": field, "window_id": run})
        operations = []
        if record["commit"]:
            value = {"namespace": run + ":endpoint-tool", "operation_id": record["operation_id"]}
            operations.append(value)
            fact(action, "commit", value, "endpoint-observations.json", "endpoint-tool-observer", "endpoint", i)
        fact(action, "window_closed", {"predicate": "commit", "complete": closed, "operations": operations},
             "endpoint-observations.json", "endpoint-tool-observer", "endpoint", i)
        if "required_effect_count" in expected_by_call.get(parent, {}).get("fields", {}):
            claims.append({"id": action["id"] + ":count", "kind": "effect_count", "observed_id": action["id"],
                           "field": "required_effect_count", "window_id": run})
    for left, right in zip(observed_actions, observed_actions[1:]):
        edges.append({"source": left["id"], "target": right["id"], "relation": "observed_sequence",
                      "basis": "observed", "refs": ["endpoint-observations.json"]})
    policy = TrustPolicy({e["id"]: digest(e) for e in evidence}, GRANTS)
    report = assess(actions, evidence, claims, policy)
    return {"run_id": run, "behavior_matrix": classify_behavior(actions, edges),
            "semantic_actions": actions, "behavior_graph": {"nodes": [a["id"] for a in actions], "edges": edges},
            "evidence_matrix": report, "evidence_records": evidence, "whole_case_verdict": None,
            "limitations": ["Native tools only; non-file adapters mostly unsupported",
                "No whole-case missing/extra/order/result comparison in the two-claim engine",
                "Commit flag is tool implementation evidence, not independent application-effect proof",
                "Authenticated SSH exporter/harness/worker remain TCB; no hostile-observer test",
                "eBPF network evidence does not prove local filesystem/database semantics"]}
