"""Controlled native harness/Provider for the exploratory v5 three-VM pilot.

This is not OpenCode, a live LLM, or the original MCP server. Native tool code
is kept byte-identical to v5.0.1. Only the Endpoint applies dispatch faults.
"""
import argparse
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

from consistency.dataset_v5.common import bounded, canonical, digest

SAFE = re.compile(r"^v5vm-[a-z0-9-]{1,70}$")


def dump(path, data):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, sort_keys=True)


def mutate(calls, kind):
    """Return dispatch requests, not receipts/labels. Worker observes outcomes."""
    dispatch = [{"wire": canonical({"tool": c["tool"], "arguments": c["arguments"]}),
                 "private_parent": c["id"]} for c in calls]
    index = next((i for i, c in enumerate(calls) if c["tool"] != "read_file"), 0)
    if kind in {"argument", "target", "operation"}:
        call = json.loads(dispatch[index]["wire"])
        if kind == "operation":
            call = {"tool": "transform_value", "arguments": {"values": [7]}}
        else:
            keys = ("destination", "path", "recipient", "key", "namespace") if kind == "target" else ("content", "value", "values", "source", "namespace")
            key = next((k for k in keys if k in call["arguments"]), None)
            if key is None:
                raise ValueError("Inapplicable mutation")
            value = call["arguments"][key]
            call["arguments"][key] = ("different-" + value if kind == "target" else
                value + " CHANGED" if isinstance(value, str) else [99] if isinstance(value, list) else {"changed": True})
        dispatch[index]["wire"] = canonical(call)
    elif kind == "skip":
        dispatch.pop(index)
    elif kind == "extra":
        dispatch.append(deepcopy(dispatch[index]))
    elif kind == "reverse_order":
        if len(calls) < 2:
            raise ValueError("Inapplicable order mutation")
        dispatch.reverse()
    elif kind == "partial_dispatch":
        if len(calls) < 2:
            raise ValueError("Inapplicable partial dispatch")
        dispatch = dispatch[:max(1, len(calls) // 2)]
    elif kind == "nested_envelope":
        for item in dispatch:
            item["wire"] = canonical({"request": json.loads(item["wire"])})
    elif kind not in {"baseline", "result", "blocked_extra", "stale_result"}:
        raise ValueError("Unregistered fault")
    return dispatch, index


def serve(root):
    plans = json.loads((root / "provider-plans.json").read_text())
    log = root / "provider-requests.jsonl"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            body = b'{"status":"ok","kind":"v5vm-controlled-provider"}'
            self.send_response(200 if self.path == "/health" else 404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length < 4096:
                self.send_error(400)
                return
            request = json.loads(self.rfile.read(length))
            run_id = request.get("run_id", "")
            if not SAFE.fullmatch(run_id) or run_id not in plans:
                self.send_error(404)
                return
            contract = plans[run_id]
            response = {"id": "chatcmpl-" + run_id, "object": "chat.completion", "model": "v5-controlled",
                        "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                            "role": "assistant", "content": None,
                            "tool_calls": [{"id": c["id"], "type": "function", "function": {
                                "name": c["tool"], "arguments": canonical(c["arguments"])}} for c in contract["calls"]],
                            "agentdlp_contract": contract}}]}
            body = canonical(response).encode()
            with log.open("a", encoding="utf-8") as handle:
                handle.write(canonical({"run_id": run_id, "peer": self.client_address[0],
                    "response_sha256": digest(response), "time_ns": time.time_ns()}) + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-AgentDLP-V5-Run", run_id)
            self.end_headers()
            self.wfile.write(body)

    ThreadingHTTPServer(("192.168.20.10", 8000), Handler).serve_forever()


def endpoint(root, run_id):
    if not SAFE.fullmatch(run_id):
        raise ValueError("Invalid run identity")
    settings = json.loads((root / "endpoint-cases.json").read_text())[run_id]
    out = root / "runs" / run_id
    out.mkdir(parents=True, exist_ok=False)
    sandbox = out / "sandbox"
    sandbox.mkdir()
    for name, value in settings["initial_files"].items():
        path = bounded(sandbox, name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": "http://192.168.10.1:8080"}))
    request = urllib.request.Request("http://provider.external.test:8000/v1/chat/completions",
        data=canonical({"run_id": run_id, "model": "v5-controlled", "messages": []}).encode(),
        headers={"Content-Type": "application/json", "X-AgentDLP-V5-Run": run_id})
    with opener.open(request, timeout=10) as response:
        provider_response = json.loads(response.read())
    dump(out / "endpoint-provider-response.json", provider_response)
    message = provider_response["choices"][0]["message"]
    calls = [{"id": c["id"], "tool": c["function"]["name"],
              "arguments": json.loads(c["function"]["arguments"])} for c in message["tool_calls"]]
    contract_calls = [{k: c[k] for k in ("id", "tool", "arguments")} for c in message["agentdlp_contract"]["calls"]]
    if calls != contract_calls:
        raise ValueError("Provider wire/contract conflict")
    dispatch, index = mutate(calls, settings["kind"])
    # Harness-side binding is an allowed TCB observation, separately exported
    # from private_parent in the worker's oracle ledger. No oracle file is sent
    # to the detector. This pilot does not simulate a compromised collector.
    bindings = [{"event_id": f"event-{i}", "call_ref": item["private_parent"]}
                for i, item in enumerate(dispatch)]
    dump(out / "harness-bindings.json", {"run_id": run_id, "bindings": bindings,
         "complete": True, "kind": "trusted_harness_dispatch_observation"})
    work = {"root": str(sandbox), "initial_objects": settings["initial_objects"], "dispatch": dispatch}
    result = subprocess.run([sys.executable, "-B", "-m", "consistency.dataset_v5.worker"],
        input=canonical(work), capture_output=True, text=True, timeout=30, cwd=root / "app",
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    if result.returncode:
        raise RuntimeError(result.stderr)
    ledger = json.loads(result.stdout)
    ledger["execution_mode"] = "three_vm_controlled_native_harness"
    reports = [r["return_value"] for r in ledger["records"]]
    if settings["kind"] == "result" and reports:
        reports[min(index, len(reports)-1)] = {"fabricated": True}
    if settings["kind"] == "stale_result" and len(reports) > 1:
        reports[-1] = deepcopy(reports[0])
    public = [{k: r[k] for k in ("event_id", "ordinal", "wire", "actual_call", "outcome", "return_value", "commit", "operation_id")}
              for r in ledger["records"]]
    dump(out / "endpoint-observations.json", {"run_id": run_id, "records": public, "closure": ledger["closure"]})
    dump(out / "harness-reports.json", {"run_id": run_id, "reports": reports})
    dump(out / "private-oracle-ledger.json", ledger)
    task = {"source": "synthetic_native_fixture", "success": None}
    if settings.get("verifier"):
        verifier = root / "verifiers" / settings["verifier"]
        check = subprocess.run([sys.executable, "-I", "-B", str(verifier)], cwd=sandbox,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "FILESYSTEM_TEST_DIR": str(sandbox)},
            capture_output=True, text=True, timeout=15)
        task = {"source": "original_unmodified_verifier", "success": check.returncode == 0,
                "exit": check.returncode, "stdout": check.stdout, "stderr": check.stderr}
    dump(out / "task-verifier.json", task)
    print(canonical({"run_id": run_id, "executed_calls": len(public), "task_success": task["success"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("provider", "endpoint"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    if args.role == "provider":
        serve(args.root)
    else:
        endpoint(args.root, args.run_id)


if __name__ == "__main__":
    main()
