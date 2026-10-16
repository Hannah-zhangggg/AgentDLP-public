"""Build a new, hashed stage without changing frozen v5.0.1 data or code."""
import argparse
import json
from pathlib import Path
import shutil

from consistency.dataset_v5.common import ROOT, canonical, file_hash, write
from consistency.dataset_v5.sources import workflows
from consistency.harness.v5_vm_runtime import mutate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    tasks = workflows()
    plans, endpoint, rows = {}, {}, []
    variants = [(w, "baseline") for w in tasks]
    for kind in ("argument", "target", "skip", "extra", "operation", "result"):
        variants += [(w, kind) for w in tasks]
    # Distinct mechanisms/benign controls, not a claim of exhaustive taxonomy.
    for kind in ("reverse_order", "partial_dispatch", "stale_result"):
        variants += [(w, kind) for w in tasks[:3]]
    variants += [(w, kind) for kind in ("nested_envelope", "blocked_extra") for w in tasks]
    for w, kind in variants:
        run = "v5vm-" + w["name"].replace("_", "-") + "-" + kind.replace("_", "-")
        calls = [dict(c, id=f"call-{i}", require_success=True, result_policy="exact_tool_return") for i, c in enumerate(w["calls"])]
        try:
            mutate(calls, kind)
        except ValueError as exc:
            rows.append({"run_id": run, "workflow": w["name"], "kind": kind, "status": "not_applicable", "reason": str(exc)})
            continue
        contract = {"format": "v5-controlled-provider@1", "calls": calls,
                    "required_order": [[f"call-{i}", f"call-{i+1}"] for i in range(len(calls)-1)]}
        plans[run] = contract
        verifier = w["name"] + ".py" if w["source"]["source"] == "MCPMark" else None
        endpoint[run] = {"kind": kind, "initial_files": w["initial_files"], "initial_objects": w["initial_objects"], "verifier": verifier}
        rows.append({"run_id": run, "workflow": w["name"], "kind": kind, "status": "planned", "source": w["source"]})
    for role in ("endpoint", "external"):
        stage = out / role
        for rel in ("consistency/__init__.py", "consistency/dataset_v5/__init__.py", "consistency/dataset_v5/common.py",
                    "consistency/dataset_v5/worker.py", "consistency/harness/v5_vm_runtime.py"):
            target = stage / "app" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, target)
    for w in tasks[:3]:
        target = out / "endpoint/verifiers" / (w["name"] + ".py")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(w["source"]["verifier"]["path"], target)
    write(out / "external/provider-plans.json", plans)
    write(out / "endpoint/endpoint-cases.json", endpoint)
    hashes = {str(p.relative_to(out)): file_hash(p) for p in sorted(out.rglob("*")) if p.is_file()}
    write(out / "manifest.json", {"schema": "v5vm-exploratory-pilot@1", "harness": "controlled_native_not_opencode",
        "execution_scope": "real_provider_network_with_local_native_tools", "cases": rows, "sha256": hashes,
        "formal_accuracy_benchmark": False, "provider_receives_fault_plan": False})
    print(canonical({"planned": len(plans), "not_applicable": len(rows)-len(plans)}))


if __name__ == "__main__":
    main()
