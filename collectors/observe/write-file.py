#!/usr/bin/env python3
"""Write one workspace-local file and record the completed endpoint effect."""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from normalization.core.event_log import append_events
from normalization.endpoint_events import local_file_write_event


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-file", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--path", required=True, help="relative path below --workspace-root")
    parser.add_argument("--mode", choices=("create", "replace", "append"), default="create")
    parser.add_argument("--text", help="synthetic content to write instead of stdin")
    parser.add_argument("--result-marker", help="print this marker only after the event is committed")
    parser.add_argument(
        "--tool-call-id",
        default=os.environ.get("AGENTDLP_TOOL_CALL_ID") or None,
        required=os.environ.get("AGENTDLP_TOOL_CALL_ID") is None,
        help="Provider/Agent tool-call ID established by the caller",
    )
    parser.add_argument("--run-id", default=os.environ.get("AGENTDLP_RUN_ID", "local"))
    parser.add_argument("--session-id", default=os.environ.get("AGENTDLP_SESSION_ID") or None)
    parser.add_argument("--harness-id", default=os.environ.get("AGENTDLP_HARNESS_ID", "unknown"))
    parser.add_argument("--workload-id", default=os.environ.get("AGENTDLP_WORKLOAD_ID"))
    return parser.parse_args()


def resolve_target(workspace_root: Path, supplied_path: str) -> Path:
    root = workspace_root.resolve()
    relative = Path(supplied_path)
    if relative.is_absolute():
        raise ValueError("--path must be relative to --workspace-root")
    target = (root / relative).resolve()
    if target == root or root not in target.parents:
        raise ValueError("--path escapes --workspace-root")
    if not target.parent.is_dir():
        raise ValueError("target parent must already exist")
    return target


def main() -> int:
    args = parse_args()
    try:
        target = resolve_target(args.workspace_root, args.path)
    except ValueError as exc:
        print(f"write-file: {exc}", file=sys.stderr)
        return 2
    content = args.text.encode("utf-8") if args.text is not None else sys.stdin.buffer.read()
    open_mode = {"create": "xb", "replace": "wb", "append": "ab"}[args.mode]
    try:
        with target.open(open_mode) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        print(f"write-file: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    defaults = {
        "run_id": args.run_id,
        "session_id": args.session_id,
        "harness_id": args.harness_id,
        "workload_id": args.workload_id or args.harness_id,
    }
    append_events(args.event_file, [local_file_write_event(
        path=str(target),
        content=content,
        pid=os.getpid(),
        ppid=os.getppid(),
        mode=args.mode,
        timestamp=time.time(),
        defaults=defaults,
        tool_call_id=args.tool_call_id,
    )])
    if args.result_marker:
        print(args.result_marker, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
