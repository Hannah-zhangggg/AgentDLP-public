#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from normalization.core.event_log import append_events
from normalization.endpoint_events import local_process_event


def parse_args():
    parser = argparse.ArgumentParser(description="Run one local tool and emit start/end unified events")
    parser.add_argument("--event-file", type=Path, required=True)
    parser.add_argument("--run-id", default=os.environ.get("AGENTDLP_RUN_ID", "local"))
    parser.add_argument("--session-id", default=os.environ.get("AGENTDLP_SESSION_ID") or None)
    parser.add_argument("--harness-id", default=os.environ.get("AGENTDLP_HARNESS_ID", "unknown"))
    parser.add_argument("--workload-id", default=os.environ.get("AGENTDLP_WORKLOAD_ID"))
    parser.add_argument(
        "--tool-call-id",
        default=os.environ.get("AGENTDLP_TOOL_CALL_ID") or None,
        help="Provider/Agent tool-call ID established by the caller",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    return args


def main() -> int:
    args = parse_args()
    defaults = {
        "run_id": args.run_id,
        "session_id": args.session_id,
        "harness_id": args.harness_id,
        "workload_id": args.workload_id or args.harness_id,
    }
    child = subprocess.Popen(args.command)
    common = {
        "executable": args.command[0], "argv": args.command, "pid": child.pid,
        "ppid": os.getpid(), "defaults": defaults,
        "tool_call_id": args.tool_call_id,
    }
    append_events(args.event_file, [local_process_event(phase="start", timestamp=time.time(), **common)])
    returncode = child.wait()
    append_events(args.event_file, [local_process_event(
        phase="end", timestamp=time.time(), returncode=returncode, **common,
    )])
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
