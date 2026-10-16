#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from normalization.core.event_log import append_events
from normalization.endpoint_events import stdio_mcp_message_to_event


def parse_args():
    parser = argparse.ArgumentParser(description="Relay and record a local MCP stdio transport")
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
        parser.error("a server command is required after --")
    return args


def main() -> int:
    args = parse_args()
    defaults = {
        "run_id": args.run_id,
        "session_id": args.session_id,
        "harness_id": args.harness_id,
        "workload_id": args.workload_id or args.harness_id,
    }
    child = subprocess.Popen(args.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    process = {"pid": child.pid, "ppid": os.getpid(), "executable": args.command[0]}

    def relay_requests() -> None:
        assert child.stdin is not None
        for line in sys.stdin.buffer:
            append_events(args.event_file, [stdio_mcp_message_to_event(
                line.rstrip(b"\r\n"), direction="request", timestamp=time.time(),
                process=process, defaults=defaults, tool_call_id=args.tool_call_id,
            )])
            try:
                child.stdin.write(line)
                child.stdin.flush()
            except BrokenPipeError:
                break
        try:
            child.stdin.close()
        except BrokenPipeError:
            pass

    request_thread = threading.Thread(target=relay_requests, name="agentdlp-mcp-stdin", daemon=True)
    request_thread.start()
    assert child.stdout is not None
    for line in child.stdout:
        append_events(args.event_file, [stdio_mcp_message_to_event(
            line.rstrip(b"\r\n"), direction="response", timestamp=time.time(),
            process=process, defaults=defaults, tool_call_id=args.tool_call_id,
        )])
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()
    return child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
