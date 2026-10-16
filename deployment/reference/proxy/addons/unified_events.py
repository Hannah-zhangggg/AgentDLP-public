from __future__ import annotations

import os
from pathlib import Path

from mitmproxy import http

from normalization.core.event_log import append_events
from normalization.core.event_pipeline import UnifiedEventPipeline
from normalization.readers import canonical_http_flow


ENABLED = True
PIPELINE = UnifiedEventPipeline()


def load(loader):
    global ENABLED
    ENABLED = os.environ.get("AGENTDLP_EVENT_LOG", "true").lower() == "true"


def _write(flow: http.HTTPFlow):
    if not ENABLED or flow.metadata.get("agentdlp_unified_events_written"):
        return
    run_id = os.environ.get("AGENTDLP_RUN_ID", "local")
    harness_id = os.environ.get("AGENTDLP_HARNESS_ID", "unknown")
    workload_id = os.environ.get("AGENTDLP_WORKLOAD_ID", harness_id)
    session_id = os.environ.get("AGENTDLP_SESSION_ID") or None
    canonical = canonical_http_flow(
        flow,
        run_id,
        harness_id,
        workload_id=workload_id,
        session_id=session_id,
    )
    output_dir = Path(os.environ.get("AGENTDLP_EVENT_DIR", "/artifacts/events"))
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{run_id}.jsonl"
    append_events(output, PIPELINE.normalize(canonical))
    flow.metadata["agentdlp_unified_events_written"] = True


def response(flow: http.HTTPFlow):
    _write(flow)


def error(flow: http.HTTPFlow):
    _write(flow)
