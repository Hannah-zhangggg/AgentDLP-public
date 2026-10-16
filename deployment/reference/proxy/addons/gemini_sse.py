import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import http

from normalization.reassembly.gemini_sse import reconstruct_gemini_sse


ENABLED = False
LOCK = threading.Lock()
OUTPUT_DIR = Path("/artifacts/reassembled")


def load(loader):
    global ENABLED
    ENABLED = os.environ.get("AGENTDLP_REASSEMBLE_SSE", "false").lower() == "true"


def response(flow: http.HTTPFlow):
    if not ENABLED:
        return
    path = flow.request.path.split("?", 1)[0].rstrip("/")
    content_type = flow.response.headers.get("content-type", "").lower()
    if not path.endswith(":streamGenerateContent") or "text/event-stream" not in content_type:
        return
    body = flow.response.raw_content or b""
    result = reconstruct_gemini_sse(body)
    record = {
        "run_id": os.environ.get("AGENTDLP_RUN_ID", "local"),
        "flow_id": flow.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": flow.request.host,
        "path": flow.request.path,
        "status_code": flow.response.status_code,
        "response_bytes": len(body),
        "response_sha256": hashlib.sha256(body).hexdigest(),
        **result,
    }
    run_id = os.environ.get("AGENTDLP_RUN_ID", "local")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIR / f"{run_id}.jsonl"
    with LOCK, output.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
