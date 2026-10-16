import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import http

from detection.exact import load_registry
from detection.online import (
    inspect_anthropic_messages_payload,
    inspect_gemini_generate_content_payload,
    inspect_openai_chat_payload,
)


LOCK = threading.Lock()
REGISTRY = []
ENABLED = False
OUTPUT_DIR = Path("/artifacts/decisions")


def load(loader):
    global ENABLED, REGISTRY
    ENABLED = os.environ.get("AGENTDLP_ONLINE_BLOCK", "false").lower() == "true"
    if ENABLED:
        dataset = Path(os.environ["AGENTDLP_DATASET_PATH"])
        REGISTRY = load_registry(dataset)


def write_decision(record):
    run_id = os.environ.get("AGENTDLP_RUN_ID", "local")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / f"{run_id}.jsonl"
    with LOCK, path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def request(flow: http.HTTPFlow):
    if not ENABLED:
        return
    path = flow.request.path.split("?", 1)[0].rstrip("/")
    if path.endswith("/chat/completions"):
        protocol = "openai_chat"
        inspect_payload = inspect_openai_chat_payload
    elif path.endswith("/v1/messages"):
        protocol = "anthropic_messages"
        inspect_payload = inspect_anthropic_messages_payload
    elif path.endswith(":generateContent") or path.endswith(":streamGenerateContent"):
        protocol = "gemini_generate_content"
        inspect_payload = inspect_gemini_generate_content_payload
    else:
        return
    try:
        payload = json.loads((flow.request.raw_content or b"{}").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return
    result = inspect_payload(payload, REGISTRY)
    record = {
        "schema_version": 2,
        "run_id": os.environ.get("AGENTDLP_RUN_ID", "local"),
        "flow_id": flow.id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "method": flow.request.method,
        "host": flow.request.host,
        "path": flow.request.path,
        "protocol": protocol,
        **result,
    }
    write_decision(record)
    if result["decision"] != "block":
        return
    if protocol == "anthropic_messages":
        body = {
            "type": "error",
            "error": {
                "type": "permission_error",
                "message": "Outbound request blocked by AgentDLP exact source policy",
            },
            "flow_id": flow.id,
        }
    elif protocol == "gemini_generate_content":
        body = {
            "error": {
                "code": 403,
                "message": "Outbound request blocked by AgentDLP exact source policy",
                "status": "PERMISSION_DENIED",
            },
            "flow_id": flow.id,
        }
    else:
        body = {
            "error": {
                "type": "agentdlp_policy_block",
                "message": "Outbound request blocked by exact source policy",
                "flow_id": flow.id,
            }
        }
    flow.response = http.Response.make(
        403,
        json.dumps(body),
        {"Content-Type": "application/json"},
    )
