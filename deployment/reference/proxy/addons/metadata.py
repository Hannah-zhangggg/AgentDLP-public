from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from mitmproxy import http, io
except ModuleNotFoundError:  # pragma: no cover - hooks require Mitmproxy at runtime
    http = None
    io = None


SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-goog-api-key",
}
SENSITIVE_QUERY_FIELDS = {
    "access_token",
    "api_key",
    "apikey",
    "key",
    "token",
    "x-goog-api-key",
}
OUTPUT_DIR = Path("/artifacts/metadata")
LOCK = threading.Lock()
FLOW_HANDLE = None
FLOW_WRITER = None


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def proxy_principal(value):
    if not value or not value.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(value.split(None, 1)[1]).decode("utf-8")
        return decoded.split(":", 1)[0]
    except (ValueError, UnicodeDecodeError):
        return "unparseable"


def redact_headers(headers):
    result = {}
    for name, value in headers.items(multi=True):
        lowered = name.lower()
        if lowered in SENSITIVE_HEADERS:
            result[name] = "[REDACTED]"
        else:
            result[name] = value
    return result


def redact_query(path):
    parts = urlsplit(path)
    if not parts.query:
        return path
    query = [
        (name, "[REDACTED]" if name.lower() in SENSITIVE_QUERY_FIELDS else value)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def preview(content, limit=512):
    if not content:
        return ""
    text = content[:limit].decode("utf-8", errors="replace")
    return text.replace("\r", "\\r").replace("\n", "\\n")


def write_record(record):
    run_id = os.environ.get("AGENTDLP_RUN_ID", "local")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIR / f"{run_id}.jsonl"
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    with LOCK, output.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def redact_flow_headers(flow):
    if flow.request:
        for name in list(flow.request.headers.keys()):
            if name.lower() in SENSITIVE_HEADERS:
                flow.request.headers[name] = "[REDACTED]"
    if flow.response:
        for name in list(flow.response.headers.keys()):
            if name.lower() in SENSITIVE_HEADERS:
                flow.response.headers[name] = "[REDACTED]"
    if flow.request:
        flow.request.path = redact_query(flow.request.path)


def write_redacted_flow(flow):
    global FLOW_HANDLE, FLOW_WRITER
    if io is None:
        raise RuntimeError("Mitmproxy is required to write redacted flows")
    if FLOW_WRITER is None:
        run_id = os.environ.get("AGENTDLP_RUN_ID", "local")
        flow_path = Path("/artifacts/flows") / f"{run_id}.flow"
        flow_path.parent.mkdir(parents=True, exist_ok=True)
        FLOW_HANDLE = flow_path.open("wb")
        FLOW_WRITER = io.FlowWriter(FLOW_HANDLE)
    safe_flow = copy.deepcopy(flow)
    redact_flow_headers(safe_flow)
    with LOCK:
        FLOW_WRITER.add(safe_flow)
        FLOW_HANDLE.flush()


def requestheaders(flow: http.HTTPFlow):
    value = flow.request.headers.get("Proxy-Authorization")
    flow.metadata["agentdlp_proxy_principal"] = proxy_principal(value)
    for name in list(flow.request.headers.keys()):
        if name.lower() == "proxy-authorization":
            del flow.request.headers[name]


def response(flow: http.HTTPFlow):
    request_body = flow.request.raw_content or b""
    response_body = flow.response.raw_content or b""
    record = {
        "schema_version": 1,
        "run_id": os.environ.get("AGENTDLP_RUN_ID", "local"),
        "harness_id": os.environ.get("AGENTDLP_HARNESS_ID", "unknown"),
        "proxy_principal": flow.metadata.get("agentdlp_proxy_principal"),
        "flow_id": flow.id,
        "timestamp_recorded": now_iso(),
        "timestamp_start": flow.request.timestamp_start,
        "timestamp_end": flow.response.timestamp_end,
        "client_addr": flow.client_conn.address,
        "server_addr": flow.server_conn.address,
        "method": flow.request.method,
        "scheme": flow.request.scheme,
        "host": flow.request.host,
        "port": flow.request.port,
        "path": redact_query(flow.request.path),
        "status_code": flow.response.status_code,
        "request_headers": redact_headers(flow.request.headers),
        "response_headers": redact_headers(flow.response.headers),
        "request_bytes": len(request_body),
        "response_bytes": len(response_body),
        "request_body_sha256": sha256(request_body),
        "response_body_sha256": sha256(response_body),
        "request_preview": preview(request_body),
        "response_preview": preview(response_body),
    }
    write_record(record)
    write_redacted_flow(flow)


def error(flow: http.HTTPFlow):
    write_record(
        {
            "schema_version": 1,
            "run_id": os.environ.get("AGENTDLP_RUN_ID", "local"),
            "harness_id": os.environ.get("AGENTDLP_HARNESS_ID", "unknown"),
            "proxy_principal": flow.metadata.get("agentdlp_proxy_principal"),
            "flow_id": flow.id,
            "timestamp_recorded": now_iso(),
            "method": flow.request.method if flow.request else None,
            "host": flow.request.host if flow.request else None,
            "path": flow.request.path if flow.request else None,
            "error": str(flow.error),
        }
    )
    write_redacted_flow(flow)


def done():
    global FLOW_HANDLE
    if FLOW_HANDLE is not None:
        FLOW_HANDLE.close()
        FLOW_HANDLE = None
