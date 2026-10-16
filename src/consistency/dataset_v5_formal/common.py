"""Small data-only utilities; no imports from the detector."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "artifacts/reports"
SOURCES = REPORTS / "v5-formal-sources"
AUDIT_SOURCES = REPORTS / "behavior-matrix-public-audit-v1/sources"
MCP = AUDIT_SOURCES / "mcpmark"
TAU = SOURCES / "tau-bench"
APP = SOURCES / "appworld"

def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)

def digest(obj):
    return hashlib.sha256(canonical(obj).encode()).hexdigest()

def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def write(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def append(path, obj):
    with Path(path).open("a", encoding="utf-8") as f:
        f.write(canonical(obj) + "\n")

