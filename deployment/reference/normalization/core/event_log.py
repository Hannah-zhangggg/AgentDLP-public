from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Iterable

from normalization.core.models import UnifiedEvent


_LOCK = threading.Lock()


def append_events(path: Path, events: Iterable[UnifiedEvent]) -> None:
    """Append complete JSONL records under a process-local lock."""
    lines = [json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")) for event in events]
    if not lines:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, path.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")
