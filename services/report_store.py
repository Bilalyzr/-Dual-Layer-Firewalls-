"""
Report store — append-only JSONL history of every test/battery run.

Personal-use analytics: the pytest hooks (tests/conftest.py,
engine/tests/conftest.py) append one record per suite run, the red-team
battery appends its verdict counts, and GET /reports visualizes the lot.
Zero infrastructure — one newline-delimited JSON file.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from core.config import ROOT

# Stable repo path — deliberately NOT derived from SETTINGS.audit_sqlite_path
# (tests pin that to a throwaway temp dir, which would discard each record).
HISTORY_PATH = ROOT / "data" / "reports" / "history.jsonl"


def append_record(kind: str, **data: Any) -> dict:
    """Append one run record; returns it. Never raises (reporting is
    best-effort — a metrics hiccup must not fail a test suite)."""
    rec = {"ts": time.time(), "kind": kind, **data}
    try:
        HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
        with HISTORY_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except Exception:
        pass
    return rec


def read_all(limit: int = 500) -> list[dict]:
    """Newest-last run records (oldest first for charting)."""
    try:
        lines = HISTORY_PATH.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out: list[dict] = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out
