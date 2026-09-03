"""
Export the personal test report as a STANDALONE HTML file.

All data (suite runs, battery history, model versions, training balance) is
EMBEDDED as JSON inside the page — open it by double-click, share it, no
server and no network needed.

    python scripts/export_report.py                 # -> data/reports/report.html
    python scripts/export_report.py --out my.html   # custom path
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def collect() -> dict:
    from services import audit_log, realtime_learner, report_store
    from services.audit_log import latest_model_version

    audit_log.init()
    data: dict = {
        "runs": report_store.read_all(),
        "model_versions": [],
        "current_version": {},
        "store": {},
    }
    data["total_runs"] = len(data["runs"])
    data["latest_ts"] = data["runs"][-1]["ts"] if data["runs"] else None
    try:
        data["current_version"] = latest_model_version() or {}
    except Exception:
        pass
    try:
        data["model_versions"] = audit_log.list_model_versions(limit=40)
    except Exception:
        pass
    try:
        st = realtime_learner.stats()
        s = st.get("samples", {})
        data["store"] = {
            "total": s.get("total", 0), "threat": s.get("threat", 0),
            "benign": s.get("benign", 0),
            "last_retrain": (st.get("auto_train", {}).get("last_retrain") or {}).get("at"),
        }
    except Exception:
        pass
    return data


def render(data: dict) -> str:
    from services.report_page import PAGE

    payload = json.dumps(data, default=str)
    page = PAGE.replace(
        "fetch('/reports/data').then(r => r.json()).then(d => {",
        "const EMBEDDED = " + payload + ";\nPromise.resolve(EMBEDDED).then(d => {",
    )
    page = page.replace(
        "· data: data/reports/history.jsonl",
        "· standalone export — data embedded at generation time",
    )
    return page


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(ROOT / "data" / "reports" / "report.html"))
    args = ap.parse_args()

    data = collect()
    html = render(data)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    size_kb = out.stat().st_size / 1024
    bats = sum(1 for r in data["runs"] if r["kind"] == "battery")
    print(f"✓ {out}")
    print(f"  {data['total_runs']} runs ({bats} batteries) · "
          f"{len(data['model_versions'])} model versions · "
          f"store {data['store'].get('total', 0)} samples · {size_kb:.0f} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
