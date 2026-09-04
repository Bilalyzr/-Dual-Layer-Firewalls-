"""
Export the personal test reports as STANDALONE HTML files.

All data (suite runs, battery history incl. per-case verdicts, model
versions, training balance) is EMBEDDED as JSON inside each page — open by
double-click, share, no server and no network needed.

    python scripts/export_report.py
      -> data/reports/report.html          (metrics dashboard)
      -> data/reports/testcase_report.html (formal TC-table QA report)
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


def render(data: dict) -> tuple[str, str]:
    """Returns (dashboard_html, testcase_html) — both fully standalone."""
    from services.report_page import PAGE as DASH
    from services.testcase_page import PAGE as TC

    payload = json.dumps(data, default=str)
    embedded = "const EMBEDDED = " + payload + ";\nPromise.resolve(EMBEDDED).then(d => {"
    dash = DASH.replace(
        "fetch('/reports/data').then(r => r.json()).then(d => {", embedded)
    dash = dash.replace(
        "· data: data/reports/history.jsonl",
        "· standalone export — data embedded at generation time",
    )
    tc = TC.replace(
        "fetch('/reports/data').then(r => r.json()).then(d => {", embedded)
    return dash, tc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(ROOT / "data" / "reports" / "report.html"))
    ap.add_argument("--tc-out", default=str(ROOT / "data" / "reports" / "testcase_report.html"))
    args = ap.parse_args()

    data = collect()
    dash_html, tc_html = render(data)
    for path, html in ((args.out, dash_html), (args.tc_out, tc_html)):
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(html, encoding="utf-8")
    size_kb = Path(args.tc_out).stat().st_size / 1024
    bats = sum(1 for r in data["runs"] if r["kind"] == "battery")
    print(f"✓ {args.out}          (metrics dashboard)")
    print(f"✓ {args.tc_out}  (test-case report, {size_kb:.0f} KB)")
    print(f"  {data['total_runs']} runs ({bats} batteries) · "
          f"{len(data['model_versions'])} model versions · "
          f"store {data['store'].get('total', 0)} samples")
    return 0


if __name__ == "__main__":
    sys.exit(main())
