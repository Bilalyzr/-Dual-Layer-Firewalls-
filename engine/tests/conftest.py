"""
Pytest configuration — make the repo root importable so tests can do
`from engine.classifier.model import ...` regardless of cwd.
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # .../dual-layer-firewall
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def pytest_sessionstart(session):
    session._dlf_start = time.time()


def pytest_sessionfinish(session, exitstatus):
    """Auto-record this suite run for the personal /reports dashboard."""
    try:
        from services import report_store

        r = session.config.pluginmanager.getplugin("terminalreporter")
        reps = getattr(r, "stats", {}) if r else {}
        failed = sum(len(v) for k, v in reps.items() if k in ("failed", "error"))
        passed = len(reps.get("passed", []))
        durations = [
            getattr(rep, "duration", 0.0)
            for v in reps.values() for rep in v
            if hasattr(rep, "duration")
        ]
        report_store.append_record(
            "pytest",
            suite="engine",
            passed=passed,
            failed=failed,
            exit=int(exitstatus),
            duration_s=round(time.time() - getattr(session, "_dlf_start", time.time()), 2),
            slowest_test=round(max(durations), 2) if durations else 0.0,
        )
    except Exception:
        pass
