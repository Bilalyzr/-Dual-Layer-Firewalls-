import os
import sys
import tempfile
import time
from pathlib import Path

# Tests run fully hermetic — no real stores, no real providers:
#   * audit DB  -> throwaway SQLite per run (a previous long run left test
#                  users banned in the real file, breaking later assertions)
#   * redis     -> unreachable port = in-memory fallback (a live Docker Redis
#                  persists strikes/timelines across runs the same way)
#   * LLM       -> offline responder (instant, network-independent)
# Process env wins over .env/.env.local (see core/config.py precedence).
os.environ["AUDIT_DSN"] = ""
os.environ["AUDIT_SQLITE_PATH"] = str(Path(tempfile.mkdtemp(prefix="dlf-test-")) / "audit.db")
os.environ["REDIS_URL"] = "redis://127.0.0.1:1/0"
os.environ["LLM_BASE_URL"] = ""
os.environ["LLM_API_KEY"] = ""
os.environ["LLM_FALLBACK_URL"] = ""
os.environ["LLM_OFFLINE_ECHO"] = "true"

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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
        t0 = getattr(session, "_dlf_start", None)
        report_store.append_record(
            "pytest",
            suite="firewall-v2",
            passed=passed,
            failed=failed,
            exit=int(exitstatus),
            duration_s=round(time.time() - getattr(session, "_dlf_start", time.time()), 2),
            slowest_test=round(max(durations), 2) if durations else 0.0,
        )
    except Exception:
        pass


def pytest_sessionstart(session):
    session._dlf_start = time.time()
