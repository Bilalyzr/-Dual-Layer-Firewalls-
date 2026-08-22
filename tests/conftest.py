import os
import sys
import tempfile
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
