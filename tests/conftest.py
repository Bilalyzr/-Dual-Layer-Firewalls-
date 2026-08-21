import os
import sys
from pathlib import Path

# Tests always run on the disposable SQLite store — never the real
# PostgreSQL audit DB (which .env may point at on a developer machine).
os.environ["AUDIT_DSN"] = ""

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
