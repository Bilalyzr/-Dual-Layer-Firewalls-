"""
Pytest configuration — make the repo root importable so tests can do
`from engine.classifier.model import ...` regardless of cwd.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # .../dual-layer-firewall
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
