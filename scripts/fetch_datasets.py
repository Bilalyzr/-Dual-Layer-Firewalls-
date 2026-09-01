"""
fetch_datasets.py — one-command public attack-dataset importer.

Pulls real labeled prompt-injection datasets and pushes them into the
firewall's REAL-TIME training store (POST /realtime/sample), deduped.

Sources (verified live):
  deepset  HF `deepset/prompt-injections`  — text + label (0=benign, 1=injection),
                                             splits train + test (~660 rows)
  advbench GitHub llm-attacks `harmful_behaviors.csv` — 520 harmful goals (label 1)

Usage (repo root):
  python scripts/fetch_datasets.py                       # dry-run, both sources
  python scripts/fetch_datasets.py --source deepset --limit 200 --push
  python scripts/fetch_datasets.py --source all --push   # import everything
  python scripts/fetch_datasets.py --export out.csv      # save locally

After --push, retrain (or wait for the auto-trainer):
  curl -X POST http://localhost:8020/admin/retrain-realtime
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402

HF_ROWS = "https://datasets-server.huggingface.co/rows"
ADVBENCH_CSV = ("https://raw.githubusercontent.com/llm-attacks/llm-attacks/"
                "main/data/advbench/harmful_behaviors.csv")

_seen: set[str] = set()


def _norm(text: str) -> str:
    return (text or "").strip()


def _hash(text: str) -> str:
    return hashlib.sha256(text.lower().encode()).hexdigest()


# --------------------------------------------------------------------------- #
# Source adapters -> yield (text, label)
# --------------------------------------------------------------------------- #
def fetch_deepset(client: httpx.Client, limit: int):
    """HF datasets-server pagination over train+test splits (retry on 5xx)."""
    got = 0
    for split in ("train", "test"):
        offset = 0
        while got < limit:
            data = None
            for attempt in range(3):  # datasets-server throws transient 502s
                try:
                    r = client.get(HF_ROWS, params={
                        "dataset": "deepset/prompt-injections",
                        "config": "default", "split": split,
                        "offset": offset, "length": 100,
                    })
                    if r.status_code >= 500:
                        raise httpx.HTTPStatusError("server 5xx", request=r.request, response=r)
                    r.raise_for_status()
                    data = r.json()
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    time.sleep(2 * (attempt + 1))
            rows = data.get("rows", [])
            if not rows:
                break
            for item in rows:
                row = item.get("row", {})
                text = _norm(row.get("text", ""))
                try:
                    label = int(str(row.get("label")).strip())
                except ValueError:
                    label = 1 if "injec" in str(row.get("label", "")).lower() else 0
                if text and len(text) >= 8:
                    yield text, label
                    got += 1
                    if got >= limit:
                        return
            offset += len(rows)
            if offset >= int(data.get("num_rows_total", 1_000_000)):
                break


def fetch_advbench(client: httpx.Client, limit: int):
    """Original CSV: goal (harmful prompt) -> label 1."""
    r = client.get(ADVBENCH_CSV)
    r.raise_for_status()
    reader = csv.DictReader(r.text.splitlines())
    got = 0
    for row in reader:
        text = _norm(row.get("goal", ""))
        if text:
            yield text, 1
            got += 1
            if got >= limit:
                return


def fetch_ultrachat_benign(client: httpx.Client, limit: int):
    """Real-world BENIGN user prompts (trial-update: class rebalance).

    HuggingFaceH4/ultrachat_200k — genuine chat prompts written by real
    users; take the FIRST human turn of each conversation. These are the
    ordinary questions/requests the firewall must never block, so the
    benign class stops being starved (was 889 threat / 441 benign).
    """
    got = 0
    for split in ("train_sft",):
        offset = 0
        while got < limit:
            data = None
            for attempt in range(3):
                try:
                    r = client.get(HF_ROWS, params={
                        "dataset": "HuggingFaceH4/ultrachat_200k",
                        "config": "default", "split": split,
                        "offset": offset, "length": 100,
                    })
                    if r.status_code >= 500:
                        raise httpx.HTTPStatusError("server 5xx", request=r.request, response=r)
                    r.raise_for_status()
                    data = r.json()
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    time.sleep(2 * (attempt + 1))
            rows = data.get("rows", [])
            if not rows:
                break
            for item in rows:
                row = item.get("row", {})
                messages = row.get("messages") or []
                # first human turn of the conversation = the user's prompt
                first = next((m.get("content", "") for m in messages
                              if m.get("from") == "human"
                              or m.get("role") == "user"), "")
                text = _norm(first)
                # keep prompt-shaped rows (not tiny greetings / huge dumps)
                if 25 <= len(text) <= 600:
                    yield text, 0
                    got += 1
                    if got >= limit:
                        return
            offset += len(rows)
            if offset >= int(data.get("num_rows_total", 1_000_000)):
                break


SOURCES = {
    "deepset": fetch_deepset,
    "advbench": fetch_advbench,
    "ultrachat": fetch_ultrachat_benign,
}


# --------------------------------------------------------------------------- #
def push_batch(base: str, rows: list[tuple[str, int, str]]) -> dict[str, int]:
    """Chunked bulk import via /realtime/samples (one transaction per chunk)."""
    out = {"recorded": 0, "duplicates": 0}
    for i in range(0, len(rows), 100):
        chunk = rows[i:i + 100]
        r = httpx.post(f"{base}/realtime/samples", json={
            "samples": [{"prompt": t, "label": l, "source": s}
                        for t, l, s in chunk],
        }, timeout=60)
        r.raise_for_status()
        d = r.json()
        out["recorded"] += int(d.get("recorded", 0))
        out["duplicates"] += int(d.get("duplicates", 0))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default="all", choices=["all", *SOURCES])
    ap.add_argument("--limit", type=int, default=10_000,
                    help="max rows PER SOURCE")
    ap.add_argument("--push", action="store_true",
                    help="push into the firewall training store (else dry-run)")
    ap.add_argument("--base", default="http://localhost:8020")
    ap.add_argument("--export", default="", help="also write rows to this CSV")
    args = ap.parse_args()

    names = list(SOURCES) if args.source == "all" else [args.source]
    grand = {"fetched": 0, "threat": 0, "benign": 0, "pushed": 0, "duplicates": 0}
    export_rows: list[tuple[str, int, str]] = []

    with httpx.Client(timeout=30, follow_redirects=True) as client:
        for name in names:
            stats = {"fetched": 0, "threat": 0, "benign": 0, "pushed": 0, "duplicates": 0}
            pending: list[tuple[str, int, str]] = []
            t0 = time.time()
            try:
                for text, label in SOURCES[name](client, args.limit):
                    h = _hash(text)
                    if h in _seen:
                        stats["duplicates"] += 1
                        continue
                    _seen.add(h)
                    stats["fetched"] += 1
                    stats["threat" if label else "benign"] += 1
                    export_rows.append((text, label, name))
                    pending.append((text, label, name))
            except Exception as exc:
                print(f"[{name}] ERROR: {type(exc).__name__}: {exc}")
            if args.push and pending:
                try:
                    res = push_batch(args.base, pending)
                    stats["pushed"] = res["recorded"]
                    stats["duplicates"] += res["duplicates"]
                except Exception as exc:
                    print(f"[{name}] PUSH ERROR: {type(exc).__name__}: {exc}")
            print(f"[{name}] fetched={stats['fetched']} "
                  f"(threat={stats['threat']} benign={stats['benign']}) "
                  f"duplicates={stats['duplicates']} "
                  f"pushed={stats['pushed']} in {time.time()-t0:.1f}s")
            for k in grand:
                grand[k] += stats[k]

    if args.export:
        with open(args.export, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["text", "label", "source"])
            w.writerows(export_rows)
        print(f"[export] {len(export_rows)} rows -> {args.export}")

    mode = "PUSHED to training store" if args.push else "DRY-RUN (use --push to import)"
    print(f"\nTOTAL: fetched={grand['fetched']} threat={grand['threat']} "
          f"benign={grand['benign']} pushed={grand['pushed']} "
          f"duplicates={grand['duplicates']} — {mode}")
    if args.push:
        print(f"Next: POST {args.base}/admin/retrain-realtime "
              f"(or wait for the auto-trainer)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
