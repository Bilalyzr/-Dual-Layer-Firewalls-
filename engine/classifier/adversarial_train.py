"""
EPIC F — Adversarial-training feedback loop.

The firewall's Req 1.5 sampler already retains ~5% of low-confidence ALLOWED
traffic in the `samples` Mongo collection. This script closes the loop:
  1. Pull reviewed samples (label = human-confirmed threat/benign) from Mongo.
  2. Augment the seed dataset with them.
  3. Retrain the ensemble + (optionally) re-fit the embedding centroid.

Run periodically (e.g. nightly) so the classifier learns from real evasion
attempts observed in production. Manual review sets the labels — never auto-train
on unreviewed samples (poisoning risk).

    python -m engine.classifier.adversarial_train
    MONGO_URI=mongodb://localhost:27017/firewall python -m engine.classifier.adversarial_train
"""
from __future__ import annotations
import csv
import os
from pathlib import Path

CSV_PATH = Path(__file__).resolve().parent / "jailbreak_dataset.csv"
REVIEWED_FLAG = "reviewed_label"  # field the review UI sets: 0=threat, 1=benign


def _pull_reviewed_samples() -> list[tuple[str, int]]:
    """Pull human-reviewed samples from Mongo. Returns [(text, label)]."""
    uri = os.getenv("MONGO_URI") or os.getenv("MONGO_URI_LOCAL")
    if not uri:
        return []
    try:
        from pymongo import MongoClient

        client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        col = client.get_default_database()["samples"]
        out = []
        for doc in col.find({REVIEWED_FLAG: {"$in": [0, 1]}}):
            text = (doc.get("prompt") or "").strip()
            if text:
                out.append((text, int(doc[REVIEWED_FLAG])))
        client.close()
        return out
    except Exception as exc:
        print(f"[adv-train] could not pull samples: {exc}")
        return []


def main() -> dict:
    reviewed = _pull_reviewed_samples()
    if not reviewed:
        print("[adv-train] no reviewed samples — retraining on seed dataset only.")

    # Append reviewed rows to the CSV (dedup by text), then retrain.
    existing = set()
    if CSV_PATH.exists():
        with CSV_PATH.open(encoding="utf-8") as f:
            for row in csv.reader(f):
                if row:
                    existing.add(row[0].strip().lower())

    added = 0
    with CSV_PATH.open("a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for text, label in reviewed:
            key = text.strip().lower()
            if key and key not in existing:
                w.writerow([text, label])
                existing.add(key)
                added += 1

    # Delegate the actual retrain to the existing train scripts.
    from engine.classifier import train as clf_train

    metrics = clf_train.train()
    metrics["adv_samples_added"] = added
    metrics["adv_samples_total_reviewed"] = len(reviewed)
    print(f"[adv-train] added {added} new reviewed samples. metrics: {metrics}")
    return metrics


if __name__ == "__main__":
    main()
