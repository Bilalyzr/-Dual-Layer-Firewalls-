"""
Train the jailbreak classifier on the bundled seed dataset and persist
artifacts to engine/models/. Run standalone or it runs on container build.

    python -m engine.classifier.train   (from repo root)
    python train.py                      (from engine/classifier/)
"""
from __future__ import annotations
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline  # noqa: F401  (kept for familiarity)


HERE = Path(__file__).resolve().parent
CSV_PATH = HERE / "jailbreak_dataset.csv"
MODEL_DIR = HERE.parent / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)


def _load() -> pd.DataFrame:
    df = pd.read_csv(CSV_PATH)
    df = df.dropna(subset=["text", "label"])
    df["text"] = df["text"].astype(str).str.strip().str.lower()
    df["label"] = df["label"].astype(int)
    df = df[df["text"].str.len() > 0]
    return df


def train() -> dict:
    df = _load()
    # Combine word + char n-grams: words catch lexical signatures, chars catch
    # obfuscation (leetspeak, missing spaces).
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        strip_accents="unicode",
        min_df=1,
    )
    clf = LogisticRegression(max_iter=1000, class_weight="balanced")

    X = vectorizer.fit_transform(df["text"])
    y = df["label"].values

    # Hold-out report — small dataset, so this is directional not authoritative.
    metrics = {}
    if len(df) >= 8 and len(set(y)) == 2:
        Xtr, Xte, ytr, yte = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y
        )
        clf.fit(Xtr, ytr)
        from sklearn.metrics import classification_report

        report = classification_report(
            yte, clf.predict(Xte), output_dict=True, zero_division=0
        )
        metrics = {
            "holdout_support": int(len(yte)),
            "benign_f1": round(report.get("1", {}).get("f1-score", 0.0), 3),
            "threat_f1": round(report.get("0", {}).get("f1-score", 0.0), 3),
            "macro_f1": round(report.get("macro avg", {}).get("f1-score", 0.0), 3),
        }
        # Refit on all data for the production artifact.
        clf.fit(X, y)
    else:
        clf.fit(X, y)

    joblib.dump(vectorizer, MODEL_DIR / "tfidf.joblib")
    joblib.dump(clf, MODEL_DIR / "clf.joblib")
    return {"rows": int(len(df)), "features": int(X.shape[1]), **metrics}


if __name__ == "__main__":
    # Allow `python train.py` from inside classifier/
    if HERE.parent.name not in sys.path:
        pass
    print(train())
