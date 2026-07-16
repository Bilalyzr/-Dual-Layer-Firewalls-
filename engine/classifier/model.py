"""
Semantic jailbreak classifier (Req 1.3).

TF-IDF (word + char n-grams) + Logistic Regression. Lightweight, low-latency,
runs inline at the proxy layer. The threshold is tunable at inference time so
SecOps can adjust the security/friction trade-off without retraining.
"""
from __future__ import annotations
import joblib
from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
VECTOR_PATH = MODEL_DIR / "tfidf.joblib"
CLF_PATH = MODEL_DIR / "clf.joblib"

# Labels in the dataset: 0 = jailbreak/threat, 1 = benign.
# We return P(threat) so a higher score => more dangerous.
THREAT_LABEL = 0


class JailbreakClassifier:
    """Loads trained artifacts; returns P(threat) for a prompt."""

    def __init__(self) -> None:
        self.vectorizer = joblib.load(VECTOR_PATH)
        self.clf = joblib.load(CLF_PATH)

    def predict_proba(self, text: str) -> float:
        """Return probability that `text` is a jailbreak/threat (0..1)."""
        if not text or not text.strip():
            return 0.0
        X = self.vectorizer.transform([text])
        proba = self.clf.predict_proba(X)[0]
        # Map class index -> threat probability.
        idx = list(self.clf.classes_).index(THREAT_LABEL)
        return float(proba[idx])


_classifier: JailbreakClassifier | None = None


def get_classifier() -> JailbreakClassifier:
    global _classifier
    if _classifier is None:
        _classifier = JailbreakClassifier()
    return _classifier
