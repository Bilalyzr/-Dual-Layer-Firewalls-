FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy engine source as the `engine` package (WORKDIR /app is the package
# root) so `python -m engine.classifier.train` and `uvicorn engine.app:app`
# resolve exactly as they do from the repo root on a dev machine.
COPY . ./engine

# Model artifacts: the COMMITTED, live-traffic-trained ones ship with the
# image when present (they encode the hybrid corpus + gated retrains — a
# seed-only build-time retrain scores ~8/16 on the red-team battery vs
# 16/16 for the enriched artifacts). Fresh clones without artifacts still
# train at build.
RUN if [ ! -f engine/models/tfidf.joblib ] || [ ! -f engine/models/clf_ensemble.joblib ]; then \
      python -m engine.classifier.train; \
    fi && \
    if [ ! -f engine/models/biometric_ensemble.joblib ]; then \
      python -m engine.biometric.train_biometric; \
    fi

EXPOSE 8011
# Read $PORT when provided (Render/cloud injects it); default to 8011 locally.
CMD ["sh", "-c", "uvicorn engine.app:app --host 0.0.0.0 --port ${PORT:-8011}"]
