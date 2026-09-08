FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for layer caching. The build context is the REPO ROOT
# (see render.yaml) so both the engine package and the root models/ (the
# deep-tier intent model — trained through the promotion gates) ship with
# the image; without it the live deep tier degrades to the fast tier only.
COPY engine/requirements.txt ./engine/requirements.txt
RUN pip install --upgrade pip && pip install -r engine/requirements.txt

COPY engine ./engine
COPY models ./models

# Model artifacts: the COMMITTED, live-traffic-trained ones ship with the
# image when present (they encode the hybrid corpus + gated retrains — a
# seed-only build-time retrain scores ~8/16 on the red-team battery vs
# 16/16 for the enriched artifacts). Fresh clones without artifacts still
# train at build.
RUN if [ ! -f engine/models/tfidf.joblib ] && [ ! -f models/tfidf.joblib ]; then \
      python -m engine.classifier.train; \
    fi && \
    if [ ! -f engine/models/biometric_ensemble.joblib ]; then \
      python -m engine.biometric.train_biometric; \
    fi

EXPOSE 8011
# Read $PORT when provided (Render/cloud injects it); default to 8011 locally.
CMD ["sh", "-c", "uvicorn engine.app:app --host 0.0.0.0 --port ${PORT:-8011}"]
