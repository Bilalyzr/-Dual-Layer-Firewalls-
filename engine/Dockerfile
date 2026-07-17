FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install deps first for layer caching.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy engine source.
COPY . .

# Train both models at build time so artifacts are baked into the image:
#   - the semantic jailbreak classifier (Tier 1)
#   - the biometric LSTM + ensemble (Tier 2, Phase 4)
RUN python -m engine.classifier.train && \
    python -m engine.biometric.train_biometric

EXPOSE 8011
CMD ["uvicorn", "engine.app:app", "--host", "0.0.0.0", "--port", "8011"]
