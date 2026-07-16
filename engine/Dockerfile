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

# Train the classifier at build time so the artifact is baked into the image.
RUN python -m engine.classifier.train

EXPOSE 8000
CMD ["uvicorn", "engine.app:app", "--host", "0.0.0.0", "--port", "8000"]
