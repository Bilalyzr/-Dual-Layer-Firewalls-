# EPIC J — GPU inference service for DistilBERT / Llama Guard.
#
# Same FastAPI app as the CPU engine, but on a CUDA base image so the models can
# use GPU acceleration (unlocks 10k+ rps for the embedding firewall + guard).
# Falls back to CPU automatically when no GPU is present (PyTorch handles this).
#
# Deploy on a GPU node pool (k8s: nodeSelector: accelerator: nvidia). The proxy
# routes to this service via INFERENCE_SVC_URL when set; otherwise the CPU engine
# handles everything.
FROM nvidia/cuda:12.4.1-cudnn-runtime-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y python3.11 python3-pip && \
    ln -sf /usr/bin/python3.11 /usr/bin/python && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY engine/requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY engine/ .
RUN python -m engine.classifier.train && python -m engine.biometric.train_biometric

EXPOSE 8011
CMD ["sh", "-c", "uvicorn engine.app:app --host 0.0.0.0 --port ${PORT:-8011}"]
