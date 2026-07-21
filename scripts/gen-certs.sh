#!/usr/bin/env bash
# EPIC D — generate a self-signed TLS 1.3 cert for local HTTPS testing.
#
# Real deployments should use Let's Encrypt / a real CA. This script produces a
# locally-trusted cert so you can verify the TLS config end-to-end.
#
#   bash scripts/gen-certs.sh
#
# Writes: tls/cert.pem + tls/key.pem (mounted by the edge proxy in docker-compose).
set -euo pipefail

OUT="$(dirname "$0")/../tls"
mkdir -p "$OUT"

echo "[gen-certs] writing self-signed cert to $OUT/"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$OUT/key.pem" -out "$OUT/cert.pem" \
  -days 825 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "[gen-certs] done."
echo "[gen-certs] For local trust, add tls/cert.pem to your browser's trust store."
echo "[gen-certs] For PRODUCTION, replace these with certs from Let's Encrypt / your CA."
