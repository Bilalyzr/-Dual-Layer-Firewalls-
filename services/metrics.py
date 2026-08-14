"""
Prometheus metrics (diagram: "MONITORING — Prometheus, Grafana; ALERTS —
Alert Manager; Dashboards (Real-time)").

Counters + a latency histogram per pipeline layer, exposed at /metrics for
the Prometheus scraper. Alert rules live in deploy/prometheus/alerts.yml.
"""
from __future__ import annotations

try:
    from prometheus_client import (CONTENT_TYPE_LATEST, Counter, Histogram,
                                   generate_latest)

    REQUESTS_TOTAL = Counter(
        "firewall_requests_total", "Requests through the pipeline",
        ["decision"],  # allow | block | filtered
    )
    LAYER_BLOCKS = Counter(
        "firewall_layer_blocks_total", "Blocks attributed to each layer",
        ["layer"],  # sanitizer | intent | behavioral | rag | output
    )
    LAYER_LATENCY = Histogram(
        "firewall_layer_latency_seconds", "Per-layer latency",
        ["layer"],
        buckets=(0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
    )
    RISK_SCORE = Histogram(
        "firewall_risk_score", "Final risk score distribution",
        buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
    )
    _ENABLED = True
except Exception:  # prometheus_client missing — metrics become no-ops
    CONTENT_TYPE_LATEST = "text/plain; charset=utf-8"
    _ENABLED = False


def inc_requests(decision: str) -> None:
    if _ENABLED:
        REQUESTS_TOTAL.labels(decision=decision).inc()


def inc_layer_block(layer: str) -> None:
    if _ENABLED:
        LAYER_BLOCKS.labels(layer=layer).inc()


def observe_latency(layer: str, seconds: float) -> None:
    if _ENABLED:
        LAYER_LATENCY.labels(layer=layer).observe(seconds)


def observe_risk(score: float) -> None:
    if _ENABLED:
        RISK_SCORE.observe(score)


def render() -> tuple[bytes, str]:
    if _ENABLED:
        return generate_latest(), CONTENT_TYPE_LATEST
    return b"metrics disabled\n", CONTENT_TYPE_LATEST
