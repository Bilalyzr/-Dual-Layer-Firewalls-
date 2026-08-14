"""
API-key validation for the firewall proxy (PDF §4.2 core/security.py).

Optional by default: set FIREWALL_API_KEY to enforce `Authorization: Bearer`
on every endpoint. Also accepts the diagram's `X-User-Id` / `X-Session-Id`
convention — those headers are trusted as identity hints, not secrets.
"""
from __future__ import annotations

from fastapi import Header, HTTPException

from .config import SETTINGS


def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """Dependency: 401 when a key is configured but not presented correctly."""
    if not SETTINGS.api_key:
        return  # auth disabled — open proxy (dev/demo default)
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if token != SETTINGS.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
