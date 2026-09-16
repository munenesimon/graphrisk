"""
Simple API key authentication for the GraphRisk API.

This is deliberately minimal -- a single shared key checked via a FastAPI
dependency -- appropriate for gating a public demo deployment against
random internet traffic before real multi-tenant JWT auth (Phase 4) exists.

If GRAPHRISK_API_KEY is not set in the environment, auth is disabled --
this keeps local development frictionless while still being safe once
the env var is set on a real deployment (Render, etc.).
"""
import os
from fastapi import Header, HTTPException, status
from typing import Optional

API_KEY = os.environ.get("GRAPHRISK_API_KEY")


async def verify_api_key(x_api_key: Optional[str] = Header(default=None)):
    """
    FastAPI dependency: raises 401 if the API key is missing or wrong.
    Include via `dependencies=[Depends(verify_api_key)]` on any router
    that should require authentication.
    """
    if not API_KEY:
        # No key configured (local dev) -- auth is a no-op.
        return
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key. Include it as the X-API-Key header.",
        )
