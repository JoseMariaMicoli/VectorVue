"""Tenant extraction utilities from JWT for Phase 6.5."""

from __future__ import annotations

from uuid import UUID

import jwt
from fastapi import HTTPException, Request, status


JWT_MISSING_TENANT = "JWT is missing required tenant_id claim"


def get_current_tenant(request: Request) -> UUID:
    """Extract tenant_id claim from bearer JWT and return as UUID.

    Tokens without tenant_id are rejected with HTTP 401.
    """

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    token = auth.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

    try:
        payload = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT") from exc

    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=JWT_MISSING_TENANT)

    try:
        return UUID(str(tenant_id))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid tenant_id format") from exc
