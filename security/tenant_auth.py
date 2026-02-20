# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 → Apache-2.0
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products

"""Tenant extraction utilities from JWT for Phase 6.5."""

from __future__ import annotations

import os
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

    jwt_secret = os.environ.get("VV_CLIENT_JWT_SECRET", "").strip()
    allow_unsigned = os.environ.get("VV_CLIENT_JWT_ALLOW_UNSIGNED", "0").strip() == "1"

    try:
        if jwt_secret:
            payload = jwt.decode(token, key=jwt_secret, algorithms=["HS256"], options={"verify_aud": False})
        elif allow_unsigned:
            payload = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
        else:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="JWT verification misconfigured on server",
            )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid JWT") from exc

    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=JWT_MISSING_TENANT)

    try:
        return UUID(str(tenant_id))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid tenant_id format") from exc
