# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

"""Build externally reachable absolute URLs in reverse-proxy deployments."""

from __future__ import annotations

import os
from urllib.parse import urljoin

from fastapi import Request


def build_public_url(path: str, request: Request | None = None) -> str:
    """Build an absolute public URL for API responses.

    Priority:
    1. PUBLIC_BASE_URL environment variable
    2. Forwarded proxy headers from request
    3. Direct request URL components
    """

    if not path.startswith("/"):
        path = f"/{path}"

    base_url = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if base_url:
        return f"{base_url}{path}"

    if request is None:
        return path

    forwarded_proto = request.headers.get("x-forwarded-proto", "").strip()
    forwarded_host = request.headers.get("x-forwarded-host", "").strip()

    scheme = forwarded_proto or request.url.scheme or "http"
    host = forwarded_host or request.headers.get("host", "") or request.url.netloc

    if not host:
        return path

    return urljoin(f"{scheme}://{host}", path)
