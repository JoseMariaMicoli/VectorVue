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

"""Tenant asset path resolver for Phase 7D white-label portal."""

from __future__ import annotations

import os
from pathlib import Path


def tenant_assets_root() -> Path:
    return Path(os.environ.get('VV_TENANT_ASSETS_DIR', '/var/lib/vectorvue/assets')).resolve()


def resolve_tenant_asset(tenant_id: str, filename: str) -> Path:
    """Resolve tenant asset safely, preventing traversal outside asset root."""
    safe_tenant = str(tenant_id).strip()
    safe_name = Path(filename).name
    if not safe_tenant or not safe_name:
        raise ValueError('tenant_id and filename are required')

    base = tenant_assets_root()
    candidate = (base / safe_tenant / safe_name).resolve()

    if not str(candidate).startswith(str(base) + os.sep):
        raise ValueError('invalid tenant asset path')

    return candidate
