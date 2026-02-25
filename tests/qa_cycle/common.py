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

from __future__ import annotations

import os
from dataclasses import dataclass

import requests


BASE_URL = os.environ.get("QA_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
PG_URL = os.environ.get(
    "QA_PG_URL",
    os.environ.get("VV_DB_URL", "postgresql://vectorvue:strongpassword@postgres:5432/vectorvue_db"),
)


@dataclass(frozen=True)
class Creds:
    username: str
    password: str
    tenant_id: str


ACME_VIEWER = Creds("acme_viewer", "AcmeView3r!", "10000000-0000-0000-0000-000000000001")
ACME_LEAD = Creds("rt_lead", "LeadOperat0r!", "10000000-0000-0000-0000-000000000001")
GLOBEX_VIEWER = Creds("globex_viewer", "GlobexView3r!", "20000000-0000-0000-0000-000000000002")


def login(creds: Creds) -> tuple[str, dict]:
    r = requests.post(
        f"{BASE_URL}/api/v1/client/auth/login",
        json={
            "username": creds.username,
            "password": creds.password,
            "tenant_id": creds.tenant_id,
        },
        timeout=15,
    )
    if r.status_code != 200:
        raise AssertionError(f"login failed {creds.username}: {r.status_code} {r.text[:300]}")
    payload = r.json()
    return payload["access_token"], payload


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}

