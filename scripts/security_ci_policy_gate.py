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

"""Phase 8.1 security policy gate for CI enforcement."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


def _fail(msg: str) -> None:
    print(f"SECURITY POLICY VIOLATION: {msg}")
    raise SystemExit(1)


def _load_compose(path: Path) -> dict:
    if not path.exists():
        _fail(f"compose file not found: {path}")
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        _fail(f"compose parse failed: {exc}")


def _compose_env_to_map(env: object) -> dict[str, str]:
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    if isinstance(env, list):
        out: dict[str, str] = {}
        for item in env:
            text = str(item)
            if "=" not in text:
                continue
            key, value = text.split("=", 1)
            out[key.strip()] = value.strip()
        return out
    return {}


def _check_runtime_security_flags(compose: dict) -> None:
    services = compose.get("services") or {}
    gateway = services.get("vectorvue_telemetry_gateway") or {}
    env = _compose_env_to_map(gateway.get("environment"))

    mtls = str(env.get("VV_TG_REQUIRE_MTLS", "")).strip().lower()
    if mtls not in {"1", "true", "yes", "on"}:
        _fail("mTLS is disabled for telemetry gateway")

    sig = str(env.get("VV_TG_REQUIRE_PAYLOAD_SIGNATURE", "")).strip().lower()
    if sig not in {"1", "true", "yes", "on"}:
        _fail("payload signature validation is disabled for telemetry gateway")


def _check_code_guards(repo_root: Path) -> None:
    gateway_main = repo_root / "services" / "telemetry_gateway" / "main.py"
    content = gateway_main.read_text(encoding="utf-8")

    if "Unsigned telemetry is disabled by policy" not in content:
        _fail("unsigned telemetry fail-closed guard missing")

    if "_enforce_signed_tenant_metadata" not in content:
        _fail("tenant mapping enforcement guard missing")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    compose = _load_compose(repo_root / "docker-compose.yml")
    _check_runtime_security_flags(compose)
    _check_code_guards(repo_root)
    print("Security policy gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
