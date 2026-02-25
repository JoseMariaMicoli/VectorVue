#!/usr/bin/env python3
"""Phase 7-9 smoke validation for real scenarios (no dummy seed dependency)."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def _request_json(method: str, url: str, headers: dict[str, str] | None = None, body: dict | None = None) -> tuple[int, dict]:
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    raw = None
    if body is not None:
        raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=raw, headers=req_headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as resp:
        payload = resp.read().decode("utf-8")
        return resp.status, json.loads(payload) if payload else {}


def _request_bytes(method: str, url: str, headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=25) as resp:
        return resp.status, resp.read(), dict(resp.headers)


def _assert_status(code: int, expected: int, context: str) -> None:
    if code != expected:
        raise RuntimeError(f"{context}: expected {expected}, got {code}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate phase 7-9 endpoints in real scenario mode")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--framework", default="ISO27001")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")

    try:
        status, login = _request_json(
            "POST",
            f"{base}/api/v1/client/auth/login",
            body={"username": args.username, "password": args.password, "tenant_id": args.tenant_id},
        )
        _assert_status(status, 200, "login")
        token = str(login.get("access_token", ""))
        if not token:
            raise RuntimeError("login missing access_token")
        auth = {"Authorization": f"Bearer {token}"}

        # Phase 7 core client endpoints (must work even with empty data).
        for ep in [
            "/api/v1/client/findings?page=1&page_size=10",
            "/api/v1/client/reports?page=1&page_size=10",
            "/api/v1/client/remediation?page=1&page_size=10",
            "/api/v1/client/risk",
            "/api/v1/client/risk-summary",
            "/api/v1/client/risk-trend?days=30",
            "/api/v1/client/theme",
        ]:
            code, _ = _request_json("GET", f"{base}{ep}", headers=auth)
            _assert_status(code, 200, f"phase7 endpoint {ep}")

        code, _ = _request_json(
            "POST",
            f"{base}/api/v1/client/events",
            headers=auth,
            body={
                "event_type": "DASHBOARD_VIEWED",
                "object_type": "dashboard",
                "object_id": "overview",
                "severity": None,
                "metadata_json": {"source": "phase79_real_smoke"},
            },
        )
        _assert_status(code, 202, "phase7 telemetry event")

        # Phase 8 endpoints should return client contract (may be queued/defaults).
        for ep, method, payload in [
            ("/ml/client/security-score", "GET", None),
            ("/ml/client/risk", "GET", None),
            ("/ml/client/detection-gaps", "GET", None),
            ("/ml/client/anomalies", "GET", None),
            ("/ml/client/simulate", "POST", {"scenario": "baseline", "controls_improvement": 0.0, "detection_improvement": 0.0}),
        ]:
            if method == "GET":
                code, payload_json = _request_json("GET", f"{base}{ep}", headers=auth)
            else:
                code, payload_json = _request_json("POST", f"{base}{ep}", headers=auth, body=payload)
            _assert_status(code, 200, f"phase8 endpoint {ep}")
            for key in ["score", "confidence", "explanation", "model_version", "generated_at"]:
                if key not in payload_json:
                    raise RuntimeError(f"phase8 endpoint {ep}: missing key '{key}'")

        # Phase 9 signed compliance endpoints.
        framework = urllib.parse.quote(args.framework, safe="")
        for ep in [
            "/compliance/frameworks",
            f"/compliance/{framework}/controls",
            f"/compliance/{framework}/score?period_days=30",
            f"/compliance/{framework}/report?days=30",
            f"/compliance/audit-window?framework={framework}&days=30",
        ]:
            code, payload_json = _request_json("GET", f"{base}{ep}", headers=auth)
            _assert_status(code, 200, f"phase9 endpoint {ep}")
            if "data" not in payload_json or "signature" not in payload_json:
                raise RuntimeError(f"phase9 endpoint {ep}: missing signed envelope")

        code, audit = _request_json(
            "POST",
            f"{base}/audit/session",
            headers=auth,
            body={"ttl_minutes": 30, "purpose": "phase79_real_smoke"},
        )
        _assert_status(code, 200, "phase9 audit session")
        audit_token = str(audit.get("token", ""))
        if not audit_token:
            raise RuntimeError("phase9 audit session: missing audit token")

        dl_headers = {"Authorization": f"Bearer {audit_token}"}
        dl_url = f"{base}/compliance/{framework}/report/download?tenant_id={args.tenant_id}&days=30"
        code, content, headers = _request_bytes("GET", dl_url, headers=dl_headers)
        _assert_status(code, 200, "phase9 report download")
        if not content:
            raise RuntimeError("phase9 report download: empty package")
        lower_headers = {k.lower(): v for k, v in headers.items()}
        if not lower_headers.get("x-vectorvue-dataset-hash"):
            raise RuntimeError("phase9 report download: missing dataset hash header")

        print("Phase 7-9 real scenario smoke passed.")
        return 0
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"HTTP error {exc.code}: {detail}")
        return 1
    except Exception as exc:
        print(f"Smoke failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
