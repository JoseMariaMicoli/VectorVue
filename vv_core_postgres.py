"""
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Tuple
from urllib.parse import urlparse

try:
    import psycopg
except Exception:  # pragma: no cover
    psycopg = None

try:
    from vv import CyberTUI, RuntimeExecutor
    from vv_core import Database, SessionCrypto
except Exception as exc:  # pragma: no cover
    print(f"CRITICAL: failed to import VectorVue modules: {exc}")
    raise


LOGGER = logging.getLogger("vectorvue.phase6")


def _append_key_audit(event: str, detail: str) -> None:
    """Append key retrieval activity for compliance/audit visibility."""
    log_dir = os.environ.get("VV_LOG_DIR", "/var/lib/vectorvue/logs")
    os.makedirs(log_dir, exist_ok=True)
    line = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event": event,
        "detail": detail,
    }
    with open(os.path.join(log_dir, "key_access_audit.log"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, sort_keys=True) + "\n")


def _load_passphrase_from_hsm() -> str:
    """Load service passphrase from PKCS#11 or file-backed HSM secret mount."""
    file_path = os.environ.get("VV_HSM_KEY_FILE", "").strip()
    if file_path:
        with open(file_path, "r", encoding="utf-8") as handle:
            value = handle.read().strip()
        if not value:
            raise RuntimeError(f"HSM key file is empty: {file_path}")
        _append_key_audit("HSM_KEY_READ", f"file:{file_path}")
        return value

    module = os.environ.get("VV_PKCS11_MODULE", "").strip()
    label = os.environ.get("VV_HSM_KEY_LABEL", "").strip()
    pin = os.environ.get("VV_PKCS11_PIN", "").strip()
    if module and label:
        cmd = [
            "pkcs11-tool",
            "--module",
            module,
            "--read-object",
            "--type",
            "data",
            "--label",
            label,
        ]
        if pin:
            cmd.extend(["--pin", pin])
        proc = subprocess.run(cmd, check=True, capture_output=True)
        # Treat stored object as base64 text payload for passphrase transport.
        passphrase = base64.b64decode(proc.stdout.strip()).decode("utf-8").strip()
        if not passphrase:
            raise RuntimeError("PKCS#11 object resolved but passphrase was empty")
        _append_key_audit("HSM_KEY_READ", f"pkcs11:{label}")
        return passphrase

    raise RuntimeError("No HSM key source configured")


def _resolve_service_passphrase() -> str:
    """Resolve service passphrase from HSM if enabled, else environment/default."""
    if os.environ.get("VV_HSM_ENABLED", "0").strip() in {"1", "true", "TRUE"}:
        return _load_passphrase_from_hsm()
    env_passphrase = os.environ.get("VV_SERVICE_PASSPHRASE", "").strip()
    if env_passphrase:
        return env_passphrase
    return "VectorVueServiceModePassphrase!"


def _build_pg_url() -> str:
    """Build PostgreSQL DSN using VV_DB_URL or VV_DB_* variables."""
    env_url = os.environ.get("VV_DB_URL", "").strip()
    if env_url:
        return env_url
    user = os.environ.get("VV_DB_USER", os.environ.get("POSTGRES_USER", "vectorvue"))
    password = os.environ.get("VV_DB_PASSWORD", os.environ.get("POSTGRES_PASSWORD", "strongpassword"))
    host = os.environ.get("VV_DB_HOST", "127.0.0.1")
    port = os.environ.get("VV_DB_PORT", "5432")
    name = os.environ.get("VV_DB_NAME", os.environ.get("POSTGRES_DB", "vectorvue_db"))
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


def _check_postgres() -> Tuple[bool, str]:
    """Check PostgreSQL liveness for health endpoint and service mode."""
    if psycopg is None:
        return False, "psycopg_missing"
    dsn = _build_pg_url()
    try:
        with psycopg.connect(dsn, connect_timeout=3) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                _ = cur.fetchone()
        return True, "ok"
    except Exception as exc:
        return False, str(exc)


def _check_redis() -> Tuple[bool, str]:
    """Perform a low-level Redis PING without external dependencies."""
    host = os.environ.get("VV_REDIS_HOST", "redis")
    port = int(os.environ.get("VV_REDIS_PORT", "6379"))
    password = os.environ.get("VV_REDIS_PASSWORD", "")
    try:
        with socket.create_connection((host, port), timeout=2.0) as sock:
            if password:
                auth_cmd = f"*2\r\n$4\r\nAUTH\r\n${len(password)}\r\n{password}\r\n".encode("utf-8")
                sock.sendall(auth_cmd)
                auth_resp = sock.recv(256)
                if not auth_resp.startswith(b"+OK"):
                    return False, "auth_failed"
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")
            data = sock.recv(256)
        if data.startswith(b"+PONG"):
            return True, "ok"
        return False, "bad_pong"
    except Exception as exc:
        return False, str(exc)


def _health_snapshot() -> Dict[str, object]:
    pg_ok, pg_msg = _check_postgres()
    redis_ok, redis_msg = _check_redis()
    return {
        "status": "healthy" if pg_ok and redis_ok else "degraded",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": {
            "postgres": {"ok": pg_ok, "detail": pg_msg},
            "redis": {"ok": redis_ok, "detail": redis_msg},
        },
    }


class _HealthHandler(BaseHTTPRequestHandler):
    """Simple HTTP health endpoint used by docker and nginx probes."""

    def log_message(self, fmt: str, *args):  # pragma: no cover
        LOGGER.debug("health-server: " + fmt, *args)

    def _write_json(self, status_code: int, payload: Dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path in ("/", "/healthz", "/readyz"):
            payload = _health_snapshot()
            code = 200 if payload["status"] == "healthy" else 503
            self._write_json(code, payload)
            return
        self._write_json(404, {"status": "not_found"})


def _start_health_server() -> HTTPServer:
    host = os.environ.get("VV_HEALTH_HOST", "0.0.0.0")
    port = int(os.environ.get("VV_HEALTH_PORT", "8080"))
    server = HTTPServer((host, port), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    LOGGER.info("health endpoint listening on http://%s:%s", host, port)
    return server


async def _run_service_mode() -> None:
    """Service mode keeps RuntimeExecutor alive for scheduled maintenance tasks."""
    os.environ.setdefault("VV_DB_BACKEND", "postgres")
    crypto = SessionCrypto()
    service_passphrase = _resolve_service_passphrase()
    crypto.derive_key(service_passphrase)
    db = Database(crypto)
    executor = RuntimeExecutor(db)

    stop_event = asyncio.Event()

    def _handle_stop(signum, _frame):
        LOGGER.info("received signal=%s, stopping service loop", signum)
        executor.stop()
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    loop_task = asyncio.create_task(executor.run_maintenance_loop())
    LOGGER.info("RuntimeExecutor loop started")
    try:
        await stop_event.wait()
    finally:
        executor.stop()
        await asyncio.sleep(0)
        loop_task.cancel()
        try:
            await loop_task
        except asyncio.CancelledError:
            pass
        db.close()
        LOGGER.info("service loop stopped cleanly")


def _run_tui_mode() -> None:
    """Run full TUI exactly as vv.py entrypoint does."""
    if sys.platform == "win32":
        os.system("cls")
    else:
        os.system("clear")
    CyberTUI().run()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="VectorVue PostgreSQL launcher")
    parser.add_argument(
        "--mode",
        choices=["auto", "tui", "service"],
        default=os.environ.get("VV_RUN_MODE", "auto").strip().lower() or "auto",
        help="Launch mode. auto selects tui if tty is present, otherwise service.",
    )
    parser.add_argument(
        "--disable-health-server",
        action="store_true",
        help="Disable embedded /healthz endpoint.",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("VV_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    args = _parse_args()

    mode = args.mode
    if mode == "auto":
        mode = "tui" if sys.stdin.isatty() and sys.stdout.isatty() else "service"

    server = None
    if not args.disable_health_server:
        server = _start_health_server()

    try:
        if mode == "tui":
            _run_tui_mode()
        else:
            asyncio.run(_run_service_mode())
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
