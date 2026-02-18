#!/usr/bin/env python3
"""
Copyright (c) 2026 José María Micoli
Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vv_core import Database, SessionCrypto, Role


def ensure_login(db: Database, username: str, password: str) -> None:
    ok, _ = db.authenticate_user(username, password)
    if ok:
        return
    db.register_user(username, password, role=Role.ADMIN, group_name="default")
    ok, msg = db.authenticate_user(username, password)
    if not ok:
        raise RuntimeError(f"unable to authenticate seed user: {msg}")


def _role_from_name(role_name: str) -> str:
    mapping = {
        "viewer": Role.VIEWER,
        "operator": Role.OPERATOR,
        "lead": Role.LEAD,
        "admin": Role.ADMIN,
    }
    key = (role_name or "").strip().lower()
    if key not in mapping:
        raise ValueError(f"invalid role '{role_name}' (use viewer|operator|lead|admin)")
    return mapping[key]


def ensure_user_credentials(db: Database, username: str, password: str, role: str) -> str:
    """Create user if missing; verify credentials if present.

    Returns a short status string for console output.
    """
    ok, _ = db.authenticate_user(username, password)
    if ok:
        return "present"

    created, msg = db.register_user(username, password, role=role, group_name="default")
    if created:
        return "created"

    # Most common failure is duplicate username with different password.
    if "already exists" in msg.lower():
        return "exists_with_different_password"
    return f"error:{msg}"


def get_or_create_campaign(db: Database, name: str, project_id: str = "DEFAULT") -> int:
    existing = db.get_campaign_by_name(name)
    if existing:
        return int(existing.id)
    ok, msg = db.create_campaign(name, project_id)
    if not ok:
        raise RuntimeError(f"unable to create campaign {name}: {msg}")
    created = db.get_campaign_by_name(name)
    if not created:
        raise RuntimeError(f"campaign missing right after create: {name}")
    return int(created.id)


def seed_campaign(db: Database, campaign_id: int, op_name: str, operator: str, c2_name: str) -> None:
    c0 = db.conn.cursor()
    c0.execute("SELECT COUNT(*) AS n FROM assets WHERE campaign_id=?", (campaign_id,))
    already_seeded = int(c0.fetchone()["n"]) > 0

    assets = [
        ("host", f"{op_name}-VPN", "10.20.0.10", "Ubuntu 22.04", "gateway,server"),
        ("host", f"{op_name}-WS01", "10.20.10.21", "Windows 11", "workstation,user"),
        ("host", f"{op_name}-APP01", "10.20.20.15", "Windows Server 2022", "server,critical"),
        ("host", f"{op_name}-DB01", "10.20.30.9", "Windows Server 2019", "db,critical"),
        ("host", f"{op_name}-DC01", "10.20.40.5", "Windows Server 2022", "dc,critical,domain"),
    ]
    if already_seeded:
        existing_assets = db.list_assets(campaign_id)
        by_name = {a.name: int(a.id) for a in existing_assets if a.id is not None}
        required = [a[1] for a in assets]
        if all(name in by_name for name in required):
            asset_ids = [by_name[name] for name in required]
            print(f"Refreshing {op_name}: enriching existing seeded campaign.")
        else:
            asset_ids = [db.add_asset(campaign_id, *a) for a in assets]
    else:
        asset_ids = [db.add_asset(campaign_id, *a) for a in assets]

    cred_ids = [
        db.add_credential(campaign_id, asset_ids[1], "password", f"{op_name}\\j.doe", "Summer2026!", "lsass_dump"),
        db.add_credential(campaign_id, asset_ids[2], "hash", f"{op_name}\\svc_app", "aad3b435b51404eeaad3b435b51404ee", "sam_dump"),
        db.add_credential(campaign_id, asset_ids[4], "ticket", f"{op_name}\\krbtgt", "kirbi_blob_redacted", "kerberoast"),
    ]
    db.mark_credential_valid(cred_ids[0], assets[1][2])
    db.mark_credential_valid(cred_ids[1], assets[2][2])
    db.mark_credential_invalid(cred_ids[2], assets[4][2])

    ses1 = db.open_session(campaign_id, asset_ids[1], f"{op_name}-sess-1", "beacon", operator, "scheduled_task")
    ses2 = db.open_session(campaign_id, asset_ids[2], f"{op_name}-sess-2", "shell", operator, "service_abuse")
    db.mark_session_detected(ses2)

    cmd_events = [
        (asset_ids[1], "cmd", "whoami /all", "T1033", True, "LOW"),
        (asset_ids[1], "powershell", "net localgroup administrators", "T1069", True, "MEDIUM"),
        (asset_ids[2], "powershell", "Invoke-Mimikatz -Command sekurlsa::logonpasswords", "T1003", True, "HIGH"),
        (asset_ids[2], "cmd", "wmic /node:DB01 process call create cmd.exe", "T1047", True, "HIGH"),
        (asset_ids[3], "sqlcmd", "SELECT name FROM master..sysdatabases", "T1046", True, "MEDIUM"),
        (asset_ids[4], "powershell", "Get-ADDomainController -Filter *", "T1018", True, "MEDIUM"),
        (asset_ids[4], "powershell", "Get-ADComputer -Filter * -SearchBase 'OU=Servers,DC=corp,DC=local'", "T1087", True, "MEDIUM"),
        (asset_ids[3], "powershell", "Invoke-Command -ComputerName APP01 -ScriptBlock { whoami }", "T1021", True, "MEDIUM"),
        (asset_ids[2], "cmd", "net use \\\\DC01\\c$ /user:svc_app ********", "T1078", True, "HIGH"),
        (asset_ids[1], "cmd", "dir \\\\APP01\\share\\finance", "T1083", True, "LOW"),
    ]
    command_ids = []
    c0.execute("SELECT COUNT(*) AS n FROM command_execution_ledger WHERE campaign_id=?", (campaign_id,))
    existing_cmds = int(c0.fetchone()["n"])
    should_seed_commands = existing_cmds < 10
    for aid, shell, cmd, mitre, success, likelihood in cmd_events:
        if not should_seed_commands:
            break
        cid = db.log_command_execution(
            campaign_id=campaign_id,
            operator=operator,
            asset_id=aid,
            shell_type=shell,
            command=cmd,
            output=f"seed-output::{cmd[:24]}",
            mitre_technique=mitre,
            success=success,
            return_code=0 if success else 1,
            detection_likelihood=likelihood,
            session_id=ses1 if aid == asset_ids[1] else ses2,
        )
        command_ids.append(cid)

    db.log_detection_event(campaign_id, asset_ids[2], "EDR Alert", "credential_dump", "Defender", confidence=0.82)
    db.log_detection_event(campaign_id, asset_ids[3], "SIEM Rule", "lateral_wmi", "Sentinel", confidence=0.71)
    db.log_detection_event(campaign_id, asset_ids[4], "AD Alert", "dcsync_attempt", "DC Logs", confidence=0.64)

    if len(command_ids) < 5:
        c0.execute(
            """SELECT id FROM command_execution_ledger
               WHERE campaign_id=?
               ORDER BY executed_at DESC
               LIMIT 8""",
            (campaign_id,),
        )
        existing = [int(r["id"]) for r in c0.fetchall()]
        command_ids = (command_ids + existing)

    obj1 = db.create_campaign_objective(campaign_id, "Obtain Domain Admin", "Escalate to DA in target AD", priority=1)
    obj2 = db.create_campaign_objective(campaign_id, "Exfiltrate Crown Data", "Proof of access to sensitive DB", priority=2)
    if len(command_ids) >= 5:
        db.link_action_to_objective(obj1, str(command_ids[2]), progress_pct=55.0, evidence="mimikatz output")
        db.link_action_to_objective(obj2, str(command_ids[4]), progress_pct=35.0, evidence="db enumeration")
    db.update_objective_progress(obj1, 72.0, status="in_progress")
    db.update_objective_progress(obj2, 48.0, status="in_progress")

    # Relationship model used by graph + timeline.
    c0.execute("SELECT COUNT(*) AS n FROM relationships WHERE campaign_id=?", (campaign_id,))
    existing_rels = int(c0.fetchone()["n"])
    if existing_rels < 6:
        db.add_relationship(campaign_id, "asset", str(asset_ids[1]), "authenticates_to", "asset", str(asset_ids[2]), 0.88)
        db.add_relationship(campaign_id, "asset", str(asset_ids[2]), "admin_to", "asset", str(asset_ids[3]), 0.79)
        db.add_relationship(campaign_id, "asset", str(asset_ids[3]), "trusts", "asset", str(asset_ids[4]), 0.74)
        db.add_relationship(campaign_id, "credential", str(cred_ids[1]), "delegates", "asset", str(asset_ids[4]), 0.69)
        db.add_relationship(campaign_id, "asset", str(asset_ids[4]), "controls", "asset", str(asset_ids[0]), 0.86)
        db.add_relationship(campaign_id, "asset", str(asset_ids[2]), "authenticates_to", "asset", str(asset_ids[4]), 0.67)

    # Phase 5.5 persistence tables.
    now = datetime.now(timezone.utc)
    c = db.conn.cursor()
    for i in range(8):
        ts = (now - timedelta(minutes=(8 - i) * 12)).isoformat() + "Z"
        pressure = min(95.0, 28.0 + (i * 6.5))
        state = "LOW" if pressure < 40 else "ELEVATED" if pressure < 60 else "HIGH" if pressure < 80 else "CRITICAL"
        c.execute(
            """INSERT INTO detection_pressure_history
               (campaign_id, recorded_at, total_pressure, pressure_state, recent_alerts, repetition_penalty, failed_actions, pressure_trend)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (campaign_id, ts, pressure, state, i // 2, float(i) * 0.6, i // 3, "increasing" if i > 3 else "stable"),
        )

    c.execute(
        """INSERT INTO c2_infrastructure
           (campaign_id, node_name, node_type, exposure_score, reputation_score, burn_probability, burn_level, should_rotate, last_rotated, notes, updated_at)
           VALUES (?, ?, 'redirector', 0.58, 0.62, 0.67, 'hot', 1, ?, 'Seeded hot infra for burn-tracker testing', ?)
           ON CONFLICT(campaign_id, node_name) DO UPDATE SET
             node_type=excluded.node_type,
             exposure_score=excluded.exposure_score,
             reputation_score=excluded.reputation_score,
             burn_probability=excluded.burn_probability,
             burn_level=excluded.burn_level,
             should_rotate=excluded.should_rotate,
             last_rotated=excluded.last_rotated,
             notes=excluded.notes,
             updated_at=excluded.updated_at""",
        (campaign_id, c2_name, (now - timedelta(days=2)).isoformat() + "Z", now.isoformat() + "Z"),
    )

    for idx, opp in enumerate([
        ("T1021", assets[2][1], 88.0, 72.0, 90.0, 44.0, 0.81, "Use authenticated remote service execution", "Prefer SMB exec over WMI"),
        ("T1558", assets[4][1], 83.0, 64.0, 95.0, 61.0, 0.76, "Kerberos abuse likely advances DA objective", "Delay until pressure decreases"),
        ("T1078", assets[3][1], 78.0, 85.0, 70.0, 35.0, 0.74, "Valid creds allow low-noise persistence", "Use constrained delegation path"),
    ]):
        technique, target, score, stealth, value, risk, confidence, explanation, safer = opp
        c.execute(
            """INSERT INTO recommendation_history
               (campaign_id, opportunity_id, action, technique, target_asset, score, stealth, value, risk, confidence, explanation, safer_alternative, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                campaign_id,
                f"{op_name.lower()}-opp-{idx+1}",
                f"Execute {technique} on {target}",
                technique,
                target,
                score,
                stealth,
                value,
                risk,
                confidence,
                explanation,
                safer,
                (now - timedelta(minutes=idx * 7)).isoformat() + "Z",
                db.current_user.id if db.current_user else None,
            ),
        )

    replay_rows = [
        ("observe", operator, asset_ids[1], "T1033", 1, "Initial host identity confirmation"),
        ("simulate", operator, asset_ids[2], "T1003", 1, "OPSEC simulation before credential access"),
        ("execute", operator, asset_ids[2], "T1003", 1, "Credential dump succeeded"),
        ("evaluate", operator, asset_ids[2], "", 1, "Detection pressure increased after EDR event"),
        ("adapt", operator, asset_ids[3], "T1021", 1, "Shifted to lower-noise lateral path"),
    ]
    for event_type, op, aid, tech, success, summary in replay_rows:
        c.execute(
            """INSERT INTO replay_events
               (campaign_id, event_type, event_time, operator, asset_id, technique, success, summary, details_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                campaign_id,
                event_type,
                (now - timedelta(minutes=35 - (replay_rows.index((event_type, op, aid, tech, success, summary)) * 6))).isoformat() + "Z",
                op,
                aid,
                tech,
                success,
                summary,
                json.dumps({"source": "seed_db", "operation": op_name}),
            ),
        )

    c.execute(
        """INSERT INTO operator_tempo_metrics
           (campaign_id, operator_id, recorded_at, actions_per_hour, action_intensity, spike_detected, suggested_slow_window, staging_recommendation)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            campaign_id,
            db.current_user.id if db.current_user else None,
            now.isoformat() + "Z",
            11.4,
            "high",
            1,
            "02:00-04:00 UTC",
            "Stage one objective at a time and insert 5-8 min idle windows.",
        ),
    )

    snapshot = {
        "campaign": op_name,
        "assets": len(assets),
        "credentials": len(cred_ids),
        "pressure": pressure_val_for_rows(c),
        "status": "active",
    }
    c.execute(
        """INSERT INTO cognition_state_cache
           (campaign_id, snapshot_json, detection_pressure, pressure_state, infra_burn, confidence_score, updated_at, updated_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(campaign_id) DO UPDATE SET
             snapshot_json=excluded.snapshot_json,
             detection_pressure=excluded.detection_pressure,
             pressure_state=excluded.pressure_state,
             infra_burn=excluded.infra_burn,
             confidence_score=excluded.confidence_score,
             updated_at=excluded.updated_at,
             updated_by=excluded.updated_by""",
        (
            campaign_id,
            json.dumps(snapshot),
            67.0,
            "HIGH",
            "hot",
            0.78,
            now.isoformat() + "Z",
            db.current_user.id if db.current_user else None,
        ),
    )
    db.conn.commit()


def pressure_val_for_rows(cursor) -> float:
    cursor.execute("SELECT MAX(total_pressure) AS m FROM detection_pressure_history")
    row = cursor.fetchone()
    return float(row["m"]) if row and row["m"] is not None else 0.0


def resolve_active_tenant_id(db: Database) -> str | None:
    """Resolve active tenant UUID for tenant-scoped client API seed data."""
    if getattr(db, "db_backend", "").lower() != "postgres":
        return None
    c = db.conn.cursor()
    try:
        c.execute("SELECT id FROM tenants WHERE active=TRUE ORDER BY created_at ASC LIMIT 1")
        row = c.fetchone()
        if row and row["id"]:
            return str(row["id"])
    except Exception:
        return None
    return "00000000-0000-0000-0000-000000000001"


def seed_client_portal_data(db: Database, campaign_ids: list[int], operator: str, tenant_id: str | None) -> None:
    """Seed findings/reports/remediation/evidence so Phase 7 portal is not empty."""
    if not tenant_id:
        return
    c = db.conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    user_id = db.current_user.id if db.current_user else None

    templates = [
        ("Weak AD Password Policy", 8.4, "T1110", "Password spraying exposed weak domain accounts."),
        ("Unrestricted Lateral Movement Path", 7.6, "T1021", "Service account enabled broad admin pivot paths."),
    ]

    for camp in campaign_ids:
        finding_ids: list[int] = []
        for idx, (title, cvss, mitre, desc) in enumerate(templates, start=1):
            scoped_title = f"{title} [campaign:{camp}]"
            c.execute("SELECT id FROM findings WHERE title=? AND tenant_id=?", (scoped_title, tenant_id))
            row = c.fetchone()
            if row:
                fid = int(row["id"])
            else:
                c.execute(
                    """INSERT INTO findings
                       (title, description, cvss_score, mitre_id, status, evidence, remediation, project_id,
                        cvss_vector, evidence_hash, created_by, last_modified_by, assigned_to, visibility,
                        tags, approval_status, approved_by, approval_timestamp, tenant_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        scoped_title,
                        desc,
                        cvss,
                        mitre,
                        "Open",
                        "Seeded client evidence narrative.",
                        "Apply least privilege and harden privileged groups.",
                        "DEFAULT",
                        "",
                        hashlib.sha256(f"{scoped_title}:{tenant_id}".encode()).hexdigest(),
                        user_id,
                        user_id,
                        user_id,
                        "global",
                        "seed,client,portal",
                        "approved",
                        user_id,
                        now,
                        tenant_id,
                    ),
                )
                fid = int(c.lastrowid)
            finding_ids.append(fid)

            evidence_hash = hashlib.sha256(f"evidence:{tenant_id}:{camp}:{idx}".encode()).hexdigest()
            c.execute(
                """INSERT INTO evidence_items
                   (campaign_id, finding_id, artifact_type, description, sha256_hash, collected_by,
                    collection_method, collected_timestamp, source_host, technique_id,
                    approval_status, approved_by, approval_timestamp, immutable, tenant_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (sha256_hash) DO NOTHING""",
                (
                    camp,
                    fid,
                    "screenshot",
                    f"Seed evidence for finding {fid}",
                    evidence_hash,
                    user_id,
                    "seed_db",
                    now,
                    f"seed-host-{camp}",
                    mitre,
                    "approved",
                    user_id,
                    now,
                    1,
                    tenant_id,
                ),
            )

            task_title = f"Remediate finding {fid}"
            c.execute(
                "SELECT id FROM remediation_tasks WHERE tenant_id=? AND title=?",
                (tenant_id, task_title),
            )
            if not c.fetchone():
                c.execute(
                    """INSERT INTO remediation_tasks (finding_id, title, status, created_at, tenant_id)
                       VALUES (?, ?, ?, ?, ?)""",
                    (fid, task_title, "open", now, tenant_id),
                )

        report_title = f"Client Portal Report [campaign:{camp}]"
        c.execute(
            "SELECT id FROM client_reports WHERE campaign_id=? AND report_title=? AND tenant_id=?",
            (camp, report_title, tenant_id),
        )
        if not c.fetchone():
            c.execute(
                """INSERT INTO client_reports
                   (campaign_id, client_name, report_title, report_date, generated_at, generated_by,
                    filter_rules, include_exec_summary, include_risk_dashboard, include_metrics,
                    branding_logo_url, footer_text, status, file_path, file_hash, created_at, tenant_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    camp,
                    "Default Customer",
                    report_title,
                    now,
                    now,
                    operator,
                    "{}",
                    1,
                    1,
                    1,
                    "",
                    "Seeded by VectorVue",
                    "finalized",
                    "",
                    "",
                    now,
                    tenant_id,
                ),
            )

    db.conn.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed VectorVue DB with realistic Phase 5.5 data.")
    parser.add_argument(
        "--backend",
        choices=["sqlite", "postgres"],
        default=os.environ.get("VV_DB_BACKEND", "sqlite").strip().lower(),
        help="Database backend (default: env VV_DB_BACKEND or sqlite).",
    )
    parser.add_argument(
        "--pg-url",
        default=None,
        help="PostgreSQL URL override. Falls back to VV_DB_URL / VV_DB_* env vars.",
    )
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-pass", default="AdminPassw0rd!")
    parser.add_argument("--client-user-1", default="client_viewer")
    parser.add_argument("--client-pass-1", default="ClientView3r!")
    parser.add_argument("--client-role-1", default="viewer")
    parser.add_argument("--client-user-2", default="client_operator")
    parser.add_argument("--client-pass-2", default="ClientOperat0r!")
    parser.add_argument("--client-role-2", default="operator")
    parser.add_argument(
        "--passphrase",
        default=None,
        help="Database encryption passphrase (defaults to --admin-pass).",
    )
    args = parser.parse_args()

    if Path.cwd() != ROOT:
        # Make relative DB paths deterministic.
        os.chdir(ROOT)

    os.environ["VV_DB_BACKEND"] = args.backend
    if args.backend == "postgres" and args.pg_url:
        os.environ["VV_DB_URL"] = args.pg_url

    encryption_passphrase = args.passphrase or args.admin_pass
    crypto = SessionCrypto()
    if not crypto.derive_key(encryption_passphrase):
        raise RuntimeError("failed to derive encryption key from provided passphrase")
    db = Database(crypto_manager=crypto)
    try:
        # If DB already exists with a different encryption key, fail fast.
        if db.has_users() and not db.verify_or_set_canary():
            raise RuntimeError(
                "existing DB encrypted with another passphrase. "
                "Run scripts/reset_db.py --yes or pass the original --passphrase."
            )

        ensure_login(db, args.admin_user, args.admin_pass)
        camp1 = get_or_create_campaign(db, "OP_REDWOLF_2026")
        camp2 = get_or_create_campaign(db, "OP_NIGHTGLASS_2026")

        seed_campaign(db, camp1, "REDWOLF", args.admin_user, "RW-C2-01")
        seed_campaign(db, camp2, "NIGHTGLASS", args.admin_user, "NG-C2-01")
        tenant_id = resolve_active_tenant_id(db)
        seed_client_portal_data(db, [camp1, camp2], args.admin_user, tenant_id)

        # Ensure two client users for portal/API login after reset+seed workflows.
        client1_status = ensure_user_credentials(
            db,
            args.client_user_1,
            args.client_pass_1,
            _role_from_name(args.client_role_1),
        )
        client2_status = ensure_user_credentials(
            db,
            args.client_user_2,
            args.client_pass_2,
            _role_from_name(args.client_role_2),
        )

        print("Seed complete.")
        print("Campaigns:")
        print(" - OP_REDWOLF_2026")
        print(" - OP_NIGHTGLASS_2026")
        print(f"Backend: {args.backend}")
        print("Login:")
        print(f" - username: {args.admin_user}")
        print(f" - password: {args.admin_pass}")
        print("Client portal users:")
        print(f" - {args.client_user_1} / {args.client_pass_1} (role={args.client_role_1}, status={client1_status})")
        print(f" - {args.client_user_2} / {args.client_pass_2} (role={args.client_role_2}, status={client2_status})")
        print("Tenant ID for client portal login:")
        print(f" - {tenant_id or 'N/A (non-postgres backend)'}")
        print(f" - passphrase used for DB encryption: {encryption_passphrase}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
