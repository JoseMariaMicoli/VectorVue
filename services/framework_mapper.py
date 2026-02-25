from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from analytics.db import session_scope


FRAMEWORK_CATALOG: dict[str, dict[str, str]] = {
    "ISO27001": {"name": "ISO 27001", "version": "2022"},
    "SOC2": {"name": "SOC 2 Type II", "version": "2017"},
    "HIPAA": {"name": "HIPAA Security Rule", "version": "164"},
    "ISO27799": {"name": "ISO 27799 Healthcare", "version": "2016"},
    "SOX": {"name": "SOX ITGC", "version": "baseline"},
    "GLBA": {"name": "GLBA Safeguards", "version": "latest"},
    "FFIEC": {"name": "FFIEC Cybersecurity", "version": "latest"},
    "DORA": {"name": "DORA Resilience", "version": "2025"},
    "GDPR32": {"name": "GDPR Article 32", "version": "2018"},
    "LATAM_FIN": {"name": "LATAM Financial Baseline", "version": "2026"},
}

CONTROL_CATALOG: list[dict[str, str]] = [
    {"code": "CTRL_DETECT_001", "title": "Detection Logging Coverage", "domain": "monitoring", "severity": "high"},
    {"code": "CTRL_ACCESS_001", "title": "Privileged Access Accountability", "domain": "identity", "severity": "critical"},
    {"code": "CTRL_IR_001", "title": "Incident Response Timeliness", "domain": "response", "severity": "high"},
    {"code": "CTRL_EVID_001", "title": "Evidence Integrity Chain", "domain": "governance", "severity": "critical"},
    {"code": "CTRL_MON_001", "title": "Continuous Monitoring Discipline", "domain": "monitoring", "severity": "medium"},
]

FRAMEWORK_CONTROL_LINKS: list[dict[str, str]] = [
    {"framework": "ISO27001", "control": "CTRL_DETECT_001", "requirement_ref": "A.8.16", "source_event_type": "DETECTION_LOGGED"},
    {"framework": "ISO27001", "control": "CTRL_ACCESS_001", "requirement_ref": "A.5.16", "source_event_type": "FINDING_ACKNOWLEDGED"},
    {"framework": "SOC2", "control": "CTRL_MON_001", "requirement_ref": "CC7.2", "source_event_type": "DASHBOARD_VIEWED"},
    {"framework": "SOC2", "control": "CTRL_IR_001", "requirement_ref": "CC7.4", "source_event_type": "REMEDIATION_COMPLETED"},
    {"framework": "HIPAA", "control": "CTRL_ACCESS_001", "requirement_ref": "164.312(a)", "source_event_type": "FINDING_VIEWED"},
    {"framework": "HIPAA", "control": "CTRL_IR_001", "requirement_ref": "164.308(a)(6)", "source_event_type": "REMEDIATION_OPENED"},
    {"framework": "ISO27799", "control": "CTRL_EVID_001", "requirement_ref": "7.10", "source_event_type": "REPORT_DOWNLOADED"},
    {"framework": "SOX", "control": "CTRL_EVID_001", "requirement_ref": "ITGC-LOG", "source_event_type": "OPERATOR_ACTION"},
    {"framework": "GLBA", "control": "CTRL_MON_001", "requirement_ref": "314.4(c)", "source_event_type": "DASHBOARD_VIEWED"},
    {"framework": "FFIEC", "control": "CTRL_DETECT_001", "requirement_ref": "DE.CM-1", "source_event_type": "DETECTION_LOGGED"},
    {"framework": "DORA", "control": "CTRL_IR_001", "requirement_ref": "Art-11", "source_event_type": "REMEDIATION_COMPLETED"},
    {"framework": "GDPR32", "control": "CTRL_ACCESS_001", "requirement_ref": "Art32-1b", "source_event_type": "FINDING_ACKNOWLEDGED"},
    {"framework": "LATAM_FIN", "control": "CTRL_MON_001", "requirement_ref": "LATAM-MON-1", "source_event_type": "DASHBOARD_VIEWED"},
]


def ensure_framework_catalog() -> None:
    now = datetime.now(timezone.utc)
    with session_scope() as db:
        for code, item in FRAMEWORK_CATALOG.items():
            db.execute(
                text(
                    """INSERT INTO frameworks (code, name, version, description, active, created_at)
                       VALUES (:code, :name, :version, :description, TRUE, :created_at)
                       ON CONFLICT (code) DO UPDATE SET
                         name=EXCLUDED.name,
                         version=EXCLUDED.version,
                         description=EXCLUDED.description,
                         active=TRUE"""
                ),
                {
                    "code": code,
                    "name": item["name"],
                    "version": item["version"],
                    "description": f"{item['name']} automated assurance mapping",
                    "created_at": now,
                },
            )

        for ctl in CONTROL_CATALOG:
            db.execute(
                text(
                    """INSERT INTO controls (code, title, description, domain, severity, created_at)
                       VALUES (:code, :title, :description, :domain, :severity, :created_at)
                       ON CONFLICT (code) DO UPDATE SET
                         title=EXCLUDED.title,
                         description=EXCLUDED.description,
                         domain=EXCLUDED.domain,
                         severity=EXCLUDED.severity"""
                ),
                {
                    "code": ctl["code"],
                    "title": ctl["title"],
                    "description": f"{ctl['title']} derived from operational behavior",
                    "domain": ctl["domain"],
                    "severity": ctl["severity"],
                    "created_at": now,
                },
            )

        fw_ids = {str(r["code"]): int(r["id"]) for r in db.execute(text("SELECT id, code FROM frameworks")).mappings()}
        ctl_ids = {str(r["code"]): int(r["id"]) for r in db.execute(text("SELECT id, code FROM controls")).mappings()}
        for link in FRAMEWORK_CONTROL_LINKS:
            framework_id = fw_ids.get(link["framework"])
            control_id = ctl_ids.get(link["control"])
            if framework_id is None or control_id is None:
                continue
            db.execute(
                text(
                    """INSERT INTO control_mappings (framework_id, control_id, requirement_ref, source_event_type, created_at)
                       VALUES (:framework_id, :control_id, :requirement_ref, :source_event_type, :created_at)
                       ON CONFLICT (framework_id, control_id, requirement_ref) DO UPDATE SET
                         source_event_type=EXCLUDED.source_event_type"""
                ),
                {
                    "framework_id": framework_id,
                    "control_id": control_id,
                    "requirement_ref": link["requirement_ref"],
                    "source_event_type": link["source_event_type"],
                    "created_at": now,
                },
            )


def list_frameworks_with_latest_scores(tenant_id: str) -> list[dict[str, Any]]:
    with session_scope() as db:
        rows = db.execute(
            text(
                """SELECT f.code, f.name, f.version,
                          s.score AS latest_score,
                          s.coverage_percent AS latest_coverage_percent,
                          s.calculated_at AS latest_calculated_at
                   FROM frameworks f
                   LEFT JOIN LATERAL (
                     SELECT score, coverage_percent, calculated_at
                     FROM compliance_scores cs
                     WHERE cs.tenant_id=:tenant_id AND cs.framework=f.code
                     ORDER BY cs.calculated_at DESC
                     LIMIT 1
                   ) s ON TRUE
                   WHERE f.active=TRUE
                   ORDER BY f.code"""
            ),
            {"tenant_id": tenant_id},
        ).mappings().all()
        return [dict(r) for r in rows]


def list_framework_controls(tenant_id: str, framework_code: str) -> list[dict[str, Any]]:
    with session_scope() as db:
        rows = db.execute(
            text(
                """SELECT c.id AS control_id,
                          c.code AS control_code,
                          c.title AS control_title,
                          cm.requirement_ref,
                          COALESCE(sh.state, 'insufficient_evidence') AS state,
                          sh.evaluated_at,
                          COALESCE(sh.details_json, '{}'::jsonb) AS details_json
                   FROM frameworks f
                   JOIN control_mappings cm ON cm.framework_id=f.id
                   JOIN controls c ON c.id=cm.control_id
                   LEFT JOIN LATERAL (
                     SELECT state, evaluated_at, details_json
                     FROM control_state_history h
                     WHERE h.tenant_id=:tenant_id AND h.control_id=c.id
                     ORDER BY h.evaluated_at DESC
                     LIMIT 1
                   ) sh ON TRUE
                   WHERE f.code=:framework_code
                   ORDER BY c.code"""
            ),
            {"tenant_id": tenant_id, "framework_code": framework_code},
        ).mappings().all()
        return [dict(r) for r in rows]
