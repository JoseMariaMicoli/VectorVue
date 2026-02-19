# Copyright (c) 2026 Jose Maria Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

"""Phase 7A tenant-isolated public client read-only API router."""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import MetaData, Table, and_, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from api_contract.client_api_models import Paginated, RiskSummary
from app.client_api.dependencies import client_rate_limit, get_db, engine
from app.client_api.schemas import (
    ClientEvidenceGalleryItem,
    ClientEvidenceGalleryResponse,
    ClientFindingDetail,
    ClientRemediationResponse,
    ClientRemediationTask,
    ClientReportItem,
)
from schemas.client_safe import ClientFinding
from security.tenant_auth import get_current_tenant
from utils.url_builder import build_public_url


router = APIRouter(
    prefix="/api/v1/client",
    tags=["client-public"],
    dependencies=[Depends(client_rate_limit)],
)

_metadata = MetaData()


def _table(name: str, db_engine: Engine = engine) -> Table:
    return Table(name, _metadata, autoload_with=db_engine)


def _require_tenant_column(table: Table) -> None:
    if "tenant_id" not in table.c:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Table '{table.name}' missing tenant isolation column",
        )


def _severity_expr(min_severity: str, findings: Table):
    sev = min_severity.lower()
    if sev == "critical":
        return findings.c.cvss_score >= 9.0
    if sev == "high":
        return and_(findings.c.cvss_score >= 7.0, findings.c.cvss_score < 9.0)
    if sev == "medium":
        return and_(findings.c.cvss_score >= 4.0, findings.c.cvss_score < 7.0)
    if sev == "low":
        return and_(findings.c.cvss_score >= 0.0, findings.c.cvss_score < 4.0)
    raise HTTPException(status_code=400, detail="severity must be low|medium|high|critical")


def _safe_text(value: Any, default: str = "") -> str:
    return default if value is None else str(value)


def _download_signature(path: str, exp: int) -> str:
    secret = os.environ.get("CLIENT_DOWNLOAD_SIGNING_KEY", "vectorvue-phase7a-signing-key")
    payload = f"{path}:{exp}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _verify_download_signature(path: str, exp: int, sig: str) -> bool:
    expected = _download_signature(path, exp)
    return hmac.compare_digest(expected, sig)


@router.get("/findings", response_model=Paginated[ClientFinding])
def get_findings(
    request: Request,
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    findings = _table("findings")
    _require_tenant_column(findings)

    filters = [
        findings.c.tenant_id == str(tenant_id),
        findings.c.approval_status == "approved",
    ]
    if status_filter:
        filters.append(findings.c.status == status_filter)
    if severity:
        filters.append(_severity_expr(severity, findings))

    total = db.execute(select(func.count()).select_from(findings).where(and_(*filters))).scalar_one()
    offset = (page - 1) * page_size

    rows = db.execute(
        select(
            findings.c.id,
            findings.c.title,
            findings.c.cvss_score,
            findings.c.mitre_id,
            findings.c.approval_status,
            findings.c.visibility.label("visibility_status"),
        )
        .where(and_(*filters))
        .order_by(findings.c.id.desc())
        .offset(offset)
        .limit(page_size)
    ).mappings().all()

    items = [
        ClientFinding(
            id=int(r["id"]),
            title=_safe_text(r["title"]),
            severity=None,
            cvss_score=float(r["cvss_score"]) if r["cvss_score"] is not None else None,
            mitre_id=_safe_text(r.get("mitre_id"), None),
            created_at=None,
            visibility_status=_safe_text(r.get("visibility_status"), "restricted"),
            approval_status=_safe_text(r.get("approval_status"), "pending"),
        )
        for r in rows
    ]
    return Paginated[ClientFinding](items=items, page=page, page_size=page_size, total=int(total))


@router.get("/findings/{finding_id}", response_model=ClientFindingDetail)
def get_finding_by_id(
    finding_id: int,
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    findings = _table("findings")
    _require_tenant_column(findings)

    row = db.execute(
        select(
            findings.c.id,
            findings.c.title,
            findings.c.description,
            findings.c.status,
            findings.c.cvss_score,
            findings.c.mitre_id,
            findings.c.visibility.label("visibility_status"),
            findings.c.approval_status,
        ).where(
            and_(
                findings.c.id == finding_id,
                findings.c.tenant_id == str(tenant_id),
                findings.c.approval_status == "approved",
            )
        )
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")

    return ClientFindingDetail(
        id=int(row["id"]),
        title=_safe_text(row["title"]),
        description=_safe_text(row.get("description"), None),
        severity=None,
        status=_safe_text(row.get("status"), "Open"),
        cvss_score=float(row["cvss_score"]) if row["cvss_score"] is not None else None,
        mitre_id=_safe_text(row.get("mitre_id"), None),
        visibility_status=_safe_text(row.get("visibility_status"), "restricted"),
        approval_status=_safe_text(row.get("approval_status"), "pending"),
    )


@router.get("/evidence/{finding_id}", response_model=ClientEvidenceGalleryResponse)
def get_evidence_gallery(
    request: Request,
    finding_id: int,
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    evidence = _table("evidence_items")
    _require_tenant_column(evidence)

    rows = db.execute(
        select(
            evidence.c.id,
            evidence.c.finding_id,
            evidence.c.artifact_type,
            evidence.c.description,
            evidence.c.collected_timestamp,
            evidence.c.approval_status,
        ).where(
            and_(
                evidence.c.finding_id == finding_id,
                evidence.c.tenant_id == str(tenant_id),
                evidence.c.approval_status == "approved",
            )
        )
    ).mappings().all()

    items: list[ClientEvidenceGalleryItem] = []
    for row in rows:
        evidence_id = int(row["id"])
        exp = int(time.time()) + 900
        path = f"/api/v1/client/evidence/{finding_id}"
        sig = _download_signature(path=f"{path}:{evidence_id}", exp=exp)
        signed_path = f"{path}?evidence_id={evidence_id}&exp={exp}&sig={sig}"
        items.append(
            ClientEvidenceGalleryItem(
                id=evidence_id,
                finding_id=int(row["finding_id"]),
                artifact_type=_safe_text(row.get("artifact_type"), "artifact"),
                description=_safe_text(row.get("description"), None),
                collected_at=None,
                approval_status=_safe_text(row.get("approval_status"), "pending"),
                download_url=build_public_url(signed_path, request),
            )
        )

    return ClientEvidenceGalleryResponse(finding_id=finding_id, items=items)


@router.get("/reports", response_model=Paginated[ClientReportItem])
def get_reports(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    reports = _table("client_reports")
    _require_tenant_column(reports)

    filters = [reports.c.tenant_id == str(tenant_id)]
    total = db.execute(select(func.count()).select_from(reports).where(and_(*filters))).scalar_one()

    offset = (page - 1) * page_size
    rows = db.execute(
        select(
            reports.c.id,
            reports.c.report_title,
            reports.c.report_date,
            reports.c.status,
        )
        .where(and_(*filters))
        .order_by(reports.c.id.desc())
        .offset(offset)
        .limit(page_size)
    ).mappings().all()

    items: list[ClientReportItem] = []
    for row in rows:
        rid = int(row["id"])
        download_path = f"/api/v1/client/reports/{rid}/download"
        items.append(
            ClientReportItem(
                id=rid,
                title=_safe_text(row.get("report_title"), "Untitled Report"),
                report_date=None,
                status=_safe_text(row.get("status"), "draft"),
                download_url=build_public_url(download_path, request),
            )
        )

    return Paginated[ClientReportItem](items=items, page=page, page_size=page_size, total=int(total))


@router.get("/reports/{report_id}/download")
def download_report(
    request: Request,
    report_id: int,
    exp: int | None = Query(default=None),
    sig: str | None = Query(default=None),
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    reports = _table("client_reports")
    _require_tenant_column(reports)

    row = db.execute(
        select(
            reports.c.id,
            reports.c.report_title,
            reports.c.file_path,
            reports.c.tenant_id,
        ).where(and_(reports.c.id == report_id, reports.c.tenant_id == str(tenant_id)))
    ).mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="Report not found")

    if exp is not None or sig is not None:
        if exp is None or sig is None:
            raise HTTPException(status_code=403, detail="Invalid signed URL")
        if exp < int(time.time()):
            raise HTTPException(status_code=403, detail="Signed URL expired")
        path = f"/api/v1/client/reports/{report_id}/download"
        if not _verify_download_signature(path, exp, sig):
            raise HTTPException(status_code=403, detail="Invalid signed URL")

    file_path = _safe_text(row.get("file_path"), "")
    if not file_path:
        raise HTTPException(status_code=404, detail="Report file unavailable")

    p = Path(file_path)
    if not p.exists() or not p.is_file():
        raise HTTPException(status_code=404, detail="Report file missing")

    filename = f"{_safe_text(row.get('report_title'), 'report')}.pdf"
    media_type = "application/pdf" if p.suffix.lower() == ".pdf" else "application/octet-stream"
    _ = build_public_url(request.url.path, request)
    return FileResponse(path=str(p), filename=filename, media_type=media_type)


@router.get("/risk", response_model=RiskSummary)
def get_risk_summary(
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    findings = _table("findings")
    _require_tenant_column(findings)

    rows = db.execute(
        select(findings.c.cvss_score).where(
            and_(findings.c.tenant_id == str(tenant_id), findings.c.approval_status == "approved")
        )
    ).all()
    scores = [float(row[0]) for row in rows if row[0] is not None]

    critical = sum(1 for s in scores if s >= 9.0)
    high = sum(1 for s in scores if 7.0 <= s < 9.0)
    medium = sum(1 for s in scores if 4.0 <= s < 7.0)
    low = sum(1 for s in scores if 0.0 <= s < 4.0)
    score = round(sum(scores) / len(scores), 2) if scores else 0.0

    return RiskSummary(
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        score=score,
        last_updated=None,
    )


@router.get("/remediation", response_model=ClientRemediationResponse)
def get_remediation_tasks(
    tenant_id: UUID = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    tasks = _table("remediation_tasks")
    _require_tenant_column(tasks)

    rows = db.execute(
        select(
            tasks.c.id,
            tasks.c.finding_id,
            tasks.c.title,
            tasks.c.status,
        )
        .where(tasks.c.tenant_id == str(tenant_id))
        .order_by(tasks.c.id.desc())
    ).mappings().all()

    items = [
        ClientRemediationTask(
            id=int(r["id"]),
            finding_id=r.get("finding_id"),
            title=_safe_text(r.get("title"), "task"),
            status=_safe_text(r.get("status"), "open"),
            priority=None,
            due_date=None,
        )
        for r in rows
    ]
    return ClientRemediationResponse(items=items)
