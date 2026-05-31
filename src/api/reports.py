"""Asset Report Upload API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.ingest.lynis_parser import detect_report_type, parse_lynis_report
from src.models.all_models import Asset, AssetReport

router = APIRouter()

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


class ReportSummary(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    report_type: str
    filename: Optional[str]
    created_at: datetime
    hardening_index: Optional[int] = None
    warnings_count: int = 0
    suggestions_count: int = 0


class ReportDetail(ReportSummary):
    parsed_data: dict


@router.post("/assets/{asset_id}", response_model=ReportDetail, status_code=201)
async def upload_report(
    asset_id: uuid.UUID,
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """
    Lädt einen externen Audit-Report hoch (z.B. Lynis lynis-report.dat).

    Unterstützte Formate:
    - Lynis: lynis-report.dat (key=value Format)
    """
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")

    # Datei lesen
    content_bytes = await file.read()
    if len(content_bytes) > MAX_FILE_SIZE:
        raise HTTPException(413, f"Datei zu groß (max. 5 MB)")

    try:
        content = content_bytes.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(400, "Datei konnte nicht als Text gelesen werden")

    # Report-Typ erkennen und parsen
    report_type = detect_report_type(content, file.filename or "")

    if report_type == "lynis":
        parsed = parse_lynis_report(content)
    else:
        parsed = {"raw_lines": len(content.splitlines()), "type": report_type}

    # In DB speichern
    report = AssetReport(
        asset_id=asset_id,
        report_type=report_type,
        filename=file.filename,
        parsed_data=parsed,
        raw_content=content if len(content) < 100_000 else content[:100_000] + "\n[gekürzt]",
    )
    session.add(report)
    await session.flush()
    await session.refresh(report)

    return ReportDetail(
        id=report.id,
        asset_id=report.asset_id,
        report_type=report.report_type,
        filename=report.filename,
        created_at=report.created_at,
        hardening_index=parsed.get("hardening_index"),
        warnings_count=len(parsed.get("warnings", [])),
        suggestions_count=len(parsed.get("suggestions", [])),
        parsed_data=parsed,
    )


@router.get("/assets/{asset_id}", response_model=list[ReportSummary])
async def list_reports(
    asset_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    """Alle Reports eines Assets."""
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")

    result = await session.execute(
        select(AssetReport)
        .where(AssetReport.asset_id == asset_id)
        .order_by(desc(AssetReport.created_at))
    )
    reports = result.scalars().all()

    return [
        ReportSummary(
            id=r.id,
            asset_id=r.asset_id,
            report_type=r.report_type,
            filename=r.filename,
            created_at=r.created_at,
            hardening_index=r.parsed_data.get("hardening_index"),
            warnings_count=len(r.parsed_data.get("warnings", [])),
            suggestions_count=len(r.parsed_data.get("suggestions", [])),
        )
        for r in reports
    ]


@router.get("/assets/{asset_id}/{report_id}", response_model=ReportDetail)
async def get_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    report = await session.get(AssetReport, report_id)
    if not report or report.asset_id != asset_id:
        raise HTTPException(404, "Report nicht gefunden")

    p = report.parsed_data
    return ReportDetail(
        id=report.id,
        asset_id=report.asset_id,
        report_type=report.report_type,
        filename=report.filename,
        created_at=report.created_at,
        hardening_index=p.get("hardening_index"),
        warnings_count=len(p.get("warnings", [])),
        suggestions_count=len(p.get("suggestions", [])),
        parsed_data=p,
    )


@router.delete("/assets/{asset_id}/{report_id}", status_code=204)
async def delete_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    report = await session.get(AssetReport, report_id)
    if not report or report.asset_id != asset_id:
        raise HTTPException(404, "Report nicht gefunden")
    await session.delete(report)
