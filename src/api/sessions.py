"""
Audit-Sessions – Jumpbox SSH-Session-Aufzeichnung.

Zwei Quellen, korreliert über `session_uuid`:
  - Jumpbox: lädt die komplette Terminal-Aufzeichnung hoch (POST /ingest)
  - Zielhost: lädt die saubere Kommandoliste hoch (POST /{uuid}/commands)

Beide Endpunkte sind upsert-fähig: egal welche Quelle zuerst eintrifft,
die Session-Zeile wird angelegt bzw. ergänzt.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user, require_admin
from src.core.database import get_session
from src.models.all_models import Asset, AuditSession, AuditSessionCommand

router = APIRouter()

MAX_RECORDING_SIZE = 10 * 1024 * 1024  # 10 MB Typescript


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class SessionIngest(BaseModel):
    session_uuid: str = Field(..., max_length=64)
    operator: str = Field(..., max_length=120)
    jumpbox_host: Optional[str] = None
    target_host: str = Field(..., max_length=255)
    target_user: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    duration_sec: Optional[int] = None
    exit_code: Optional[int] = None
    recording_format: str = "script-typescript"
    recording: Optional[str] = None
    timing: Optional[str] = None
    client_ip: Optional[str] = None


class CommandIn(BaseModel):
    seq: int
    executed_at: Optional[datetime] = None
    command: str
    cwd: Optional[str] = None
    os_user: Optional[str] = None


class CommandOut(CommandIn):
    model_config = {"from_attributes": True}


class SessionSummary(BaseModel):
    id: uuid.UUID
    session_uuid: str
    operator: str
    jumpbox_host: Optional[str]
    target_host: str
    target_user: Optional[str]
    target_asset_id: Optional[uuid.UUID]
    started_at: Optional[datetime]
    ended_at: Optional[datetime]
    duration_sec: Optional[int]
    exit_code: Optional[int]
    has_recording: bool = False
    command_count: int = 0
    created_at: datetime
    model_config = {"from_attributes": True}


class SessionDetail(SessionSummary):
    recording_format: str
    recording: Optional[str]
    timing: Optional[str]
    commands: list[CommandOut] = []


# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------

def _naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Wandelt tz-aware Zeitstempel in naive UTC (Spalten sind TIMESTAMP WITHOUT TIME ZONE)."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


async def _resolve_asset(target_host: str, session: AsyncSession) -> Optional[uuid.UUID]:
    """Versucht target_host (Hostname oder IP) einem Asset zuzuordnen."""
    if not target_host:
        return None
    host = target_host.strip().lower()
    stmt = select(Asset.id).where(
        Asset.is_active == True,
        Asset.is_archived == False,
        or_(
            func.lower(Asset.ip_address) == host,
            func.lower(Asset.hostname) == host,
            func.lower(Asset.fqdn) == host,
        ),
    ).limit(1)
    return (await session.execute(stmt)).scalar_one_or_none()


async def _get_or_create_session(
    session_uuid: str, target_host: str, operator: str, session: AsyncSession
) -> AuditSession:
    existing = (await session.execute(
        select(AuditSession).where(AuditSession.session_uuid == session_uuid)
    )).scalar_one_or_none()
    if existing:
        return existing
    sess = AuditSession(
        session_uuid=session_uuid,
        operator=operator,
        target_host=target_host,
        target_asset_id=await _resolve_asset(target_host, session),
    )
    session.add(sess)
    await session.flush()
    return sess


# ---------------------------------------------------------------------------
# Ingest (Jumpbox)
# ---------------------------------------------------------------------------

@router.post("/ingest", status_code=201)
async def ingest_session(
    body: SessionIngest,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Jumpbox lädt eine abgeschlossene Session-Aufzeichnung hoch."""
    if body.recording and len(body.recording) > MAX_RECORDING_SIZE:
        raise HTTPException(413, "Aufzeichnung zu groß (max. 10 MB)")

    sess = await _get_or_create_session(
        body.session_uuid, body.target_host, body.operator, session
    )

    # Metadaten setzen/aktualisieren
    sess.operator = body.operator
    sess.jumpbox_host = body.jumpbox_host
    sess.target_host = body.target_host
    sess.target_user = body.target_user
    sess.started_at = _naive_utc(body.started_at)
    sess.ended_at = _naive_utc(body.ended_at)
    sess.duration_sec = body.duration_sec
    sess.exit_code = body.exit_code
    sess.recording_format = body.recording_format
    sess.recording = body.recording
    sess.timing = body.timing
    sess.client_ip = body.client_ip
    if not sess.target_asset_id:
        sess.target_asset_id = await _resolve_asset(body.target_host, session)

    await session.flush()
    return {"id": str(sess.id), "session_uuid": sess.session_uuid,
            "target_asset_id": str(sess.target_asset_id) if sess.target_asset_id else None}


@router.post("/{session_uuid}/commands", status_code=201)
async def ingest_commands(
    session_uuid: str,
    commands: list[CommandIn],
    target_host: Optional[str] = None,
    operator: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Zielhost lädt die ausgeführten Kommandos für eine Session hoch."""
    sess = await _get_or_create_session(
        session_uuid, target_host or "unbekannt", operator or "unbekannt", session
    )

    # Bereits vorhandene seq-Nummern überspringen (idempotenter Re-Upload)
    existing_seqs = set((await session.execute(
        select(AuditSessionCommand.seq).where(AuditSessionCommand.session_id == sess.id)
    )).scalars().all())

    added = 0
    for c in commands:
        if c.seq in existing_seqs:
            continue
        session.add(AuditSessionCommand(
            session_id=sess.id,
            seq=c.seq,
            executed_at=_naive_utc(c.executed_at),
            command=c.command,
            cwd=c.cwd,
            os_user=c.os_user,
        ))
        added += 1

    await session.flush()
    return {"id": str(sess.id), "commands_added": added}


# ---------------------------------------------------------------------------
# Lesen
# ---------------------------------------------------------------------------

@router.get("", response_model=list[SessionSummary])
async def list_sessions(
    target_host: Optional[str] = None,
    operator: Optional[str] = None,
    asset_id: Optional[uuid.UUID] = None,
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    stmt = select(AuditSession).order_by(AuditSession.started_at.desc().nullslast())
    if target_host:
        stmt = stmt.where(func.lower(AuditSession.target_host) == target_host.strip().lower())
    if operator:
        stmt = stmt.where(AuditSession.operator == operator)
    if asset_id:
        stmt = stmt.where(AuditSession.target_asset_id == asset_id)
    stmt = stmt.limit(min(limit, 500))

    sessions = (await session.execute(stmt)).scalars().all()

    # command_count je Session
    counts: dict = {}
    if sessions:
        counts = dict((await session.execute(
            select(AuditSessionCommand.session_id, func.count())
            .where(AuditSessionCommand.session_id.in_([s.id for s in sessions]))
            .group_by(AuditSessionCommand.session_id)
        )).all())

    out = []
    for s in sessions:
        summ = SessionSummary.model_validate(s)
        summ.has_recording = bool(s.recording)
        summ.command_count = counts.get(s.id, 0)
        out.append(summ)
    return out


@router.get("/{session_id}", response_model=SessionDetail)
async def get_session_detail(
    session_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(get_current_user),
):
    sess = await session.get(AuditSession, session_id)
    if not sess:
        raise HTTPException(404, "Session nicht gefunden")

    cmds = (await session.execute(
        select(AuditSessionCommand)
        .where(AuditSessionCommand.session_id == sess.id)
        .order_by(AuditSessionCommand.seq)
    )).scalars().all()

    detail = SessionDetail.model_validate(sess)
    detail.has_recording = bool(sess.recording)
    detail.command_count = len(cmds)
    detail.commands = [CommandOut.model_validate(c) for c in cmds]
    return detail


@router.delete("/{session_id}", status_code=204)
async def delete_session(
    session_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    _: AuthContext = Depends(require_admin),
):
    sess = await session.get(AuditSession, session_id)
    if not sess:
        raise HTTPException(404, "Session nicht gefunden")
    await session.delete(sess)
