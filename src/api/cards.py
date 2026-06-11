"""
Asset Karteikarten API — generiert strukturierte Dokumente für RAG/LLM-Training.
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.card_generator import (
    TEMPLATES, CardTemplate, generate_card, load_asset_data
)
from src.core.database import get_session
from src.models.all_models import Asset

router = APIRouter()


class TemplateOut(BaseModel):
    id: str
    name: str
    description: str
    sections: list[str]


class CardRequest(BaseModel):
    template_id: str = "full"
    format: str = "markdown"   # markdown | json | text


@router.get("/templates", response_model=list[TemplateOut])
async def list_templates(_: AuthContext = Depends(get_current_user)):
    """Verfügbare Templates."""
    return [
        TemplateOut(
            id=t.id,
            name=t.name,
            description=t.description,
            sections=[s.key for s in t.sections if s.enabled],
        )
        for t in TEMPLATES.values()
    ]


@router.post("/assets/{asset_id}")
async def generate_asset_card(
    asset_id: str,
    body: CardRequest,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Generiert eine Karteikarte für ein einzelnes Asset."""
    template = TEMPLATES.get(body.template_id)
    if not template:
        raise HTTPException(400, f"Template '{body.template_id}' nicht gefunden. "
                                 f"Verfügbar: {list(TEMPLATES.keys())}")

    data = await load_asset_data(asset_id, session)
    if not data:
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")

    # Tag-Check
    if allowed := ctx.filter_tags():
        if not data.asset.tags or not set(data.asset.tags) & set(allowed):
            raise HTTPException(403, "Kein Zugriff auf dieses Asset")

    content = generate_card(data, template, body.format)

    media_types = {
        "markdown": "text/markdown",
        "json": "application/json",
        "text": "text/plain",
    }
    extensions = {"markdown": "md", "json": "json", "text": "txt"}
    name = data.asset.hostname or asset_id
    filename = f"{name}_{body.template_id}.{extensions.get(body.format, 'md')}"

    return Response(
        content=content.encode("utf-8"),
        media_type=media_types.get(body.format, "text/markdown"),
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/export")
async def export_all_cards(
    body: CardRequest,
    asset_type: Optional[str] = None,
    exposure_level: Optional[str] = None,
    tag: Optional[str] = None,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """
    Exportiert Karteikarten für alle (oder gefilterte) Assets als ZIP.
    Enthält eine Datei pro Asset + eine Metadaten-Datei (manifest.json).
    """
    template = TEMPLATES.get(body.template_id)
    if not template:
        raise HTTPException(400, f"Template '{body.template_id}' nicht gefunden")

    # Assets laden
    stmt = select(Asset).where(Asset.is_active == True, Asset.is_archived == False)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if exposure_level:
        stmt = stmt.where(Asset.exposure_level == exposure_level)
    if tag:
        stmt = stmt.where(Asset.tags.contains([tag]))
    if allowed := ctx.filter_tags():
        stmt = stmt.where(Asset.tags.overlap(allowed))

    result = await session.execute(stmt)
    assets = result.scalars().all()

    if not assets:
        raise HTTPException(404, "Keine Assets gefunden")

    ext = {"markdown": "md", "json": "json", "text": "txt"}.get(body.format, "md")
    manifest = {
        "generated_at": __import__("datetime").datetime.utcnow().isoformat(),
        "template": body.template_id,
        "format": body.format,
        "total_assets": len(assets),
        "cards": [],
    }

    # ZIP in Memory erstellen
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for asset in assets:
            data = await load_asset_data(str(asset.id), session)
            if not data:
                continue
            content = generate_card(data, template, body.format)
            name = (asset.hostname or str(asset.id)).replace("/", "_").replace(" ", "_")
            filename = f"cards/{name}.{ext}"
            zf.writestr(filename, content.encode("utf-8"))

            manifest["cards"].append({
                "file": filename,
                "asset_id": str(asset.id),
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "asset_type": asset.asset_type,
                "exposure_level": asset.exposure_level,
            })

        # JSON-L Export (alle Karten als Lines, gut für LLM-Training)
        if body.format == "json":
            jsonl_lines = []
            for card_info in manifest["cards"]:
                # JSON bereits in den Dateien, auch als JSONL anbieten
                pass

        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))

        # Auch als JSONL (ein JSON-Objekt pro Zeile — ideal für LLM-Training)
        if body.format in ("json", "markdown"):
            jsonl = []
            for asset in assets:
                data = await load_asset_data(str(asset.id), session)
                if not data:
                    continue
                from src.core.card_generator import generate_json
                card_json = generate_json(data, template)
                # Markdown als "content"-Feld hinzufügen
                card_json["content"] = generate_card(data, template, "markdown")
                jsonl.append(json.dumps(card_json, ensure_ascii=False))
            zf.writestr("cards.jsonl", "\n".join(jsonl).encode("utf-8"))

    zip_buffer.seek(0)
    return Response(
        content=zip_buffer.read(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="netasset_cards_{body.template_id}.zip"'
        },
    )
