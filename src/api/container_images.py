"""Container-Images: SBOM-Ingest, OSV-Ergebnisse, CycloneDX-Export."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, get_current_user
from src.core.database import get_session
from src.ingest.container_scan import SEVERITY_ORDER, scan_all_images, scan_images
from src.models.all_models import Asset, ContainerImage, ContainerPackage, ContainerVuln

router = APIRouter()


class PackageIn(BaseModel):
    name: str
    version: str
    type: Optional[str] = None
    purl: Optional[str] = None


class ImageIn(BaseModel):
    image_id: str
    image_ref: str
    distro: Optional[str] = None
    containers: list[str] = []
    # None = Image unverändert, Paketliste nicht erneut mitgeschickt
    packages: Optional[list[PackageIn]] = None


class IngestIn(BaseModel):
    images: list[ImageIn]


class ImageRow(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    hostname: Optional[str]
    image_ref: str
    image_id: str
    distro: Optional[str]
    containers: list[str]
    package_count: int
    vuln_counts: dict[str, int]
    fixable: int
    sbom_at: Optional[datetime]
    osv_at: Optional[datetime]
    last_seen_at: Optional[datetime]


def _visible(asset: Asset, ctx: AuthContext) -> bool:
    allowed = ctx.filter_tags()
    return not allowed or bool(asset.tags and set(asset.tags) & set(allowed))


async def _image_for(image_pk: uuid.UUID, session: AsyncSession, ctx: AuthContext) -> ContainerImage:
    image = await session.get(ContainerImage, image_pk)
    asset = await session.get(Asset, image.asset_id) if image else None
    if not image or not asset or not _visible(asset, ctx):
        raise HTTPException(404, "Image nicht gefunden")
    return image


@router.post("/assets/{asset_id}", status_code=202)
async def ingest_images(
    asset_id: uuid.UUID,
    body: IngestIn,
    background: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """Vollständige Liste der laufenden Images eines Hosts; andere werden entfernt."""
    asset = await session.get(Asset, asset_id)
    if not asset or not _visible(asset, ctx):
        raise HTTPException(404, f"Asset {asset_id} nicht gefunden")

    existing = {
        img.image_id: img for img in (await session.execute(
            select(ContainerImage).where(ContainerImage.asset_id == asset_id)
        )).scalars().all()
    }
    now = datetime.utcnow()
    to_scan: list[uuid.UUID] = []
    for item in body.images:
        image = existing.get(item.image_id)
        if image is None:
            image = ContainerImage(id=uuid.uuid4(), asset_id=asset_id, image_id=item.image_id,
                                   image_ref=item.image_ref)
            session.add(image)
            await session.flush()
        image.image_ref = item.image_ref
        image.containers = sorted(set(item.containers))
        image.last_seen_at = now
        if item.distro:
            image.distro = item.distro
        if item.packages is not None:
            await session.execute(delete(ContainerPackage).where(ContainerPackage.image_pk == image.id))
            unique = {(p.name, p.version, p.purl): p for p in item.packages}
            session.add_all(
                ContainerPackage(image_pk=image.id, pkg_name=p.name[:300], pkg_version=p.version[:200],
                                 pkg_type=p.type, purl=(p.purl or "")[:800] or None)
                for p in unique.values()
            )
            image.sbom_at = now
            to_scan.append(image.id)

    current = {item.image_id for item in body.images}
    removed = [img.id for image_id, img in existing.items() if image_id not in current]
    if removed:
        await session.execute(delete(ContainerImage).where(ContainerImage.id.in_(removed)))
    await session.commit()

    if to_scan:
        background.add_task(scan_images, to_scan)
    return {"images": len(body.images), "scan_queued": len(to_scan), "removed": len(removed)}


@router.get("", response_model=list[ImageRow])
async def list_images(
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    rows = (await session.execute(
        select(ContainerImage, Asset).join(Asset, Asset.id == ContainerImage.asset_id)
        .where(Asset.is_active == True, Asset.is_archived == False)  # noqa: E712
    )).all()
    package_counts = Counter(dict((await session.execute(
        select(ContainerPackage.image_pk, func.count())
        .group_by(ContainerPackage.image_pk)
    )).all()))
    vulns = (await session.execute(
        select(ContainerVuln.image_pk, ContainerVuln.severity, ContainerVuln.fixed_version)
    )).all()
    per_image: dict[uuid.UUID, Counter] = {}
    fixable: Counter = Counter()
    for pk, severity, fixed in vulns:
        per_image.setdefault(pk, Counter())[severity] += 1
        if fixed:
            fixable[pk] += 1

    out = [
        ImageRow(
            id=img.id, asset_id=asset.id, hostname=asset.hostname, image_ref=img.image_ref,
            image_id=img.image_id, distro=img.distro, containers=img.containers or [],
            package_count=package_counts[img.id],
            vuln_counts={s: per_image.get(img.id, {}).get(s, 0) for s in SEVERITY_ORDER},
            fixable=fixable[img.id], sbom_at=img.sbom_at, osv_at=img.osv_at, last_seen_at=img.last_seen_at,
        )
        for img, asset in rows if _visible(asset, ctx)
    ]
    out.sort(key=lambda r: tuple(-r.vuln_counts[s] for s in SEVERITY_ORDER))
    return out


@router.get("/{image_pk}/vulns")
async def image_vulns(
    image_pk: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    await _image_for(image_pk, session, ctx)
    rows = (await session.execute(
        select(ContainerVuln).where(ContainerVuln.image_pk == image_pk)
    )).scalars().all()
    rows.sort(key=lambda v: (SEVERITY_ORDER.index(v.severity), -(v.cvss or 0), v.pkg_name))
    return [
        {"vuln_id": v.vuln_id, "osv_id": v.osv_id, "pkg_name": v.pkg_name, "pkg_version": v.pkg_version,
         "ecosystem": v.ecosystem, "severity": v.severity, "cvss": v.cvss,
         "fixed_version": v.fixed_version, "summary": v.summary}
        for v in rows
    ]


@router.get("/{image_pk}/packages")
async def image_packages(
    image_pk: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    await _image_for(image_pk, session, ctx)
    rows = (await session.execute(
        select(ContainerPackage).where(ContainerPackage.image_pk == image_pk)
        .order_by(ContainerPackage.pkg_type, ContainerPackage.pkg_name)
    )).scalars().all()
    return [{"name": p.pkg_name, "version": p.pkg_version, "type": p.pkg_type, "purl": p.purl} for p in rows]


@router.get("/{image_pk}/cyclonedx")
async def image_cyclonedx(
    image_pk: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    ctx: AuthContext = Depends(get_current_user),
):
    """SBOM des Images als CycloneDX 1.6 (JSON), inkl. bekannter Schwachstellen."""
    image = await _image_for(image_pk, session, ctx)
    packages = (await session.execute(
        select(ContainerPackage).where(ContainerPackage.image_pk == image_pk)
    )).scalars().all()
    vulns = (await session.execute(
        select(ContainerVuln).where(ContainerVuln.image_pk == image_pk)
    )).scalars().all()
    by_name = {}
    for p in packages:
        by_name.setdefault(p.pkg_name, p)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": (image.sbom_at or datetime.utcnow()).replace(tzinfo=timezone.utc).isoformat(),
            "component": {"type": "container", "name": image.image_ref, "version": image.image_id,
                          "bom-ref": image.image_id},
        },
        "components": [
            {"type": "library", "name": p.pkg_name, "version": p.pkg_version,
             **({"purl": p.purl, "bom-ref": p.purl} if p.purl else {"bom-ref": f"{p.pkg_name}@{p.pkg_version}"})}
            for p in {(x.purl or f"{x.pkg_name}@{x.pkg_version}"): x for x in packages}.values()
        ],
        "vulnerabilities": [
            {"id": v.vuln_id, "description": v.summary or "",
             "ratings": [{"severity": v.severity.lower(), **({"score": v.cvss, "method": "CVSSv3"} if v.cvss else {})}],
             "affects": [{"ref": (by_name[v.pkg_name].purl if v.pkg_name in by_name and by_name[v.pkg_name].purl
                                  else image.image_id)}]}
            for v in vulns
        ],
    }


@router.post("/scan", status_code=202)
async def rescan_images(
    background: BackgroundTasks,
    ctx: AuthContext = Depends(get_current_user),
):
    """Alle Images neu gegen OSV abgleichen (neue Lücken bei unveränderten Images)."""
    background.add_task(scan_all_images)
    return {"status": "gestartet"}
