"""Auth-Endpunkte: Login, User-Verwaltung, API-Keys."""

from __future__ import annotations

import io
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import (
    AuthContext,
    consume_backup_code,
    create_access_token,
    create_mfa_token,
    decode_mfa_token,
    generate_api_key,
    generate_backup_codes,
    generate_totp_secret,
    get_current_user,
    hash_backup_codes,
    hash_password,
    require_admin,
    totp_provisioning_uri,
    verify_password,
    verify_totp_code,
)
from src.core.database import get_session
from src.models.auth import APIKey, User

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    role: Optional[str] = None
    allowed_tags: Optional[list[str]] = None
    mfa_required: bool = False
    mfa_token: Optional[str] = None


class MFAVerify(BaseModel):
    mfa_token: str
    code: str


class TOTPSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str
    qr_code_svg: str


class TOTPCode(BaseModel):
    code: str


class TOTPEnableResponse(BaseModel):
    backup_codes: list[str]

class UserCreate(BaseModel):
    username: str
    email: Optional[str] = None
    password: str
    role: str = "user"
    allowed_tags: list[str] = []

class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    allowed_tags: Optional[list[str]] = None
    is_active: Optional[bool] = None

class UserOut(BaseModel):
    id: uuid.UUID
    username: str
    email: Optional[str]
    role: str
    allowed_tags: list[str]
    is_active: bool
    totp_enabled: bool = False
    model_config = {"from_attributes": True}

class APIKeyCreate(BaseModel):
    name: str
    allowed_tags: Optional[list[str]] = None  # None = User-Tags erben

class APIKeyOut(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    allowed_tags: Optional[list[str]]
    is_active: bool
    last_used_at: Optional[datetime] = None
    model_config = {"from_attributes": True}

class APIKeyCreated(APIKeyOut):
    raw_key: str  # Nur einmal sichtbar!

# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@router.post("/login", response_model=TokenResponse)
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    session: AsyncSession = Depends(get_session),
):
    stmt = select(User).where(User.username == form.username, User.is_active == True)
    user = (await session.execute(stmt)).scalar_one_or_none()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Benutzername oder Passwort falsch",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.totp_enabled:
        return TokenResponse(mfa_required=True, mfa_token=create_mfa_token(str(user.id)))

    token = create_access_token(str(user.id), user.role, user.allowed_tags or [])
    return TokenResponse(access_token=token, role=user.role, allowed_tags=user.allowed_tags or [])


@router.post("/2fa/verify", response_model=TokenResponse)
async def verify_2fa(
    body: MFAVerify,
    session: AsyncSession = Depends(get_session),
):
    """Zweiter Schritt des Logins: TOTP- oder Backup-Code prüfen."""
    user_id = decode_mfa_token(body.mfa_token)
    if not user_id:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2FA-Token ungültig oder abgelaufen")

    user = await session.get(User, user_id)
    if not user or not user.is_active or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2FA nicht verfügbar")

    if verify_totp_code(user.totp_secret, body.code):
        token = create_access_token(str(user.id), user.role, user.allowed_tags or [])
        return TokenResponse(access_token=token, role=user.role, allowed_tags=user.allowed_tags or [])

    remaining = consume_backup_code(user.totp_backup_codes or [], body.code)
    if remaining is not None:
        user.totp_backup_codes = remaining
        await session.flush()
        token = create_access_token(str(user.id), user.role, user.allowed_tags or [])
        return TokenResponse(access_token=token, role=user.role, allowed_tags=user.allowed_tags or [])

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Code ungültig")


@router.get("/me", response_model=UserOut)
async def me(
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    user = await session.get(User, ctx.user_id)
    return user

# ---------------------------------------------------------------------------
# Zwei-Faktor-Authentifizierung (eigener Account)
# ---------------------------------------------------------------------------

@router.post("/2fa/setup", response_model=TOTPSetupResponse)
async def setup_2fa(
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Erzeugt ein neues TOTP-Secret (noch nicht aktiv) und liefert QR-Code + Secret."""
    import qrcode
    import qrcode.image.svg

    user = await session.get(User, ctx.user_id)
    if user.totp_enabled:
        raise HTTPException(400, "2FA ist bereits aktiviert")

    secret = generate_totp_secret()
    user.totp_secret = secret
    await session.flush()

    uri = totp_provisioning_uri(secret, user.username)

    buf = io.BytesIO()
    qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage).save(buf)
    qr_svg = buf.getvalue().decode("utf-8")

    return TOTPSetupResponse(secret=secret, otpauth_uri=uri, qr_code_svg=qr_svg)


@router.post("/2fa/enable", response_model=TOTPEnableResponse)
async def enable_2fa(
    body: TOTPCode,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Bestätigt das in /2fa/setup erzeugte Secret mit einem TOTP-Code und aktiviert 2FA."""
    user = await session.get(User, ctx.user_id)
    if user.totp_enabled:
        raise HTTPException(400, "2FA ist bereits aktiviert")
    if not user.totp_secret:
        raise HTTPException(400, "2FA-Setup nicht gestartet (POST /auth/2fa/setup)")
    if not verify_totp_code(user.totp_secret, body.code):
        raise HTTPException(400, "Code ungültig")

    backup_codes = generate_backup_codes()
    user.totp_enabled = True
    user.totp_backup_codes = hash_backup_codes(backup_codes)
    await session.flush()

    return TOTPEnableResponse(backup_codes=backup_codes)


@router.post("/2fa/disable", status_code=204)
async def disable_2fa(
    body: TOTPCode,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Deaktiviert 2FA. Erfordert einen gültigen TOTP- oder Backup-Code."""
    user = await session.get(User, ctx.user_id)
    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(400, "2FA ist nicht aktiviert")

    valid = verify_totp_code(user.totp_secret, body.code)
    if not valid and consume_backup_code(user.totp_backup_codes or [], body.code) is not None:
        valid = True
    if not valid:
        raise HTTPException(400, "Code ungültig")

    user.totp_enabled = False
    user.totp_secret = None
    user.totp_backup_codes = None
    await session.flush()

# ---------------------------------------------------------------------------
# User-Verwaltung (nur Admin)
# ---------------------------------------------------------------------------

@router.get("/users", response_model=list[UserOut])
async def list_users(
    _: AuthContext = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(User))
    return result.scalars().all()


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreate,
    ctx: AuthContext = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    existing = (await session.execute(
        select(User).where(User.username == body.username)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(400, f"Username '{body.username}' bereits vergeben")

    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        allowed_tags=body.allowed_tags,
        created_by=ctx.user_id,
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)
    return user


@router.put("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    ctx: AuthContext = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(404, "User nicht gefunden")

    if body.password:
        user.password_hash = hash_password(body.password)
    if body.email is not None:
        user.email = body.email
    if body.role is not None:
        user.role = body.role
    if body.allowed_tags is not None:
        user.allowed_tags = body.allowed_tags
    if body.is_active is not None:
        user.is_active = body.is_active

    await session.flush()
    await session.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    ctx: AuthContext = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
):
    if user_id == ctx.user_id:
        raise HTTPException(400, "Eigenen Account nicht löschbar")
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(404, "User nicht gefunden")
    await session.delete(user)

# ---------------------------------------------------------------------------
# API-Keys
# ---------------------------------------------------------------------------

@router.get("/apikeys", response_model=list[APIKeyOut])
async def list_api_keys(
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    # Admins sehen alle Keys, User nur ihre eigenen
    if ctx.is_admin:
        result = await session.execute(select(APIKey))
    else:
        result = await session.execute(select(APIKey).where(APIKey.user_id == ctx.user_id))
    return result.scalars().all()


@router.post("/apikeys", response_model=APIKeyCreated, status_code=201)
async def create_api_key(
    body: APIKeyCreate,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    raw_key, prefix, key_hash = generate_api_key()
    api_key = APIKey(
        name=body.name,
        key_prefix=prefix,
        key_hash=key_hash,
        user_id=ctx.user_id,
        allowed_tags=body.allowed_tags,
    )
    session.add(api_key)
    await session.flush()
    await session.refresh(api_key)
    return APIKeyCreated(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        allowed_tags=api_key.allowed_tags,
        is_active=api_key.is_active,
        last_used_at=None,
        raw_key=raw_key,
    )


@router.delete("/apikeys/{key_id}", status_code=204)
async def delete_api_key(
    key_id: uuid.UUID,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    api_key = await session.get(APIKey, key_id)
    if not api_key:
        raise HTTPException(404, "API-Key nicht gefunden")
    if api_key.user_id != ctx.user_id and not ctx.is_admin:
        raise HTTPException(403, "Kein Zugriff")
    await session.delete(api_key)
    await session.flush()
