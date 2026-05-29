"""Auth-Endpunkte: Login, User-Verwaltung, API-Keys."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import (
    AuthContext,
    create_access_token,
    generate_api_key,
    get_current_user,
    hash_password,
    require_admin,
    verify_password,
)
from src.core.database import get_session
from src.models.auth import APIKey, User

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    allowed_tags: list[str]

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
    last_used_at: Optional[str]
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
    token = create_access_token(str(user.id), user.role, user.allowed_tags or [])
    return TokenResponse(access_token=token, role=user.role, allowed_tags=user.allowed_tags or [])


@router.get("/me", response_model=UserOut)
async def me(
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    user = await session.get(User, ctx.user_id)
    return user

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
async def revoke_api_key(
    key_id: uuid.UUID,
    ctx: AuthContext = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    api_key = await session.get(APIKey, key_id)
    if not api_key:
        raise HTTPException(404, "API-Key nicht gefunden")
    if api_key.user_id != ctx.user_id and not ctx.is_admin:
        raise HTTPException(403, "Kein Zugriff")
    api_key.is_active = False
    await session.flush()
