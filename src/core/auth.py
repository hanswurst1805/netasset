"""JWT + API-Key Authentifizierung & Tag-basierte Zugriffskontrolle."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.database import get_session
from src.models.auth import APIKey, User

# ---------------------------------------------------------------------------
# Krypto-Helpers
# ---------------------------------------------------------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def generate_api_key() -> tuple[str, str, str]:
    """Gibt (raw_key, prefix, hash) zurück. raw_key wird nur einmal angezeigt."""
    raw = "sk-na-" + secrets.token_urlsafe(32)
    prefix = raw[:12]
    hashed = pwd_context.hash(raw)
    return raw, prefix, hashed

def create_access_token(user_id: str, role: str, allowed_tags: list[str]) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.jwt_expire_hours)
    return jwt.encode(
        {"sub": user_id, "role": role, "tags": allowed_tags, "exp": expire},
        settings.jwt_secret,
        algorithm="HS256",
    )

# ---------------------------------------------------------------------------
# Auth-Kontext
# ---------------------------------------------------------------------------

class AuthContext(BaseModel):
    user_id: uuid.UUID
    username: str
    role: str           # admin | user
    allowed_tags: list[str]  # leer = keine Einschränkung

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def filter_tags(self) -> list[str] | None:
        """None = kein Filter nötig (admin), Liste = erlaubte Tags."""
        if self.is_admin or not self.allowed_tags:
            return None
        return self.allowed_tags

# ---------------------------------------------------------------------------
# FastAPI Security Schemes
# ---------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def _user_from_jwt(token: str, session: AsyncSession) -> Optional[AuthContext]:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except JWTError:
        return None
    user = await session.get(User, uuid.UUID(payload["sub"]))
    if not user or not user.is_active:
        return None
    return AuthContext(
        user_id=user.id,
        username=user.username,
        role=user.role,
        allowed_tags=user.allowed_tags or [],
    )


async def _user_from_api_key(raw_key: str, session: AsyncSession) -> Optional[AuthContext]:
    prefix = raw_key[:12]
    stmt = select(APIKey).where(APIKey.key_prefix == prefix, APIKey.is_active == True)
    result = await session.execute(stmt)
    api_key = result.scalar_one_or_none()
    if not api_key or not verify_password(raw_key, api_key.key_hash):
        return None

    user = await session.get(User, api_key.user_id)
    if not user or not user.is_active:
        return None

    # last_used aktualisieren
    api_key.last_used_at = datetime.now(timezone.utc)
    await session.flush()

    # Tags: explizite Key-Tags überschreiben User-Tags
    tags = api_key.allowed_tags if api_key.allowed_tags is not None else (user.allowed_tags or [])
    return AuthContext(
        user_id=user.id,
        username=user.username,
        role=user.role,
        allowed_tags=tags,
    )


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Security(api_key_header),
    session: AsyncSession = Depends(get_session),
) -> AuthContext:
    """FastAPI-Dependency: liefert AuthContext oder 401."""
    if token:
        ctx = await _user_from_jwt(token, session)
        if ctx:
            return ctx
    if api_key:
        ctx = await _user_from_api_key(api_key, session)
        if ctx:
            return ctx
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Nicht authentifiziert",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_admin(ctx: AuthContext = Depends(get_current_user)) -> AuthContext:
    if not ctx.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin-Rechte erforderlich")
    return ctx
