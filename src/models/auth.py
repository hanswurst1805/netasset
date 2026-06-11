"""Auth-Modelle: User und APIKey."""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.all_models import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[Optional[str]] = mapped_column(String(200), unique=True)
    password_hash: Mapped[str] = mapped_column(String(200), nullable=False)

    # admin sieht alles, user ist auf allowed_tags eingeschränkt
    role: Mapped[str] = mapped_column(String(20), default="user")

    # Leere Liste = keine Einschränkung (nur für admins sinnvoll)
    # Befüllt = nur Assets sehen, die mindestens einen dieser Tags haben
    allowed_tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), default=list)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)

    # Zwei-Faktor-Authentifizierung (TOTP)
    totp_secret: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_backup_codes: Mapped[Optional[list]] = mapped_column(ARRAY(String), nullable=True)

    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)  # Anzeige: "sk-na-abc123"
    key_hash: Mapped[str] = mapped_column(String(200), nullable=False)   # bcrypt-Hash
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))

    # None = Rechte des Users erben, befüllt = explizit einschränken
    allowed_tags: Mapped[Optional[list]] = mapped_column(ARRAY(String), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="api_keys")
