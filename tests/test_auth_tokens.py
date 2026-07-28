"""Token-Scope-Tests – laufen ohne Datenbank (Session wird gefaked).

Hintergrund: `create_mfa_token()` stellt das Zwischen-Token aus, das
`/auth/login` NACH der Passwortprüfung, aber VOR der TOTP-Prüfung
zurückgibt. Es ist mit demselben JWT-Secret signiert wie ein echtes
Access-Token. Ohne Scope-Prüfung in `_user_from_jwt()` könnte man es
direkt als `Authorization: Bearer ...` verwenden und damit 2FA komplett
umgehen.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from jose import jwt

from src.core.auth import _user_from_jwt, create_access_token, create_mfa_token
from src.core.config import settings

USER_ID = uuid.uuid4()


class _FakeSession:
    """Liefert immer denselben aktiven Admin-User zurück."""

    async def get(self, model, key):
        return SimpleNamespace(
            id=USER_ID,
            username="test-user",
            role="admin",
            allowed_tags=[],
            is_active=True,
        )


def _token(claims: dict) -> str:
    claims.setdefault("exp", datetime.now(timezone.utc) + timedelta(hours=1))
    return jwt.encode(claims, settings.jwt_secret, algorithm="HS256")


async def test_mfa_token_ist_kein_access_token():
    """Das 2FA-Zwischen-Token darf NICHT als Login durchgehen."""
    ctx = await _user_from_jwt(create_mfa_token(str(USER_ID)), _FakeSession())
    assert ctx is None


async def test_access_token_wird_akzeptiert():
    ctx = await _user_from_jwt(
        create_access_token(str(USER_ID), "admin", []), _FakeSession()
    )
    assert ctx is not None
    assert ctx.user_id == USER_ID
    assert ctx.is_admin


async def test_token_ohne_scope_bleibt_gueltig():
    """Vor dem Fix ausgestellte Tokens sollen nicht schlagartig ungültig werden."""
    ctx = await _user_from_jwt(
        _token({"sub": str(USER_ID), "role": "admin", "tags": []}), _FakeSession()
    )
    assert ctx is not None


@pytest.mark.parametrize("scope", ["2fa", "refresh", "", "beliebig"])
async def test_fremde_scopes_werden_abgelehnt(scope):
    ctx = await _user_from_jwt(_token({"sub": str(USER_ID), "scope": scope}), _FakeSession())
    assert ctx is None


async def test_kaputtes_sub_gibt_kein_500():
    """Ungültige UUID im sub-Claim → sauber abgelehnt statt ValueError."""
    assert await _user_from_jwt(_token({"sub": "keine-uuid"}), _FakeSession()) is None
    assert await _user_from_jwt(_token({"role": "admin"}), _FakeSession()) is None


async def test_fremdes_secret_wird_abgelehnt():
    fremd = jwt.encode(
        {"sub": str(USER_ID), "scope": "access",
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        "ein-anderes-secret",
        algorithm="HS256",
    )
    assert await _user_from_jwt(fremd, _FakeSession()) is None
