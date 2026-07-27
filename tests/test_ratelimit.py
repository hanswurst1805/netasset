"""Tests für die Login-/TOTP-Bremse (ohne Datenbank)."""

from __future__ import annotations

import time

import pytest
from fastapi import HTTPException

from src.core.ratelimit import RateLimiter


def test_limit_greift_nach_max_attempts():
    rl = RateLimiter(max_attempts=3, window_seconds=300)
    for _ in range(3):
        rl.check("admin")
    with pytest.raises(HTTPException) as exc:
        rl.check("admin")
    assert exc.value.status_code == 429
    assert int(exc.value.headers["Retry-After"]) > 0


def test_konten_sind_unabhaengig():
    """Ein gesperrtes Konto darf andere Nutzer nicht aussperren."""
    rl = RateLimiter(max_attempts=2, window_seconds=300)
    rl.check("opfer")
    rl.check("opfer")
    rl.check("jemand-anderes")  # darf nicht werfen


def test_reset_nach_erfolgreichem_login():
    rl = RateLimiter(max_attempts=2, window_seconds=300)
    rl.check("admin")
    rl.check("admin")
    rl.reset("admin")
    rl.check("admin")  # darf nicht werfen


@pytest.mark.parametrize("variante", ["ADMIN", " Admin ", "aDmIn"])
def test_schreibweise_umgeht_die_bremse_nicht(variante):
    rl = RateLimiter(max_attempts=2, window_seconds=300)
    rl.check("admin")
    rl.check("admin")
    with pytest.raises(HTTPException):
        rl.check(variante)


def test_fenster_laeuft_ab():
    rl = RateLimiter(max_attempts=1, window_seconds=1)
    rl.check("u")
    with pytest.raises(HTTPException):
        rl.check("u")
    time.sleep(1.1)
    rl.check("u")  # nach Ablauf wieder erlaubt


def test_abgelaufene_eintraege_werden_aufgeraeumt():
    """Sonst wäre die Bremse selbst ein Speicherleck."""
    rl = RateLimiter(max_attempts=5, window_seconds=1)
    for i in range(500):
        rl.check(f"user{i}")
    time.sleep(1.1)
    rl.check("noch-einer")
    assert len(rl._hits) == 1
