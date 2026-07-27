"""Einfache In-Process-Bremse gegen Passwort- und TOTP-Raten.

Bewusst ohne Redis/slowapi: NetAsset läuft als einzelner API-Container,
ein Dict im Prozess reicht. Bei mehreren Replicas müsste das durch einen
gemeinsamen Store ersetzt werden (siehe HINWEIS unten).

Gezählt wird pro Konto (Username bzw. User-ID), nicht pro IP:
- Hinter Caddy sähen alle Requests wie dieselbe IP aus – ein einzelner
  Angreifer würde damit sämtliche Nutzer aussperren.
- `X-Forwarded-For` ist clientseitig fälschbar und taugt nicht als
  Sicherheitsgrenze.

Tradeoff: Wer einen Usernamen kennt, kann dessen Login gezielt für
`window_seconds` ausbremsen. Das ist eine Verzögerung, keine Sperre – der
Zähler läuft von selbst ab und ein erfolgreicher Login setzt ihn zurück.
"""

from __future__ import annotations

import threading
import time

from fastapi import HTTPException, status


class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        """Abgelaufene Einträge entfernen, damit das Dict nicht wächst."""
        cutoff = now - self.window_seconds
        for key in [k for k, v in self._hits.items() if not v or v[-1] < cutoff]:
            del self._hits[key]

    def check(self, key: str) -> None:
        """Zählt einen Versuch. Wirft 429, sobald das Limit erreicht ist."""
        key = key.strip().lower()
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            attempts = [t for t in self._hits.get(key, []) if t > now - self.window_seconds]
            if len(attempts) >= self.max_attempts:
                retry_after = int(self.window_seconds - (now - attempts[0])) + 1
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    "Zu viele Fehlversuche. Bitte später erneut versuchen.",
                    headers={"Retry-After": str(max(retry_after, 1))},
                )
            attempts.append(now)
            self._hits[key] = attempts

    def reset(self, key: str) -> None:
        """Nach erfolgreicher Anmeldung den Zähler leeren."""
        with self._lock:
            self._hits.pop(key.strip().lower(), None)


# Passwort-Login: 10 Versuche pro 5 Minuten und Konto.
login_limiter = RateLimiter(max_attempts=10, window_seconds=300)

# TOTP/Backup-Codes: enger, da nur 6 Ziffern zu raten sind.
mfa_limiter = RateLimiter(max_attempts=5, window_seconds=300)
