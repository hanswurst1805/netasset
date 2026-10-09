from pydantic_settings import BaseSettings, SettingsConfigDict

# Platzhalter, die in .env.example / docker-compose stehen und niemals
# in einer echten Installation gültig sein dürfen.
INSECURE_SECRETS = {
    "",
    "CHANGE_ME_IN_PRODUCTION_USE_RANDOM_32_CHARS",
    "CHANGE_ME_USE_RANDOM_32_CHARS",
}
INSECURE_PASSWORDS = {"", "changeme", "CHANGE_ME", "CHANGE_ME_STRONG_PASSWORD", "password", "admin"}
MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://netasset:changeme@localhost:5432/netasset"
    nvd_api_key: str = ""
    embedding_model: str = "all-MiniLM-L6-v2"
    log_level: str = "INFO"

    # LLM via OpenRouter
    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    llm_model: str = "anthropic/claude-sonnet-4-5"
    # Beliebiges OpenRouter-Modell, z.B.:
    #   anthropic/claude-sonnet-4-5
    #   openai/gpt-4o
    #   google/gemini-2.0-flash-001

    # Auth
    jwt_secret: str = "CHANGE_ME_IN_PRODUCTION_USE_RANDOM_32_CHARS"
    jwt_expire_hours: int = 8
    initial_admin_password: str = "changeme"  # Wird beim ersten Start gesetzt

    # Risk-Schwellwerte
    risk_high_threshold: float = 7.0
    risk_medium_threshold: float = 4.0

    # CORS: kommagetrennte Liste erlaubter Origins, z.B.
    #   CORS_ORIGINS=https://netasset.example.com,https://bl.example.com
    # Leer = keine Cross-Origin-Requests (Standard – Frontend und API laufen
    # hinter Caddy auf derselben Origin, im Dev-Betrieb proxyt Vite).
    cors_origins: str = ""

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()


class InsecureConfigError(RuntimeError):
    """Konfiguration ist für den Produktivbetrieb unsicher."""


def validate_startup_settings(cfg: Settings = settings) -> None:
    """Bricht den Start ab, wenn das JWT-Secret unsicher ist.

    Bewusst beim Start und nicht beim Import geprüft: Tests, Alembic und
    Hilfsskripte sollen das Modul importieren können, ohne ein echtes
    Secret zu brauchen. Ein ungültiges Secret bedeutet, dass jeder mit
    Repo-Zugriff Admin-Tokens signieren kann.
    """
    secret = cfg.jwt_secret
    if secret in INSECURE_SECRETS or len(secret) < MIN_SECRET_LENGTH:
        raise InsecureConfigError(
            "JWT_SECRET ist nicht gesetzt oder zu schwach "
            f"(mindestens {MIN_SECRET_LENGTH} Zeichen, kein Platzhalter aus .env.example).\n"
            "Neues Secret erzeugen:  openssl rand -base64 48\n"
            "Danach in .env.prod als JWT_SECRET=... eintragen.\n"
            "Achtung: Ein neues Secret invalidiert alle bestehenden Logins."
        )


def initial_admin_password_is_weak(cfg: Settings = settings) -> bool:
    return cfg.initial_admin_password in INSECURE_PASSWORDS
