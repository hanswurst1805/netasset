from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # Risk-Schwellwerte
    risk_high_threshold: float = 7.0
    risk_medium_threshold: float = 4.0


settings = Settings()
