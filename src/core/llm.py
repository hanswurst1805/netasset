"""OpenRouter-Client (OpenAI-kompatibler Endpunkt)."""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from openai import OpenAI as _OpenAI

from src.core.config import settings


@lru_cache(maxsize=1)
def get_llm_client() -> _OpenAI:
    from openai import OpenAI  # lazy – erst bei echtem LLM-Call laden

    if not settings.openrouter_api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY nicht gesetzt. "
            "Bitte in .env eintragen: OPENROUTER_API_KEY=sk-or-..."
        )
    return OpenAI(
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        default_headers={
            "HTTP-Referer": "https://github.com/netasset",
            "X-Title": "NetAsset CMDB",
        },
    )


def llm_complete(prompt: str, max_tokens: int = 800) -> str:
    """Synchroner LLM-Call via OpenRouter."""
    client = get_llm_client()
    response = client.chat.completions.create(
        model=settings.llm_model,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content or ""
