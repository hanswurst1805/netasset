"""Embedding-Model Wrapper (sentence-transformers, lokal)."""

from functools import lru_cache

import numpy as np
from sentence_transformers import SentenceTransformer

from src.core.config import settings


@lru_cache(maxsize=1)
def get_model() -> SentenceTransformer:
    return SentenceTransformer(settings.embedding_model)


def embed(text: str) -> list[float]:
    model = get_model()
    vec: np.ndarray = model.encode(text, normalize_embeddings=True)
    return vec.tolist()


def embed_batch(texts: list[str]) -> list[list[float]]:
    model = get_model()
    vecs: np.ndarray = model.encode(texts, normalize_embeddings=True, batch_size=64)
    return vecs.tolist()
