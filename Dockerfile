FROM docker.io/python:3.12-slim

WORKDIR /app

# uv für schnelle Dependency-Installation
RUN pip install --no-cache-dir uv

# Dependencies zuerst (Layer-Cache)
COPY pyproject.toml .
RUN uv pip install --system --no-cache .

COPY . .

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
