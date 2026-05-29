"""
NetAsset API – FastAPI Hauptanwendung
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.core.config import settings
from src.api import assets, sbom, cve, processes, discovery


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown


app = FastAPI(
    title="NetAsset API",
    description="CMDB & Security Intelligence Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(assets.router,    prefix="/api/v1/assets",    tags=["Assets"])
app.include_router(sbom.router,      prefix="/api/v1/sbom",      tags=["SBOM"])
app.include_router(cve.router,       prefix="/api/v1/cve",       tags=["CVE & Security"])
app.include_router(processes.router, prefix="/api/v1/processes", tags=["Business Processes"])
app.include_router(discovery.router, prefix="/api/v1/discovery", tags=["Discovery"])


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
