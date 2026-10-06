"""CyberRisk FastAPI application."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import ai, analysis, assess, dashboard, etl, registers, reports, settings as settings_api, simulation as simulation_api, workspaces as workspaces_api
from app.api.common import install_error_handlers
from app.ai.llm import resolve_provider
from app.config import get_settings
import re

from fastapi import Request
from fastapi.responses import JSONResponse

from app.db import session as dbs
from app.db.session import connect, get_engine, init_schema
from app.tenancy import workspaces as tenancy
from app.rag import ingest as rag_ingest

WEB = Path(__file__).parent / "web"


@asynccontextmanager
async def lifespan(_: FastAPI):
    logging.basicConfig(level=get_settings().log_level)
    tenancy.reset_cache()
    init_schema(get_engine())
    tenancy.ensure_defaults()
    with connect() as conn:  # knowledge base ingestion is idempotent (checksum-based)
        rag_ingest.ingest_knowledge_base(conn)
    yield
    from app.simulation import runner as sim_runner
    sim_runner.stop_all()


app = FastAPI(title="CyberRisk", version="1.0.0", description="Cyber risk, GRC and AI governance platform", lifespan=lifespan)
install_error_handlers(app)
app.include_router(dashboard.router)
app.include_router(registers.router)
app.include_router(etl.router)
app.include_router(ai.router)
app.include_router(settings_api.router)
app.include_router(workspaces_api.router)
app.include_router(assess.router)
app.include_router(analysis.router)
app.include_router(reports.router)
app.include_router(simulation_api.router)

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")


@app.middleware("http")
async def workspace_context(request: Request, call_next):
    """Tenant routing: every /api call runs against exactly one workspace database, chosen by the X-Workspace header."""
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    slug = request.headers.get("x-workspace", dbs.DEFAULT_WORKSPACE).strip().lower()
    if not _SLUG.match(slug) or not tenancy.exists(slug):
        return JSONResponse(status_code=404, content={"error": {"code": 404, "message": f"Unknown workspace '{slug[:41]}'"}})
    token = dbs.set_workspace(slug)
    try:
        return await call_next(request)
    finally:
        dbs._current_workspace.reset(token)


@app.get("/api/health", tags=["health"])
def health():
    s = get_settings()
    return {"status": "ok", "app": s.app_name, "database": "sqlite", "ai_configured": resolve_provider().provider != "none"}  # never expose the key itself


app.mount("/static", StaticFiles(directory=WEB), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(WEB / "index.html")
