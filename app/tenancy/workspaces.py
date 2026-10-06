"""Workspaces = tenants. One SQLite database per workspace gives hard data isolation; a small platform registry lists them.

kinds: demo (bundled synthetic org), organization (customer/engagement), sandbox (no-organisation ad-hoc analysis)
"""
from __future__ import annotations

import re
import shutil
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.db import session as db

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,40}$")
RESERVED = {"demo", "sandbox", "platform", "api", "static", "admin"}
KINDS = ("demo", "organization", "sandbox")
_REG_DDL = """CREATE TABLE IF NOT EXISTS workspaces (
  slug TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, industry TEXT, size TEXT, description TEXT,
  template TEXT, created_at TEXT NOT NULL)"""
_lock = threading.Lock()
_known: set[str] | None = None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _registry():
    path = get_settings().data_dir / "platform.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    eng = create_engine(f"sqlite:///{path}", future=True)
    with eng.begin() as c:
        c.execute(text(_REG_DDL))
    return eng


def _invalidate() -> None:
    global _known
    _known = None


def reset_cache() -> None:
    _invalidate()


def list_workspaces() -> list[dict]:
    eng = _registry()
    try:
        with eng.connect() as c:
            return [dict(r) for r in c.execute(text("SELECT * FROM workspaces ORDER BY CASE kind WHEN 'demo' THEN 0 WHEN 'sandbox' THEN 1 ELSE 2 END, created_at")).mappings()]
    finally:
        eng.dispose()


def exists(slug: str) -> bool:
    global _known
    with _lock:
        if _known is None:
            _known = {w["slug"] for w in list_workspaces()}
        return slug in _known


def get(slug: str) -> dict | None:
    return next((w for w in list_workspaces() if w["slug"] == slug), None)


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:36].strip("-")
    return s if len(s) >= 2 else f"ws-{s or 'new'}"


def _insert(slug: str, name: str, kind: str, industry: str | None, size: str | None, description: str | None, template: str | None) -> None:
    eng = _registry()
    try:
        with eng.begin() as c:
            c.execute(text("INSERT OR IGNORE INTO workspaces (slug,name,kind,industry,size,description,template,created_at) VALUES (:s,:n,:k,:i,:z,:d,:t,:c)"),
                      dict(s=slug, n=name, k=kind, i=industry, z=size, d=description, t=template, c=_now()))
    finally:
        eng.dispose()
    _invalidate()


def copy_reference_data(slug: str) -> dict:
    """Public threat data + framework catalogue are shared reference data: copy them from the demo workspace into a new one.
    Organisation-specific state (control status, evidence, risks) is NOT copied."""
    src = db.workspace_db_path(db.DEFAULT_WORKSPACE)
    dst = db.workspace_db_path(slug)
    if not src.exists() or src == dst:
        return {}
    con = sqlite3.connect(dst)
    try:
        con.execute("ATTACH DATABASE ? AS ref", (str(src),))
        out = {}
        for table in ("cve_catalog", "kev_entries", "attack_techniques", "frameworks"):
            con.execute(f"INSERT OR IGNORE INTO main.{table} SELECT * FROM ref.{table}")  # noqa: S608 (static names)
            out[table] = con.execute(f"SELECT COUNT(*) FROM main.{table}").fetchone()[0]  # noqa: S608
        con.execute("""INSERT OR IGNORE INTO main.controls (control_code, framework_id, title, description, category)
                       SELECT control_code, framework_id, title, description, category FROM ref.controls""")
        out["controls"] = con.execute("SELECT COUNT(*) FROM main.controls").fetchone()[0]
        con.execute("""INSERT OR IGNORE INTO main.source_registry (source_name, publisher, source_type, official_url, acquisition_method, license_notes,
                         retrieval_timestamp, dataset_version, checksum, record_count, last_successful_run, status, from_cache, last_error)
                       SELECT source_name, publisher, source_type, official_url, acquisition_method, license_notes,
                         retrieval_timestamp, dataset_version, checksum, record_count, last_successful_run, status, from_cache, last_error
                       FROM ref.source_registry WHERE source_type='PUBLIC'""")
        con.commit()
        con.execute("DETACH DATABASE ref")
        return out
    finally:
        con.close()


def _init_db(slug: str) -> None:
    from app.rag import ingest as rag_ingest
    from app.risk import service as risk_service

    db.workspace_dir(slug).mkdir(parents=True, exist_ok=True)
    eng = db.engine_for(slug)
    db.init_schema(eng)
    copy_reference_data(slug)
    with db.connect(eng) as conn:
        risk_service.seed_config(conn)
        rag_ingest.ingest_knowledge_base(conn)
        rag_ingest.ingest_reference_data(conn)


def ensure_defaults() -> None:
    """Idempotent: register the bundled demo workspace and the no-organisation sandbox."""
    _insert("demo", "Acme Corp (demo)", "demo", "Technology", "250 people", "Bundled synthetic organisation with real public threat data.", "demo")
    if not get("sandbox"):
        _insert("sandbox", "Personal sandbox", "sandbox", None, None, "Analyse logs and incidents without an organisation.", "empty")
    if not db.workspace_db_path("sandbox").exists():
        _init_db("sandbox")


def create(name: str, industry: str | None = None, size: str | None = None, description: str | None = None, template: str = "empty") -> dict:
    name = name.strip()
    if len(name) < 2:
        raise ValueError("Name must be at least 2 characters")
    if template not in ("empty", "demo"):
        raise ValueError("template must be 'empty' or 'demo'")
    base = slugify(name)
    slug, n = base, 2
    while slug in RESERVED or exists(slug):
        slug = f"{base}-{n}"
        n += 1
    _insert(slug, name, "organization", industry, size, description, template)
    try:
        _init_db(slug)
        if template == "demo":
            seed_demo_data(slug)
    except Exception:
        delete(slug, force=True)
        raise
    return get(slug)


def seed_demo_data(slug: str) -> dict:
    """Populate a workspace with synthetic organisational data (different seed per workspace) via the normal ETL."""
    from app.demo import synthetic
    from app.demo.setup import backfill_history
    from app.etl.pipeline import run_all

    seed = sum(ord(c) for c in slug) + 7
    out = db.workspace_dir(slug) / "synthetic"
    eng = db.engine_for(slug)
    synthetic.generate(out, engine=eng, seed=seed)
    runs = run_all(out, eng)
    with db.connect(eng) as conn:
        backfill_history(conn)
    return {"datasets": len(runs), "loaded": sum(r["loaded"] for r in runs), "rejected": sum(r["rejected"] for r in runs)}


def delete(slug: str, force: bool = False) -> None:
    w = get(slug)
    if not force and (not w or w["kind"] != "organization"):
        raise ValueError("Only organization workspaces can be deleted")
    db.drop_engine(slug)
    shutil.rmtree(db.workspace_dir(slug), ignore_errors=True)
    eng = _registry()
    try:
        with eng.begin() as c:
            c.execute(text("DELETE FROM workspaces WHERE slug=:s"), {"s": slug})
    finally:
        eng.dispose()
    _invalidate()


def stats(slug: str) -> dict:
    """Quick counts for the workspace list (opens that workspace's DB read-only)."""
    path = db.workspace_db_path(slug)
    if not path.exists():
        return {}
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        def n(sql: str) -> int:
            try:
                return con.execute(sql).fetchone()[0]
            except sqlite3.Error:
                return 0
        return {"assets": n("SELECT COUNT(*) FROM assets"), "risks": n("SELECT COUNT(*) FROM risks WHERE status!='CLOSED'"),
                "open_vulnerabilities": n("SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('OPEN','IN_PROGRESS')"), "analyses": n("SELECT COUNT(*) FROM analyses")}
    finally:
        con.close()
