from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from app.api.common import audit, paged
from app.ai.llm import resolve_provider
from app.config import get_settings
from app.db.session import execute, get_conn, rows
from app.risk import engine as eng
from app.risk import service as risk_service

router = APIRouter(prefix="/api", tags=["settings"])


class RiskConfigUpdate(BaseModel):
    values: dict[str, float] = Field(min_length=1, max_length=20)


@router.get("/settings")
def get_app_settings(conn: Connection = Depends(get_conn)):
    s = get_settings()
    risk_service.seed_config(conn)
    return {
        "application": {"name": s.app_name, "database": "SQLite", "max_input_chars": s.max_input_chars},
        "ai": {"provider": resolve_provider().label, "model": resolve_provider().model or s.gemini_model, "configured": resolve_provider().provider != "none", "prompt_version": s.prompt_version,
               "fallback_models": list(resolve_provider().fallbacks), "warning": resolve_provider().warning or None},
        "nvd": {"api_key_configured": bool(s.nvd_api_key), "default_window_days": 14, "max_records": s.nvd_max_records},
        "risk_config": rows(conn, "SELECT key, value, description FROM risk_config ORDER BY key"),
        "formulas": {
            "inherent": "likelihood x impact (1-25)", "residual": "inherent x (1 - control effectiveness)",
            "levels": "LOW <5, MEDIUM 5-9.99, HIGH 10-16.99, CRITICAL >=17",
            "vulnerability_risk": "100 x weighted mean of CVSS, asset criticality, exploitability, internet exposure, CISA KEV (weights above)",
            "enterprise": "weighted mean of (average normalised residual risk, % of open risks rated HIGH/CRITICAL)",
        },
    }


@router.put("/settings/risk-config")
def update_risk_config(body: RiskConfigUpdate, conn: Connection = Depends(get_conn)):
    unknown = [k for k in body.values if k not in eng.DEFAULT_CONFIG]
    if unknown:
        raise HTTPException(422, f"Unknown configuration keys: {unknown}")
    if any(v < 0 or v > 1 for v in body.values.values()):
        raise HTTPException(422, "Weights must be between 0 and 1")
    merged = {**risk_service.load_config(conn), **body.values}
    if sum(merged[k] for k in eng.DEFAULT_CONFIG if k.startswith("vuln.")) <= 0 or sum(merged[k] for k in eng.DEFAULT_CONFIG if k.startswith("enterprise.")) <= 0:
        raise HTTPException(422, "Each weight group must have a positive total")
    for k, v in body.values.items():
        execute(conn, "UPDATE risk_config SET value=:v WHERE key=:k", v=v, k=k)
    counts = risk_service.recalculate_all(conn, reason="Recalculated after risk weight change")
    audit(conn, "update_risk_config", "risk_config", ",".join(body.values), str(body.values))
    return {"updated": list(body.values), "recalculated": counts}


@router.get("/audit-log")
def audit_log(page: int = 1, page_size: int = 25, conn: Connection = Depends(get_conn)):
    return paged(conn, "SELECT id, ts, actor, action, entity, entity_id, detail FROM audit_log", "SELECT COUNT(*) FROM audit_log", {}, {"id": "id"}, "id", "desc", page, page_size, "id")
