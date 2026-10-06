from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from app.db.session import current_workspace, get_conn, scalar
from app.tenancy import workspaces as ws

router = APIRouter(prefix="/api", tags=["workspaces"])


class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    industry: str | None = Field(None, max_length=60)
    size: str | None = Field(None, max_length=40)
    description: str | None = Field(None, max_length=300)
    template: Literal["empty", "demo"] = "empty"


@router.get("/workspaces")
def list_workspaces():
    return {"items": [{**w, "stats": ws.stats(w["slug"])} for w in ws.list_workspaces()], "current": current_workspace()}


@router.post("/workspaces", status_code=201)
def create_workspace(body: WorkspaceCreate):
    try:
        return ws.create(body.name, body.industry, body.size, body.description, body.template)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.delete("/workspaces/{slug}")
def delete_workspace(slug: str, confirm: str = ""):
    w = ws.get(slug)
    if not w:
        raise HTTPException(404, "Workspace not found")
    if confirm != slug:
        raise HTTPException(422, "Type the workspace slug in `confirm` to delete it. This permanently removes its database.")
    try:
        ws.delete(slug)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return {"deleted": slug}


@router.get("/workspace/status")
def workspace_status(conn: Connection = Depends(get_conn)):
    """Current workspace + a guided setup checklist computed from what is actually in the database."""
    slug = current_workspace()
    w = ws.get(slug)
    n = lambda sql: scalar(conn, sql)  # noqa: E731
    counts = {"assets": n("SELECT COUNT(*) FROM assets"), "vulnerabilities": n("SELECT COUNT(*) FROM vulnerabilities"), "controls_assessed": n("SELECT COUNT(*) FROM controls WHERE implementation_status!='NOT_IMPLEMENTED' OR effectiveness>0"),
              "controls_total": n("SELECT COUNT(*) FROM controls"), "evidence": n("SELECT COUNT(*) FROM evidence"), "risks": n("SELECT COUNT(*) FROM risks"),
              "risk_control_links": n("SELECT COUNT(*) FROM risk_controls"), "incidents": n("SELECT COUNT(*) FROM incidents"), "analyses": n("SELECT COUNT(*) FROM analyses"),
              "reports": n("SELECT COUNT(*) FROM audit_log WHERE action='report_generated'"), "public_sources": n("SELECT COUNT(*) FROM source_registry WHERE source_type='PUBLIC' AND status IN ('HEALTHY','CACHED')")}
    steps = [
        {"key": "assets", "title": "Add your assets", "done": counts["assets"] > 0, "detail": f"{counts['assets']} assets", "link": "#/pipeline?tab=run", "hint": "Import a CSV/JSON inventory with the import wizard, or add assets one by one."},
        {"key": "vulnerabilities", "title": "Import vulnerability findings", "done": counts["vulnerabilities"] > 0, "detail": f"{counts['vulnerabilities']} findings", "link": "#/pipeline?tab=run", "hint": "Scanner export (CVE + asset). CVSS and KEV status are enriched from NVD/CISA."},
        {"key": "controls", "title": "Assess your controls", "done": counts["controls_assessed"] > 0, "detail": f"{counts['controls_assessed']}/{counts['controls_total']} assessed", "link": "#/controls", "hint": "Set implementation status and effectiveness for each framework control."},
        {"key": "evidence", "title": "Attach evidence", "done": counts["evidence"] > 0, "detail": f"{counts['evidence']} records", "link": "#/controls", "hint": "Evidence drives evidence coverage; expired evidence counts as missing."},
        {"key": "risks", "title": "Register risks", "done": counts["risks"] > 0, "detail": f"{counts['risks']} risks", "link": "#/risks", "hint": "Add risks manually or accept suggestions generated from your vulnerability data."},
        {"key": "links", "title": "Link controls to risks", "done": counts["risk_control_links"] > 0, "detail": f"{counts['risk_control_links']} links", "link": "#/risks", "hint": "Linked control effectiveness lowers residual risk."},
        {"key": "report", "title": "Generate the assessment report", "done": counts["reports"] > 0, "detail": f"{counts['reports']} generated", "link": "#/reports", "hint": "A shareable risk assessment with gaps and recommendations."},
    ]
    return {"workspace": w, "counts": counts, "steps": steps, "progress": round(100 * sum(s["done"] for s in steps) / len(steps))}
