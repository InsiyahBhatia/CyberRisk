"""Ad-hoc analysis of logs and incidents: works in any workspace, including the organisation-free sandbox."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from app.ai import service
from app.ai.context import Facts
from app.analysis import engine as analysis
from app.api.ai import _llm, respond
from app.api.common import audit, not_found
from app.db.session import execute, get_conn, one, rows, scalar
from app.guardrails.ratelimit import limit_ai
from app.reports import build
from app.risk import engine as risk_engine
from app.risk import service as risk_service

router = APIRouter(prefix="/api/analysis", tags=["analysis"])
MAX_BYTES = 10 * 1024 * 1024
SEV_L = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}


class IncidentText(BaseModel):
    text: str = Field(min_length=20, max_length=50_000)
    name: str | None = Field(None, max_length=120)


class Promote(BaseModel):
    finding_id: str = Field(pattern=r"^F\d{1,3}$")
    asset_id: int | None = None
    owner: str | None = Field(None, max_length=80)


class Explain(BaseModel):
    question: str = Field("Explain this analysis and what to do next.", max_length=1000)


@router.post("/logs", status_code=201)
async def analyze_logs(file: UploadFile = File(...), name: str | None = Form(None, max_length=120), conn: Connection = Depends(get_conn)):
    data = await file.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "File exceeds 10 MB limit")
    if not data.strip():
        raise HTTPException(422, "File is empty")
    if (file.filename or "").lower().endswith((".exe", ".dll", ".zip", ".gz", ".png", ".jpg", ".pdf")):
        raise HTTPException(415, "Upload a text log, CSV, JSON or JSON-lines file")
    try:
        res = analysis.analyze_logs(conn, data, file.filename or "upload", name)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    audit(conn, "analysis_logs", "analysis", res["id"], f"{res['meta']['events']} events, {len(res['findings'])} findings")
    return res


@router.post("/incident", status_code=201)
def analyze_incident(body: IncidentText, conn: Connection = Depends(get_conn)):
    try:
        res = analysis.analyze_incident(conn, body.text, body.name)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    audit(conn, "analysis_incident", "analysis", res["id"], res.get("category", ""))
    return res


@router.get("")
def list_analyses(conn: Connection = Depends(get_conn)):
    return {"items": analysis.list_analyses(conn)}


@router.get("/{aid}")
def get_analysis(aid: int, conn: Connection = Depends(get_conn)):
    r = analysis.get_analysis(conn, aid)
    if not r:
        raise not_found("Analysis")
    return r


@router.delete("/{aid}")
def delete_analysis(aid: int, conn: Connection = Depends(get_conn)):
    if not scalar(conn, "SELECT 1 FROM analyses WHERE id=:i", i=aid):
        raise not_found("Analysis")
    execute(conn, "DELETE FROM analyses WHERE id=:i", i=aid)
    audit(conn, "delete", "analysis", aid)
    return {"deleted": aid}


@router.get("/{aid}/report", response_class=HTMLResponse)
def report(aid: int, conn: Connection = Depends(get_conn)):
    r = analysis.get_analysis(conn, aid)
    if not r:
        raise not_found("Analysis")
    audit(conn, "report_generated", "analysis", aid)
    return HTMLResponse(build.render_analysis(r), headers={"Content-Disposition": f'attachment; filename="analysis-{aid}.html"'})


def _facts(a: dict) -> Facts:
    f = Facts(risk_level=a["severity"])
    f.add(f"DB:analysis:{a['id']}", {"name": a["name"], "kind": a["kind"], "severity": a["severity"], "score": a["score"], "events": a["meta"].get("events"), "category": a.get("category"),
                                      "first_event": a["meta"].get("first_event"), "last_event": a["meta"].get("last_event"), "severity_rationale": a.get("severity_rationale")})
    for fd in a["findings"][:12]:
        f.add(f"DB:finding:{fd['id']}", {"title": fd["title"], "severity": fd["severity"], "techniques": fd["techniques"], "count": fd["count"], "detail": fd["description"], "sample": fd["sample"][:2]})
    for t in a["techniques"][:12]:
        f.add(f"DB:technique:{t['id']}", {"name": t["name"], "tactics": t["tactics"]})
    for c in a["cves"][:8]:
        f.add(f"DB:cve:{c['id']}", {"cvss": c["cvss"], "in_cisa_kev": c["in_kev"], "description": c["description"][:200]})
    f.deterministic = {"severity": a["severity"], "score": a["score"]}
    f.retrieval_query = " ".join([a.get("category") or "", "incident response", *[x["title"] for x in a["findings"][:4]]])
    return f


@router.post("/{aid}/explain", dependencies=[Depends(limit_ai)])
def explain(aid: int, body: Explain, conn: Connection = Depends(get_conn)):
    a = analysis.get_analysis(conn, aid)
    if not a:
        raise not_found("Analysis")
    return respond(service.run_task(conn, "analysis", body.question, _facts(a), _llm(), require_scope=False))  # facts are security data; injection checks still apply


@router.post("/{aid}/promote", status_code=201)
def promote(aid: int, body: Promote, conn: Connection = Depends(get_conn)):
    """A human decision: turn a finding into a risk-register entry in the current workspace."""
    a = analysis.get_analysis(conn, aid)
    if not a:
        raise not_found("Analysis")
    f = next((x for x in a["findings"] if x["id"] == body.finding_id), None)
    if not f:
        raise not_found("Finding")
    impact = 3
    if body.asset_id:
        asset = one(conn, "SELECT id, criticality FROM assets WHERE id=:i", i=body.asset_id)
        if not asset:
            raise not_found("Asset")
        impact = {"LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}[asset["criticality"]]
    likelihood = SEV_L[f["severity"]]
    inh = risk_engine.inherent_score(likelihood, impact)
    code = risk_service.next_risk_code(conn)
    rid = execute(conn, """INSERT INTO risks (risk_code,title,description,category,asset_id,likelihood,impact,inherent_score,control_effectiveness,residual_score,risk_level,owner,status,treatment)
                           VALUES (:c,:t,:d,'Security Operations',:a,:l,:i,:inh,0,:inh,:lvl,:o,'IDENTIFIED','MITIGATE')""",
                  c=code, t=f"{f['title']} (analysis #{aid})"[:200], d=f"{f['description']} Source: analysis #{aid} ({a['name']}). ATT&CK: {', '.join(f['techniques'])}.", a=body.asset_id, l=likelihood, i=impact, inh=inh,
                  lvl=risk_engine.risk_level(inh), o=body.owner or "Unassigned").lastrowid
    risk_service.recalc_risk(conn, one(conn, "SELECT * FROM risks WHERE id=:i", i=rid), f"Promoted from analysis #{aid}")
    audit(conn, "promote_finding", "risk", rid, f"analysis {aid} {body.finding_id}")
    return {"risk_id": rid, "risk_code": code, "likelihood": likelihood, "impact": impact, "inherent_score": inh,
            "note": "Likelihood from finding severity; impact from the chosen asset's criticality (3 if none). Edit on the Risks page."}
