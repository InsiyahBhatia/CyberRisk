"""Building and assessing an organisation: assets, control assessment, evidence, risk-control links, risk suggestions."""
from __future__ import annotations

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from app.api.common import audit, not_found, paged
from app.db.session import execute, get_conn, one, rows, scalar
from app.risk import engine as eng
from app.risk import service as risk_service

router = APIRouter(prefix="/api", tags=["assessment"])
Crit = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
DATE = r"^\d{4}-\d{2}-\d{2}$"


class AssetIn(BaseModel):
    asset_tag: str = Field(min_length=2, max_length=40, pattern=r"^[A-Za-z0-9._-]+$")
    name: str = Field(min_length=1, max_length=120)
    asset_type: str | None = Field(None, max_length=60)
    business_unit: str | None = Field(None, max_length=80)
    owner: str | None = Field(None, max_length=80)
    criticality: Crit = "MEDIUM"
    internet_exposed: bool = False
    data_classification: str | None = Field(None, max_length=40)
    environment: str | None = Field(None, max_length=40)


class ControlAssessment(BaseModel):
    implementation_status: Literal["IMPLEMENTED", "PARTIAL", "NOT_IMPLEMENTED", "NOT_APPLICABLE"] | None = None
    effectiveness: float | None = Field(None, ge=0, le=1)
    owner: str | None = Field(None, max_length=80)


class EvidenceIn(BaseModel):
    title: str = Field(min_length=2, max_length=160)
    evidence_type: str = Field("Document", max_length=60)
    location: str | None = Field(None, max_length=300)
    status: Literal["PRESENT", "NEEDS_REVIEW", "MISSING"] = "PRESENT"
    collected_at: str | None = Field(None, pattern=DATE)
    expiry_date: str | None = Field(None, pattern=DATE)
    owner: str | None = Field(None, max_length=80)


class RiskControls(BaseModel):
    control_ids: list[int] = Field(max_length=60)


class AcceptSuggestions(BaseModel):
    asset_ids: list[int] = Field(min_length=1, max_length=50)


# ------------------------------------------------------------------ assets
@router.get("/assets")
def list_assets(q: str | None = Query(None, max_length=80), business_unit: str | None = None, criticality: Crit | None = None,
                page: int = 1, page_size: int = 25, conn: Connection = Depends(get_conn)):
    cond, p = [], {}
    if q:
        cond.append("(a.asset_tag LIKE :q OR a.name LIKE :q)"); p["q"] = f"%{q}%"
    if business_unit:
        cond.append("a.business_unit=:bu"); p["bu"] = business_unit
    if criticality:
        cond.append("a.criticality=:c"); p["c"] = criticality
    where = ("WHERE " + " AND ".join(cond)) if cond else ""
    sel = f"""SELECT a.id, a.asset_tag, a.name, a.asset_type, a.business_unit, a.owner, a.criticality, a.internet_exposed, a.data_classification, a.environment, a.status,
                     (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id=a.id AND v.status IN ('OPEN','IN_PROGRESS')) AS open_vulns,
                     (SELECT COUNT(*) FROM risks r WHERE r.asset_id=a.id AND r.status!='CLOSED') AS open_risks FROM assets a {where}"""  # noqa: S608
    return paged(conn, sel, f"SELECT COUNT(*) FROM assets a {where}", p, {"asset_tag": "a.asset_tag", "criticality": "a.criticality", "open_vulns": "open_vulns", "id": "a.id"},  # noqa: S608
                 None, "asc", page, page_size, "asset_tag")


@router.post("/assets", status_code=201)
def create_asset(body: AssetIn, conn: Connection = Depends(get_conn)):
    tag = body.asset_tag.upper()
    if scalar(conn, "SELECT 1 FROM assets WHERE asset_tag=:t", t=tag):
        raise HTTPException(409, f"Asset {tag} already exists")
    rid = execute(conn, """INSERT INTO assets (asset_tag,name,asset_type,business_unit,owner,criticality,internet_exposed,data_classification,environment)
                           VALUES (:t,:n,:ty,:bu,:o,:c,:ie,:dc,:env)""", t=tag, n=body.name, ty=body.asset_type, bu=body.business_unit, o=body.owner,
                  c=body.criticality, ie=int(body.internet_exposed), dc=body.data_classification, env=body.environment).lastrowid
    audit(conn, "create", "asset", rid, tag)
    return one(conn, "SELECT * FROM assets WHERE id=:i", i=rid)


# ------------------------------------------------------------------ control assessment + evidence
@router.patch("/controls/{cid}")
def assess_control(cid: int, body: ControlAssessment, conn: Connection = Depends(get_conn)):
    if not scalar(conn, "SELECT 1 FROM controls WHERE id=:i", i=cid):
        raise not_found("Control")
    ch = body.model_dump(exclude_unset=True)
    if ch.get("implementation_status") == "NOT_IMPLEMENTED" and "effectiveness" not in ch:
        ch["effectiveness"] = 0.0
    for k, v in ch.items():
        execute(conn, f"UPDATE controls SET {k}=:v WHERE id=:i", v=v, i=cid)  # noqa: S608 (keys come from the Pydantic model)
    n = risk_service.recalc_risks(conn, "Control assessment updated")
    audit(conn, "assess_control", "control", cid, str(ch))
    return {"id": cid, "updated": ch, "risks_recalculated": n}


@router.post("/controls/{cid}/evidence", status_code=201)
def add_evidence(cid: int, body: EvidenceIn, conn: Connection = Depends(get_conn)):
    if not scalar(conn, "SELECT 1 FROM controls WHERE id=:i", i=cid):
        raise not_found("Control")
    status = body.status
    if status == "PRESENT" and body.expiry_date and body.expiry_date < date.today().isoformat():
        status = "EXPIRED"  # same consistency rule as the ETL
    rid = execute(conn, """INSERT INTO evidence (control_id,evidence_type,title,location,status,collected_at,expiry_date,owner)
                           VALUES (:c,:t,:ti,:l,:s,:ca,:ex,:o)""", c=cid, t=body.evidence_type, ti=body.title, l=body.location, s=status,
                  ca=body.collected_at, ex=body.expiry_date, o=body.owner).lastrowid
    audit(conn, "add_evidence", "control", cid, body.title)
    return one(conn, "SELECT * FROM evidence WHERE id=:i", i=rid)


# ------------------------------------------------------------------ risk <-> controls
@router.put("/risks/{rid}/controls")
def set_risk_controls(rid: int, body: RiskControls, conn: Connection = Depends(get_conn)):
    risk = one(conn, "SELECT * FROM risks WHERE id=:i", i=rid)
    if not risk:
        raise not_found("Risk")
    ids = list(dict.fromkeys(body.control_ids))
    found = {r["id"]: r for r in rows(conn, "SELECT id, framework_id FROM controls WHERE id IN (" + ",".join(str(int(i)) for i in ids) + ")")} if ids else {}  # noqa: S608 (ints only)
    missing = [i for i in ids if i not in found]
    if missing:
        raise HTTPException(422, f"Unknown control ids: {missing}")
    execute(conn, "DELETE FROM risk_controls WHERE risk_id=:r", r=rid)
    execute(conn, "DELETE FROM control_mappings WHERE source_type='risk' AND source_id=:r AND origin='CURATED' AND control_id IS NOT NULL", r=rid)
    for cid in ids:
        execute(conn, "INSERT INTO risk_controls (risk_id, control_id) VALUES (:r,:c)", r=rid, c=cid)
        execute(conn, """INSERT INTO control_mappings (source_type,source_id,framework_id,control_id,mapping_reason,confidence,origin,review_state)
                         VALUES ('risk',:r,:fw,:c,'Linked by assessor: control mitigates this risk',1.0,'CURATED','APPROVED')""", r=rid, fw=found[cid]["framework_id"], c=cid)
    res = risk_service.recalc_risk(conn, risk, "Linked controls changed")
    audit(conn, "link_controls", "risk", rid, str(ids))
    return {"risk_id": rid, "control_ids": ids, **res}


# ------------------------------------------------------------------ suggestions from vulnerability data
def _suggestions(conn: Connection) -> list[dict]:
    cands = rows(conn, """SELECT a.id AS asset_id, a.asset_tag, a.business_unit, a.criticality, a.internet_exposed,
                                 COUNT(*) AS open_vulns, SUM(v.known_exploited) AS kev_count, SUM(v.severity='CRITICAL') AS critical_count,
                                 MAX(v.risk_score) AS max_priority, MAX(v.cvss_score) AS max_cvss
                          FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id WHERE v.status IN ('OPEN','IN_PROGRESS')
                            AND NOT EXISTS (SELECT 1 FROM risks r WHERE r.asset_id=a.id AND r.category='Vulnerability Management' AND r.status!='CLOSED')
                          GROUP BY a.id HAVING kev_count > 0 OR critical_count > 0 ORDER BY max_priority DESC LIMIT 20""")
    out = []
    for c in cands:
        likelihood = min(5, 2 + (1 if c["kev_count"] else 0) + (1 if c["internet_exposed"] else 0) + (1 if (c["max_cvss"] or 0) >= 9 else 0))
        impact = {"LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}.get(c["criticality"], 3)
        out.append({**c, "likelihood": likelihood, "impact": impact, "inherent_score": eng.inherent_score(likelihood, impact),
                    "title": f"Exploitable vulnerabilities on {c['asset_tag']}",
                    "rationale": f"{c['open_vulns']} open vulnerabilities ({c['critical_count']} critical, {c['kev_count']} in CISA KEV) on a {c['criticality'].lower()}-criticality "
                                 f"{'internet-exposed ' if c['internet_exposed'] else ''}asset. Likelihood {likelihood} = 2 + KEV + exposure + CVSS≥9; impact from asset criticality."})
    return out


@router.get("/risks-suggestions")
def risk_suggestions(conn: Connection = Depends(get_conn)):
    return {"items": _suggestions(conn), "note": "Deterministic proposals from vulnerability data. Nothing is created until you accept."}


@router.post("/risks-suggestions/accept", status_code=201)
def accept_suggestions(body: AcceptSuggestions, conn: Connection = Depends(get_conn)):
    wanted = set(body.asset_ids)
    created = []
    for s in _suggestions(conn):
        if s["asset_id"] not in wanted:
            continue
        code = risk_service.next_risk_code(conn)
        rid = execute(conn, """INSERT INTO risks (risk_code,title,description,category,asset_id,likelihood,impact,inherent_score,control_effectiveness,residual_score,risk_level,owner,status,treatment)
                               VALUES (:c,:t,:d,'Vulnerability Management',:a,:l,:i,:inh,0,:inh,:lvl,'Unassigned','IDENTIFIED','MITIGATE')""",
                      c=code, t=s["title"], d=s["rationale"], a=s["asset_id"], l=s["likelihood"], i=s["impact"], inh=s["inherent_score"], lvl=eng.risk_level(s["inherent_score"])).lastrowid
        risk_service.recalc_risk(conn, one(conn, "SELECT * FROM risks WHERE id=:i", i=rid), "Created from vulnerability suggestion")
        audit(conn, "create_from_suggestion", "risk", rid, s["title"])
        created.append({"id": rid, "risk_code": code, "title": s["title"]})
    return {"created": created}
