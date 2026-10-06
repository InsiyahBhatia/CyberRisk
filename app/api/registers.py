"""Risks, vulnerabilities, incidents, controls, compliance, vendors."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from app.api.common import audit, not_found, paged
from app.db.session import execute, get_conn, one, rows, scalar
from app.grc.service import compliance_summary, controls_with_evidence, coverage
from app.risk import engine as eng
from app.risk import service as risk_service

router = APIRouter(prefix="/api", tags=["registers"])
Order = Literal["asc", "desc"]
Level = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
RiskStatus = Literal["IDENTIFIED", "ASSESSMENT", "TREATMENT", "MITIGATION", "VALIDATION", "ACCEPTED", "CLOSED"]
Treatment = Literal["MITIGATE", "TRANSFER", "AVOID", "ACCEPT"]


# ------------------------------------------------------------------ risks
class RiskCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(None, max_length=2000)
    category: str | None = Field(None, max_length=80)
    asset_id: int | None = None
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    owner: str | None = Field(None, max_length=80)
    treatment: Treatment | None = None
    due_date: str | None = Field(None, pattern=r"^\d{4}-\d{2}-\d{2}$")


class RiskUpdate(BaseModel):
    title: str | None = Field(None, min_length=3, max_length=200)
    likelihood: int | None = Field(None, ge=1, le=5)
    impact: int | None = Field(None, ge=1, le=5)
    owner: str | None = Field(None, max_length=80)
    status: RiskStatus | None = None
    treatment: Treatment | None = None
    due_date: str | None = Field(None, pattern=r"^\d{4}-\d{2}-\d{2}$")


class Simulation(BaseModel):
    action_ids: list[int] = Field(max_length=50)


class ApprovalDecision(BaseModel):
    decision: Literal["APPROVED", "REJECTED"]
    reviewer: str = Field(min_length=2, max_length=80)
    comments: str | None = Field(None, max_length=1000)


RISK_SORT = {"risk_code": "r.risk_code", "title": "r.title", "residual_score": "r.residual_score", "inherent_score": "r.inherent_score",
             "risk_level": "r.residual_score", "status": "r.status", "owner": "r.owner", "due_date": "r.due_date"}
RISK_SELECT = """SELECT r.id, r.risk_code, r.title, r.category, r.likelihood, r.impact, r.inherent_score, r.control_effectiveness, r.residual_score,
                        r.risk_level, r.owner, r.status, r.treatment, r.approval_status, r.due_date, a.asset_tag, a.business_unit
                 FROM risks r LEFT JOIN assets a ON a.id = r.asset_id {where}"""
RISK_COUNT = "SELECT COUNT(*) FROM risks r LEFT JOIN assets a ON a.id = r.asset_id {where}"


@router.get("/risks")
def list_risks(level: Level | None = None, status: RiskStatus | None = None, owner: str | None = None, q: str | None = Query(None, max_length=100),
               business_unit: str | None = None, sort: str | None = None, order: Order = "desc", page: int = 1, page_size: int = 25,
               conn: Connection = Depends(get_conn)):
    cond, p = [], {}
    for col, val, name in (("r.risk_level", level, "level"), ("r.status", status, "status"), ("r.owner", owner, "owner"), ("a.business_unit", business_unit, "bu")):
        if val:
            cond.append(f"{col} = :{name}")
            p[name] = val
    if q:
        cond.append("(r.title LIKE :q OR r.risk_code LIKE :q)")
        p["q"] = f"%{q}%"
    where = ("WHERE " + " AND ".join(cond)) if cond else ""
    return paged(conn, RISK_SELECT.format(where=where), RISK_COUNT.format(where=where), p, RISK_SORT, sort, order, page, page_size, "residual_score")


@router.get("/risks/{risk_id}")
def get_risk(risk_id: int, conn: Connection = Depends(get_conn)):
    risk = one(conn, RISK_SELECT.format(where="WHERE r.id = :id"), id=risk_id)
    if not risk:
        raise not_found("Risk")
    full = one(conn, "SELECT description, asset_id FROM risks WHERE id=:id", id=risk_id)
    asset = one(conn, "SELECT * FROM assets WHERE id=:id", id=full["asset_id"]) if full["asset_id"] else None
    controls = rows(conn, """SELECT c.id, c.control_code, c.title, c.implementation_status, c.effectiveness, f.name AS framework
                             FROM risk_controls rc JOIN controls c ON c.id=rc.control_id JOIN frameworks f ON f.id=c.framework_id
                             WHERE rc.risk_id=:id ORDER BY f.name, c.control_code""", id=risk_id)
    mappings = rows(conn, """SELECT m.id, f.name AS framework, f.version AS framework_version, COALESCE(c.control_code, m.external_ref) AS reference,
                                    COALESCE(c.title, t.name) AS title, m.mapping_reason, m.confidence, m.origin, m.review_state
                             FROM control_mappings m JOIN frameworks f ON f.id=m.framework_id
                             LEFT JOIN controls c ON c.id=m.control_id LEFT JOIN attack_techniques t ON t.technique_id=m.external_ref
                             WHERE m.source_type='risk' AND m.source_id=:id ORDER BY f.name""", id=risk_id)
    return {**risk, "description": full["description"], "asset": asset, "controls": controls, "mappings": mappings,
            "mapping_note": "Mappings are curated for this demo (origin CURATED) or AI-suggested pending human review (origin AI_SUGGESTED).",
            "remediation": rows(conn, "SELECT id, action, owner, priority, due_date, status, effectiveness_gain FROM remediation_actions WHERE risk_id=:id ORDER BY id", id=risk_id),
            "related_vulnerabilities": rows(conn, """SELECT id, cve_id, severity, cvss_score, known_exploited, status, due_date FROM vulnerabilities
                                                    WHERE asset_id=:a AND status IN ('OPEN','IN_PROGRESS') ORDER BY risk_score DESC LIMIT 8""", a=full["asset_id"]) if full["asset_id"] else []}


@router.post("/risks", status_code=201)
def create_risk(body: RiskCreate, conn: Connection = Depends(get_conn)):
    if body.asset_id and not scalar(conn, "SELECT 1 FROM assets WHERE id=:i", i=body.asset_id):
        raise not_found("Asset")
    code = risk_service.next_risk_code(conn)
    inh = eng.inherent_score(body.likelihood, body.impact)
    res = execute(conn, """INSERT INTO risks (risk_code,title,description,category,asset_id,likelihood,impact,inherent_score,control_effectiveness,residual_score,risk_level,owner,treatment,due_date)
                           VALUES (:c,:t,:d,:cat,:a,:l,:i,:inh,0,:inh,:lvl,:o,:tr,:due)""",
                  c=code, t=body.title, d=body.description, cat=body.category, a=body.asset_id, l=body.likelihood, i=body.impact, inh=inh,
                  lvl=eng.risk_level(inh), o=body.owner, tr=body.treatment, due=body.due_date)
    rid = res.lastrowid
    risk_service.recalc_risk(conn, one(conn, "SELECT * FROM risks WHERE id=:i", i=rid), "Risk created")
    audit(conn, "create", "risk", rid, body.title)
    return get_risk(rid, conn)


@router.patch("/risks/{risk_id}")
def update_risk(risk_id: int, body: RiskUpdate, conn: Connection = Depends(get_conn)):
    risk = one(conn, "SELECT * FROM risks WHERE id=:i", i=risk_id)
    if not risk:
        raise not_found("Risk")
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        execute(conn, f"UPDATE risks SET {k}=:v, updated_at=CURRENT_TIMESTAMP WHERE id=:i", v=v, i=risk_id)  # noqa: S608 (keys come from the Pydantic model)
    fresh = one(conn, "SELECT * FROM risks WHERE id=:i", i=risk_id)
    risk_service.recalc_risk(conn, fresh, "Risk updated: " + ", ".join(changes) if changes else "Risk updated")
    audit(conn, "update", "risk", risk_id, str(changes))
    return get_risk(risk_id, conn)


@router.post("/risks/{risk_id}/approval")
def decide_risk_acceptance(risk_id: int, body: ApprovalDecision, conn: Connection = Depends(get_conn)):
    """Human approval for accepting HIGH/CRITICAL risk. Never performed automatically or by AI."""
    risk = one(conn, "SELECT * FROM risks WHERE id=:i", i=risk_id)
    if not risk:
        raise not_found("Risk")
    if risk["approval_status"] != "PENDING":
        from fastapi import HTTPException
        raise HTTPException(409, "No approval is pending for this risk")
    execute(conn, "UPDATE risks SET approval_status=:a, updated_at=CURRENT_TIMESTAMP WHERE id=:i", a=body.decision, i=risk_id)
    if body.decision == "REJECTED":
        execute(conn, "UPDATE risks SET status='TREATMENT', treatment='MITIGATE' WHERE id=:i", i=risk_id)
    audit(conn, f"risk_acceptance_{body.decision.lower()}", "risk", risk_id, body.comments or "", actor=body.reviewer)
    return get_risk(risk_id, conn)


@router.get("/risks/{risk_id}/history")
def risk_history(risk_id: int, conn: Connection = Depends(get_conn)):
    if not scalar(conn, "SELECT 1 FROM risks WHERE id=:i", i=risk_id):
        raise not_found("Risk")
    return {"items": rows(conn, "SELECT score, risk_level, recorded_at, reason FROM risk_history WHERE risk_id=:i ORDER BY recorded_at", i=risk_id)}


@router.post("/risks/{risk_id}/simulate")
def simulate(risk_id: int, body: Simulation, conn: Connection = Depends(get_conn)):
    try:
        return risk_service.simulate_risk(conn, risk_id, body.action_ids)
    except LookupError:
        raise not_found("Risk")
    except ValueError as exc:
        from fastapi import HTTPException
        raise HTTPException(422, str(exc))


# ------------------------------------------------------------------ vulnerabilities
VULN_SORT = {"cve_id": "v.cve_id", "severity": "v.cvss_score", "cvss_score": "v.cvss_score", "risk_score": "v.risk_score", "status": "v.status",
             "due_date": "v.due_date", "asset_tag": "a.asset_tag", "discovered_at": "v.discovered_at"}
VULN_SELECT = """SELECT v.id, v.cve_id, v.title, v.severity, v.cvss_score, v.exploitability, v.known_exploited, v.status, v.discovered_at, v.due_date,
                        v.resolved_at, v.risk_score, v.source, a.asset_tag, a.business_unit, a.criticality AS asset_criticality, a.internet_exposed,
                        CASE WHEN v.status IN ('OPEN','IN_PROGRESS') AND v.due_date < date('now') THEN 1 ELSE 0 END AS overdue
                 FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id {where}"""
VULN_COUNT = "SELECT COUNT(*) FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id {where}"


@router.get("/vulnerabilities")
def list_vulns(severity: Level | None = None, status: Literal["OPEN", "IN_PROGRESS", "RESOLVED", "ACCEPTED"] | None = None,
               known_exploited: bool | None = None, overdue: bool | None = None, business_unit: str | None = None,
               q: str | None = Query(None, max_length=100), sort: str | None = None, order: Order = "desc", page: int = 1, page_size: int = 25,
               conn: Connection = Depends(get_conn)):
    cond, p = [], {}
    if severity:
        cond.append("v.severity=:sev"); p["sev"] = severity
    if status:
        cond.append("v.status=:st"); p["st"] = status
    if known_exploited is not None:
        cond.append("v.known_exploited=:ke"); p["ke"] = int(known_exploited)
    if overdue:
        cond.append("v.status IN ('OPEN','IN_PROGRESS') AND v.due_date < date('now')")
    if business_unit:
        cond.append("a.business_unit=:bu"); p["bu"] = business_unit
    if q:
        cond.append("(v.cve_id LIKE :q OR a.asset_tag LIKE :q)"); p["q"] = f"%{q}%"
    where = ("WHERE " + " AND ".join(cond)) if cond else ""
    return paged(conn, VULN_SELECT.format(where=where), VULN_COUNT.format(where=where), p, VULN_SORT, sort, order, page, page_size, "risk_score")


@router.get("/vulnerabilities/{vid}")
def get_vuln(vid: int, conn: Connection = Depends(get_conn)):
    v = one(conn, VULN_SELECT.format(where="WHERE v.id=:id"), id=vid)
    if not v:
        raise not_found("Vulnerability")
    cat = one(conn, "SELECT * FROM cve_catalog WHERE cve_id=:c", c=v["cve_id"])
    kev = one(conn, "SELECT * FROM kev_entries WHERE cve_id=:c", c=v["cve_id"])
    return {**v, "catalog": cat, "kev": kev,
            "scoring_note": "CVSS measures severity. risk_score (0-100) combines CVSS, asset criticality, exploitability, internet exposure and CISA KEV status using configurable weights."}


# ------------------------------------------------------------------ incidents
INC_SORT = {"incident_code": "i.incident_code", "severity": "i.severity", "status": "i.status", "detected_at": "i.detected_at", "category": "i.category"}
INC_SELECT = """SELECT i.id, i.incident_code, i.title, i.severity, i.status, i.category, i.detected_at, i.resolved_at, i.description, i.technique_ids,
                        a.asset_tag, a.business_unit FROM incidents i LEFT JOIN assets a ON a.id=i.affected_asset_id {where}"""
INC_COUNT = "SELECT COUNT(*) FROM incidents i LEFT JOIN assets a ON a.id=i.affected_asset_id {where}"


@router.get("/incidents")
def list_incidents(severity: Level | None = None, status: str | None = Query(None, max_length=20), category: str | None = Query(None, max_length=60),
                   sort: str | None = None, order: Order = "desc", page: int = 1, page_size: int = 25, conn: Connection = Depends(get_conn)):
    cond, p = [], {}
    for col, val, name in (("i.severity", severity, "sev"), ("i.status", status.upper() if status else None, "st"), ("i.category", category, "cat")):
        if val:
            cond.append(f"{col}=:{name}"); p[name] = val
    where = ("WHERE " + " AND ".join(cond)) if cond else ""
    return paged(conn, INC_SELECT.format(where=where), INC_COUNT.format(where=where), p, INC_SORT, sort, order, page, page_size, "detected_at")


@router.get("/incidents/{iid}")
def get_incident(iid: int, conn: Connection = Depends(get_conn)):
    inc = one(conn, INC_SELECT.format(where="WHERE i.id=:id"), id=iid)
    if not inc:
        raise not_found("Incident")
    ids = [t for t in (inc["technique_ids"] or "").split(",") if t]
    techniques = []
    for t in ids:
        row = one(conn, "SELECT technique_id, name, tactics, description FROM attack_techniques WHERE technique_id=:t", t=t)
        techniques.append(row or {"technique_id": t, "name": "Not in loaded ATT&CK snapshot", "tactics": "", "description": ""})
    return {**inc, "techniques": techniques}


# ------------------------------------------------------------------ controls / compliance
@router.get("/controls")
def list_controls(framework: str | None = Query(None, max_length=60), status: str | None = Query(None, max_length=20), evidence: str | None = Query(None, max_length=20),
                  q: str | None = Query(None, max_length=100), page: int = 1, page_size: int = 50, conn: Connection = Depends(get_conn)):
    items = [c for c in controls_with_evidence(conn) if c["framework"] != "MITRE ATT&CK"]
    if framework:
        items = [c for c in items if c["framework"] == framework]
    if status:
        items = [c for c in items if c["implementation_status"] == status.upper()]
    if evidence:
        items = [c for c in items if c["evidence_status"] == evidence.upper()]
    if q:
        ql = q.lower()
        items = [c for c in items if ql in c["title"].lower() or ql in c["control_code"].lower()]
    page_size = max(1, min(page_size, 200))
    page = max(1, page)
    return {"items": items[(page - 1) * page_size: page * page_size], "total": len(items), "page": page, "page_size": page_size}


@router.get("/controls/{cid}")
def get_control(cid: int, conn: Connection = Depends(get_conn)):
    c = next((x for x in controls_with_evidence(conn) if x["id"] == cid), None)
    if not c:
        raise not_found("Control")
    desc = scalar(conn, "SELECT description FROM controls WHERE id=:i", i=cid)
    linked = rows(conn, "SELECT r.id, r.risk_code, r.title, r.risk_level FROM risk_controls rc JOIN risks r ON r.id=rc.risk_id WHERE rc.control_id=:i", i=cid)
    return {**c, "description": desc, "linked_risks": linked}


@router.get("/controls/{cid}/evidence")
def control_evidence(cid: int, conn: Connection = Depends(get_conn)):
    if not scalar(conn, "SELECT 1 FROM controls WHERE id=:i", i=cid):
        raise not_found("Control")
    return {"items": rows(conn, "SELECT id, evidence_type, title, location, status, collected_at, expiry_date, owner FROM evidence WHERE control_id=:i ORDER BY collected_at DESC", i=cid)}


@router.get("/compliance/summary")
def compliance(conn: Connection = Depends(get_conn)):
    return {"frameworks": compliance_summary(conn)}


@router.get("/compliance/{framework_id}")
def compliance_framework(framework_id: int, conn: Connection = Depends(get_conn)):
    fw = one(conn, "SELECT * FROM frameworks WHERE id=:i", i=framework_id)
    if not fw:
        raise not_found("Framework")
    ctl = controls_with_evidence(conn, framework_id)
    by_cat: dict[str, list[dict]] = {}
    for c in ctl:
        by_cat.setdefault(c["category"] or "Other", []).append(c)
    return {**fw, **coverage(ctl), "categories": [{"category": k, **coverage(v)} for k, v in by_cat.items()], "controls": ctl,
            "note": "Internal readiness metric; not a certification."}


# ------------------------------------------------------------------ vendors
VENDOR_SORT = {"vendor_name": "v.vendor_name", "criticality": "v.criticality", "residual_risk": "v.residual_risk", "inherent_risk": "v.inherent_risk",
               "assessment_status": "v.assessment_status", "next_review": "v.next_review"}


@router.get("/vendors")
def list_vendors(criticality: Level | None = None, assessment_status: str | None = Query(None, max_length=20), high_risk: bool | None = None,
                 sort: str | None = None, order: Order = "desc", page: int = 1, page_size: int = 25, conn: Connection = Depends(get_conn)):
    cond, p = [], {}
    if criticality:
        cond.append("v.criticality=:c"); p["c"] = criticality
    if assessment_status:
        cond.append("v.assessment_status=:s"); p["s"] = assessment_status.upper()
    if high_risk:
        cond.append("v.residual_risk >= 7")
    where = ("WHERE " + " AND ".join(cond)) if cond else ""
    sel = f"""SELECT v.*, (SELECT COUNT(*) FROM vendor_findings f WHERE f.vendor_id=v.id AND f.status='OPEN') AS open_findings,
                     CASE WHEN v.next_review < date('now') THEN 1 ELSE 0 END AS review_overdue FROM vendors v {where}"""  # noqa: S608
    return paged(conn, sel, f"SELECT COUNT(*) FROM vendors v {where}", p, VENDOR_SORT, sort, order, page, page_size, "residual_risk")  # noqa: S608


@router.get("/vendors/{vid}")
def get_vendor(vid: int, conn: Connection = Depends(get_conn)):
    v = one(conn, "SELECT * FROM vendors WHERE id=:i", i=vid)
    if not v:
        raise not_found("Vendor")
    return {**v, "findings": rows(conn, "SELECT id, finding, severity, status, due_date FROM vendor_findings WHERE vendor_id=:i ORDER BY id", i=vid)}


@router.get("/vendors-summary/distribution")
def vendor_distribution(conn: Connection = Depends(get_conn)):
    return {"items": rows(conn, """SELECT CASE WHEN residual_risk>=7 THEN 'High (7-10)' WHEN residual_risk>=4 THEN 'Medium (4-7)' ELSE 'Low (0-4)' END AS label,
                                          COUNT(*) AS count FROM vendors GROUP BY label""")}
