"""ETL for organisational (synthetic) CSV/JSON sources.

extract (pandas) -> validate -> normalise -> referential check -> deduplicate -> load -> quality metrics -> audit log
Bad rows are never silently dropped: each is stored in etl_rejections with reason and raw payload.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable

import pandas as pd
from sqlalchemy import Connection
from sqlalchemy.engine import Engine

from app.db.session import connect, execute, get_engine, rows, scalar
from app.etl import provenance as prov
from app.etl.quality import quality_score
from app.risk import engine as risk_engine

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
TRUE, FALSE = {"y", "yes", "true", "1"}, {"n", "no", "false", "0"}


class Reject(Exception):
    def __init__(self, kind: str, reason: str):
        self.kind, self.reason = kind, reason  # kind: missing | invalid | orphan


def parse_bool(v: str, field_name: str) -> int:
    s = v.strip().lower()
    if s in TRUE:
        return 1
    if s in FALSE:
        return 0
    raise Reject("invalid", f"{field_name}: unrecognised boolean {v!r}")


SEV_ALIASES = {"VERY_HIGH": "CRITICAL", "SEVERE": "CRITICAL", "URGENT": "CRITICAL", "P1": "CRITICAL", "TIER_1": "CRITICAL", "SEV1": "CRITICAL", "SEV_1": "CRITICAL",
               "IMPORTANT": "HIGH", "P2": "HIGH", "TIER_2": "HIGH", "SEV2": "HIGH", "SEV_2": "HIGH", "MODERATE": "MEDIUM", "NORMAL": "MEDIUM", "P3": "MEDIUM", "TIER_3": "MEDIUM", "SEV3": "MEDIUM", "SEV_3": "MEDIUM",
               "MINOR": "LOW", "INFO": "LOW", "INFORMATIONAL": "LOW", "VERY_LOW": "LOW", "P4": "LOW", "TIER_4": "LOW", "SEV4": "LOW", "SEV_4": "LOW"}


def parse_enum(v: str, allowed: set[str], field_name: str, aliases: dict[str, str] | None = None) -> str:
    s = v.strip().upper().replace(" ", "_").replace("-", "_")
    if allowed == SEVERITIES:
        s = SEV_ALIASES.get(s, s)
    s = (aliases or {}).get(s, s)
    if s not in allowed:
        raise Reject("invalid", f"{field_name}: {v!r} not in {sorted(allowed)}")
    return s


def parse_date(v: str, field_name: str, required: bool = False) -> str | None:
    v = v.strip()
    if not v:
        if required:
            raise Reject("missing", f"{field_name} is required")
        return None
    try:
        return date.fromisoformat(v[:10]).isoformat()
    except ValueError:
        raise Reject("invalid", f"{field_name}: bad date {v!r}")


def parse_float(v: str, field_name: str, lo: float, hi: float) -> float:
    try:
        f = float(v)
    except (TypeError, ValueError):
        raise Reject("invalid", f"{field_name}: not numeric ({v!r})")
    if not lo <= f <= hi:
        raise Reject("invalid", f"{field_name}: {f} outside {lo}-{hi}")
    return f


def parse_int(v: str, field_name: str, lo: int, hi: int) -> int:
    try:
        i = int(float(v))
    except (TypeError, ValueError):
        raise Reject("invalid", f"{field_name}: not an integer ({v!r})")
    if not lo <= i <= hi:
        raise Reject("invalid", f"{field_name}: {i} outside {lo}-{hi}")
    return i


def require(raw: dict, *names: str) -> None:
    for n in names:
        if not str(raw.get(n, "")).strip():
            raise Reject("missing", f"required field '{n}' is empty")


@dataclass
class Dataset:
    name: str
    file: str
    key: Callable[[dict], tuple]
    transform: Callable[[dict, "Ctx"], dict]
    load: Callable[[Connection, list[dict]], int]


@dataclass
class Ctx:
    conn: Connection
    today: date = field(default_factory=date.today)
    _cache: dict[str, dict] = field(default_factory=dict)

    def lookup(self, table: str, key_col: str) -> dict:
        k = f"{table}.{key_col}"
        if k not in self._cache:
            self._cache[k] = {r[key_col]: r["id"] for r in rows(self.conn, f"SELECT id, {key_col} FROM {table}")}  # noqa: S608 (static identifiers)
        return self._cache[k]


# ---- per-dataset transforms ---------------------------------------------
def t_asset(r: dict, ctx: Ctx) -> dict:
    require(r, "asset_tag", "hostname", "criticality", "owner_role", "business_unit")
    return {
        "asset_tag": r["asset_tag"].strip().upper(), "name": r["hostname"].strip().lower(), "asset_type": r["asset_type"].strip(),
        "business_unit": r["business_unit"].strip(), "owner": r["owner_role"].strip(),
        "criticality": parse_enum(r["criticality"], SEVERITIES, "criticality"),
        "internet_exposed": parse_bool(r["internet_exposed"], "internet_exposed"),
        "data_classification": r["data_classification"].strip(), "environment": r["environment"].strip(),
        "status": parse_enum(r["status"], {"ACTIVE", "DECOMMISSIONED"}, "status"),
    }


def l_asset(conn: Connection, recs: list[dict]) -> int:
    for r in recs:
        execute(conn, """INSERT INTO assets (asset_tag,name,asset_type,business_unit,owner,criticality,internet_exposed,data_classification,environment,status)
                         VALUES (:asset_tag,:name,:asset_type,:business_unit,:owner,:criticality,:internet_exposed,:data_classification,:environment,:status)
                         ON CONFLICT(asset_tag) DO UPDATE SET name=excluded.name, asset_type=excluded.asset_type, business_unit=excluded.business_unit,
                           owner=excluded.owner, criticality=excluded.criticality, internet_exposed=excluded.internet_exposed,
                           data_classification=excluded.data_classification, environment=excluded.environment, status=excluded.status,
                           updated_at=CURRENT_TIMESTAMP""", **r)
    return len(recs)


def t_employee(r: dict, ctx: Ctx) -> dict:
    require(r, "employee_id", "department")
    return {"employee_code": r["employee_id"].strip().upper(), "department": r["department"].strip(), "role": r["role"].strip(),
            "privilege_level": r["privilege_level"].strip().title(), "mfa_enabled": parse_bool(r["mfa_enabled"], "mfa_enabled"),
            "account_status": r["account_status"].strip().title(), "last_login_days": parse_int(r["last_login_days"], "last_login_days", 0, 5000),
            "training_status": r["training_status"].strip().title()}


def l_employee(conn: Connection, recs: list[dict]) -> int:
    for r in recs:
        execute(conn, """INSERT INTO employees (employee_code,department,role,privilege_level,mfa_enabled,account_status,last_login_days,training_status)
                         VALUES (:employee_code,:department,:role,:privilege_level,:mfa_enabled,:account_status,:last_login_days,:training_status)
                         ON CONFLICT(employee_code) DO UPDATE SET department=excluded.department, role=excluded.role, privilege_level=excluded.privilege_level,
                           mfa_enabled=excluded.mfa_enabled, account_status=excluded.account_status, last_login_days=excluded.last_login_days,
                           training_status=excluded.training_status""", **r)
    return len(recs)


def t_vendor(r: dict, ctx: Ctx) -> dict:
    require(r, "vendor_id", "vendor_name", "criticality", "inherent_risk")
    return {"vendor_code": r["vendor_id"].strip().upper(), "vendor_name": r["vendor_name"].strip(), "service_category": r["service_category"].strip(),
            "criticality": parse_enum(r["criticality"], SEVERITIES, "criticality"), "data_access": r["data_access"].strip(),
            "inherent_risk": parse_float(r["inherent_risk"], "inherent_risk", 0, 10),
            "assessment_status": parse_enum(r["security_assessment_status"], {"COMPLETED", "IN_PROGRESS", "OVERDUE", "NOT_STARTED"}, "assessment_status"),
            "last_assessed": parse_date(r["last_assessed"], "last_assessed"), "next_review": parse_date(r["next_review"], "next_review")}


def l_vendor(conn: Connection, recs: list[dict]) -> int:
    for r in recs:
        execute(conn, """INSERT INTO vendors (vendor_code,vendor_name,service_category,criticality,data_access,inherent_risk,residual_risk,assessment_status,last_assessed,next_review)
                         VALUES (:vendor_code,:vendor_name,:service_category,:criticality,:data_access,:inherent_risk,:inherent_risk,:assessment_status,:last_assessed,:next_review)
                         ON CONFLICT(vendor_code) DO UPDATE SET vendor_name=excluded.vendor_name, service_category=excluded.service_category,
                           criticality=excluded.criticality, data_access=excluded.data_access, inherent_risk=excluded.inherent_risk,
                           assessment_status=excluded.assessment_status, last_assessed=excluded.last_assessed, next_review=excluded.next_review""", **r)
    return len(recs)


def t_vendor_finding(r: dict, ctx: Ctx) -> dict:
    require(r, "vendor_id", "finding")
    vid = ctx.lookup("vendors", "vendor_code").get(r["vendor_id"].strip().upper())
    if vid is None:
        raise Reject("orphan", f"vendor_id {r['vendor_id']!r} not found")
    return {"vendor_id": vid, "finding": r["finding"].strip(), "severity": parse_enum(r["severity"], SEVERITIES, "severity"),
            "status": parse_enum(r["status"], {"OPEN", "REMEDIATED"}, "status"), "due_date": parse_date(r["due_date"], "due_date")}


def l_vendor_finding(conn: Connection, recs: list[dict]) -> int:
    execute(conn, "DELETE FROM vendor_findings")
    for r in recs:
        execute(conn, "INSERT INTO vendor_findings (vendor_id,finding,severity,status,due_date) VALUES (:vendor_id,:finding,:severity,:status,:due_date)", **r)
    return len(recs)


def t_control_status(r: dict, ctx: Ctx) -> dict:
    require(r, "control_ref", "implementation_status")
    ref = r["control_ref"].strip()
    cmap = _control_refs(ctx)
    if ref.upper() not in cmap:
        raise Reject("orphan", f"control_ref {ref!r} not in framework catalog")
    return {"id": cmap[ref.upper()], "implementation_status": parse_enum(r["implementation_status"], {"IMPLEMENTED", "PARTIAL", "NOT_IMPLEMENTED", "NOT_APPLICABLE"}, "implementation_status"),
            "effectiveness": parse_float(r["effectiveness"], "effectiveness", 0, 1), "owner": r["owner_role"].strip()}


def l_control_status(conn: Connection, recs: list[dict]) -> int:
    for r in recs:
        execute(conn, "UPDATE controls SET implementation_status=:implementation_status, effectiveness=:effectiveness, owner=:owner WHERE id=:id", **r)
    return len(recs)


SLUGS = {"NIST CSF": "NIST-CSF", "ISO/IEC 27001": "ISO-27001", "SOC 2": "SOC2"}


def _control_refs(ctx: Ctx) -> dict[str, int]:
    if "control_refs" not in ctx._cache:
        ctx._cache["control_refs"] = {
            f"{SLUGS.get(r['name'], r['name'])}/{r['control_code']}".upper(): r["id"]
            for r in rows(ctx.conn, "SELECT c.id, c.control_code, f.name FROM controls c JOIN frameworks f ON f.id=c.framework_id")}
    return ctx._cache["control_refs"]


def t_evidence(r: dict, ctx: Ctx) -> dict:
    require(r, "evidence_id", "control_id", "status")
    cid = _control_refs(ctx).get(r["control_id"].strip().upper())
    if cid is None:
        raise Reject("orphan", f"control {r['control_id']!r} not found")
    status = parse_enum(r["status"], {"PRESENT", "MISSING", "EXPIRED", "NEEDS_REVIEW"}, "status")
    expiry = parse_date(r["expiry_date"], "expiry_date")
    if status == "PRESENT" and expiry and expiry < ctx.today.isoformat():
        status = "EXPIRED"  # consistency rule: past-expiry evidence cannot be PRESENT
    return {"control_id": cid, "evidence_type": r["evidence_type"].strip(), "title": r["evidence_id"].strip().upper(), "location": f"evidence-store/{r['evidence_id'].strip()}",
            "status": status, "collected_at": parse_date(r["collected_at"], "collected_at"), "expiry_date": expiry, "owner": r["owner_role"].strip()}


def l_evidence(conn: Connection, recs: list[dict]) -> int:
    execute(conn, "DELETE FROM evidence")
    for r in recs:
        execute(conn, """INSERT INTO evidence (control_id,evidence_type,title,location,status,collected_at,expiry_date,owner)
                         VALUES (:control_id,:evidence_type,:title,:location,:status,:collected_at,:expiry_date,:owner)""", **r)
    return len(recs)


VULN_STATUS = {"OPEN", "IN_PROGRESS", "RESOLVED", "ACCEPTED"}
VULN_ALIASES = {"CLOSED": "RESOLVED", "FIXED": "RESOLVED", "INPROGRESS": "IN_PROGRESS"}


def t_vuln(r: dict, ctx: Ctx) -> dict:
    require(r, "cve_id", "asset_tag", "status")
    cve = r["cve_id"].strip().upper()
    if not CVE_RE.match(cve):
        raise Reject("invalid", f"cve_id: malformed {r['cve_id']!r}")
    scanner_cvss = parse_float(r["scanner_cvss"], "scanner_cvss", 0, 10) if r["scanner_cvss"].strip() else None  # rejects N/A and out-of-range; blank is allowed if NVD has the CVE
    aid = ctx.lookup("assets", "asset_tag").get(r["asset_tag"].strip().upper())
    if aid is None:
        raise Reject("orphan", f"asset_tag {r['asset_tag']!r} not found")
    cat = _cve_catalog(ctx).get(cve)
    cvss = cat["cvss_score"] if cat and cat["cvss_score"] is not None else scanner_cvss  # NVD is authoritative when available
    if cvss is None:
        raise Reject("missing", f"no CVSS: scanner value blank and {cve} not in the loaded NVD data")
    disc = parse_date(r["discovered_at"], "discovered_at", required=True)
    due = parse_date(r["due_date"], "due_date") or disc
    return {"cve_id": cve, "asset_id": aid, "title": (cat or {}).get("description", "")[:140] if cat else None, "severity": risk_engine.cvss_severity(cvss),
            "cvss_score": cvss, "exploitability": r["exploitability"].strip().upper() or "NONE",
            "known_exploited": int(bool(cat and cat["in_kev"])), "status": parse_enum(r["status"], VULN_STATUS, "status", VULN_ALIASES),
            "discovered_at": disc, "due_date": due, "resolved_at": parse_date(r["resolved_at"], "resolved_at"),
            "source": "NVD+scanner" if cat else "scanner"}


def _cve_catalog(ctx: Ctx) -> dict[str, dict]:
    if "cve_catalog" not in ctx._cache:
        ctx._cache["cve_catalog"] = {r["cve_id"]: r for r in rows(ctx.conn, "SELECT cve_id, description, cvss_score, in_kev FROM cve_catalog")}
    return ctx._cache["cve_catalog"]


def l_vuln(conn: Connection, recs: list[dict]) -> int:
    for r in recs:
        execute(conn, """INSERT INTO vulnerabilities (cve_id,asset_id,title,severity,cvss_score,exploitability,known_exploited,status,discovered_at,due_date,resolved_at,source)
                         VALUES (:cve_id,:asset_id,:title,:severity,:cvss_score,:exploitability,:known_exploited,:status,:discovered_at,:due_date,:resolved_at,:source)
                         ON CONFLICT(cve_id, asset_id) DO UPDATE SET title=excluded.title, severity=excluded.severity, cvss_score=excluded.cvss_score,
                           exploitability=excluded.exploitability, known_exploited=excluded.known_exploited, status=excluded.status,
                           discovered_at=excluded.discovered_at, due_date=excluded.due_date, resolved_at=excluded.resolved_at, source=excluded.source""", **r)
    return len(recs)


def t_incident(r: dict, ctx: Ctx) -> dict:
    require(r, "incident_id", "severity", "status", "detected_at")
    tag = r["affected_asset_id"].strip().upper()
    aid = ctx.lookup("assets", "asset_tag").get(tag) if tag else None
    if tag and aid is None:
        raise Reject("orphan", f"affected asset {r['affected_asset_id']!r} not found")
    techs = [t.strip().upper() for t in r["mitre_technique_ids"].split(";") if t.strip()]
    bad = [t for t in techs if not TECH_RE.match(t)]
    if bad:
        raise Reject("invalid", f"malformed technique ids {bad}")
    return {"incident_code": r["incident_id"].strip().upper(), "title": r["title"].strip(), "severity": parse_enum(r["severity"], SEVERITIES, "severity"),
            "status": parse_enum(r["status"], {"OPEN", "INVESTIGATING", "CONTAINED", "CLOSED"}, "status", {"IN_PROGRESS": "INVESTIGATING", "RESOLVED": "CLOSED", "NEW": "OPEN", "ACTIVE": "OPEN", "MITIGATED": "CONTAINED", "DONE": "CLOSED"}), "category": r["category"].strip(),
            "detected_at": parse_date(r["detected_at"], "detected_at", True), "resolved_at": parse_date(r["resolved_at"], "resolved_at"),
            "affected_asset_id": aid, "description": r["description"].strip(), "technique_ids": ",".join(techs)}


def l_incident(conn: Connection, recs: list[dict]) -> int:
    for r in recs:
        execute(conn, """INSERT INTO incidents (incident_code,title,severity,status,category,detected_at,resolved_at,affected_asset_id,description,technique_ids)
                         VALUES (:incident_code,:title,:severity,:status,:category,:detected_at,:resolved_at,:affected_asset_id,:description,:technique_ids)
                         ON CONFLICT(incident_code) DO UPDATE SET title=excluded.title, severity=excluded.severity, status=excluded.status, category=excluded.category,
                           detected_at=excluded.detected_at, resolved_at=excluded.resolved_at, affected_asset_id=excluded.affected_asset_id,
                           description=excluded.description, technique_ids=excluded.technique_ids""", **r)
    return len(recs)


def t_audit(r: dict, ctx: Ctx) -> dict:
    require(r, "finding_id", "title", "severity")
    return {"finding_code": r["finding_id"].strip().upper(), "title": r["title"].strip(), "source": r["source"].strip(),
            "severity": parse_enum(r["severity"], SEVERITIES, "severity"),
            "status": parse_enum(r["status"], {"OPEN", "IN_PROGRESS", "CLOSED"}, "status"), "owner": r["owner_role"].strip(), "due_date": parse_date(r["due_date"], "due_date")}


def l_audit(conn: Connection, recs: list[dict]) -> int:
    for r in recs:
        execute(conn, """INSERT INTO audit_findings (finding_code,title,source,severity,status,owner,due_date)
                         VALUES (:finding_code,:title,:source,:severity,:status,:owner,:due_date)
                         ON CONFLICT(finding_code) DO UPDATE SET title=excluded.title, source=excluded.source, severity=excluded.severity,
                           status=excluded.status, owner=excluded.owner, due_date=excluded.due_date""", **r)
    return len(recs)


RISK_STATUS = {"IDENTIFIED", "ASSESSMENT", "TREATMENT", "MITIGATION", "VALIDATION", "ACCEPTED", "CLOSED"}


def t_risk(r: dict, ctx: Ctx) -> dict:
    require(r, "risk_code", "title", "likelihood", "impact")
    aid = ctx.lookup("assets", "asset_tag").get(r["asset_tag"].strip().upper()) if r["asset_tag"].strip() else None
    if r["asset_tag"].strip() and aid is None:
        raise Reject("orphan", f"asset_tag {r['asset_tag']!r} not found")
    refs = [x.strip().upper() for x in r["control_refs"].split(";") if x.strip()]
    cmap = _control_refs(ctx)
    missing = [x for x in refs if x not in cmap]
    if missing:
        raise Reject("orphan", f"unknown control refs {missing}")
    techs = [x.strip().upper() for x in r["technique_ids"].split(";") if x.strip()]
    li, im = parse_int(r["likelihood"], "likelihood", 1, 5), parse_int(r["impact"], "impact", 1, 5)
    return {"risk_code": r["risk_code"].strip().upper(), "title": r["title"].strip(), "category": r["category"].strip(), "asset_id": aid,
            "likelihood": li, "impact": im, "owner": r["owner_role"].strip(), "status": parse_enum(r["status"], RISK_STATUS, "status"),
            "treatment": parse_enum(r["treatment"], {"MITIGATE", "TRANSFER", "AVOID", "ACCEPT"}, "treatment"),
            "due_date": parse_date(r["due_date"], "due_date"), "_controls": [cmap[x] for x in refs], "_techniques": techs}


def l_risk(conn: Connection, recs: list[dict]) -> int:
    for r in recs:
        inh = risk_engine.inherent_score(r["likelihood"], r["impact"])
        res = execute(conn, """INSERT INTO risks (risk_code,title,category,asset_id,likelihood,impact,inherent_score,control_effectiveness,residual_score,risk_level,owner,status,treatment,due_date)
                         VALUES (:risk_code,:title,:category,:asset_id,:likelihood,:impact,:inh,0,:inh,:lvl,:owner,:status,:treatment,:due_date)
                         ON CONFLICT(risk_code) DO UPDATE SET title=excluded.title, category=excluded.category, asset_id=excluded.asset_id,
                           likelihood=excluded.likelihood, impact=excluded.impact, owner=excluded.owner, status=excluded.status,
                           treatment=excluded.treatment, due_date=excluded.due_date, updated_at=CURRENT_TIMESTAMP""",
                       inh=inh, lvl=risk_engine.risk_level(inh), **{k: v for k, v in r.items() if not k.startswith("_")})
        rid = scalar(conn, "SELECT id FROM risks WHERE risk_code=:c", c=r["risk_code"])
        execute(conn, "DELETE FROM risk_controls WHERE risk_id=:r", r=rid)
        execute(conn, "DELETE FROM control_mappings WHERE source_type='risk' AND source_id=:r AND origin='CURATED'", r=rid)
        for cid in r["_controls"]:
            execute(conn, "INSERT OR IGNORE INTO risk_controls (risk_id, control_id) VALUES (:r,:c)", r=rid, c=cid)
            fw = scalar(conn, "SELECT framework_id FROM controls WHERE id=:c", c=cid)
            execute(conn, """INSERT INTO control_mappings (source_type,source_id,framework_id,control_id,mapping_reason,confidence,origin,review_state)
                             VALUES ('risk',:r,:fw,:c,'Curated mapping: control mitigates the risk scenario',1.0,'CURATED','APPROVED')""", r=rid, fw=fw, c=cid)
        for t in r["_techniques"]:
            fw = scalar(conn, "SELECT id FROM frameworks WHERE name='MITRE ATT&CK'")
            if fw and scalar(conn, "SELECT 1 FROM attack_techniques WHERE technique_id=:t", t=t):
                execute(conn, """INSERT INTO control_mappings (source_type,source_id,framework_id,external_ref,mapping_reason,confidence,origin,review_state)
                                 VALUES ('risk',:r,:fw,:t,'Adversary technique context for this risk scenario',1.0,'CURATED','APPROVED')""", r=rid, fw=fw, t=t)
    return len(recs)


def t_remediation(r: dict, ctx: Ctx) -> dict:
    require(r, "risk_code", "action")
    rid = ctx.lookup("risks", "risk_code").get(r["risk_code"].strip().upper())
    if rid is None:
        raise Reject("orphan", f"risk_code {r['risk_code']!r} not found")
    return {"risk_id": rid, "action": r["action"].strip(), "owner": r["owner_role"].strip(), "priority": parse_enum(r["priority"], SEVERITIES, "priority"),
            "due_date": parse_date(r["due_date"], "due_date"), "status": parse_enum(r["status"], {"OPEN", "IN_PROGRESS", "COMPLETED"}, "status"),
            "effectiveness_gain": parse_float(r["effectiveness_gain"], "effectiveness_gain", 0, 1)}


def l_remediation(conn: Connection, recs: list[dict]) -> int:
    execute(conn, "DELETE FROM remediation_actions")
    for r in recs:
        execute(conn, """INSERT INTO remediation_actions (risk_id,action,owner,priority,due_date,status,effectiveness_gain,completed_at)
                         VALUES (:risk_id,:action,:owner,:priority,:due_date,:status,:effectiveness_gain, CASE WHEN :status='COMPLETED' THEN :due_date END)""", **r)
    return len(recs)


DATASETS: list[Dataset] = [
    Dataset("assets", "assets.csv", lambda r: (r["asset_tag"],), t_asset, l_asset),
    Dataset("employees", "employees.csv", lambda r: (r["employee_code"],), t_employee, l_employee),
    Dataset("vendors", "vendors.csv", lambda r: (r["vendor_code"],), t_vendor, l_vendor),
    Dataset("vendor_findings", "vendor_findings.csv", lambda r: (r["vendor_id"], r["finding"]), t_vendor_finding, l_vendor_finding),
    Dataset("control_status", "control_status.csv", lambda r: (r["id"],), t_control_status, l_control_status),
    Dataset("compliance_evidence", "compliance_evidence.csv", lambda r: (r["title"],), t_evidence, l_evidence),
    Dataset("vulnerability_scan", "vulnerability_scan.csv", lambda r: (r["cve_id"], r["asset_id"]), t_vuln, l_vuln),
    Dataset("incidents", "incidents.csv", lambda r: (r["incident_code"],), t_incident, l_incident),
    Dataset("audit_findings", "audit_findings.csv", lambda r: (r["finding_code"],), t_audit, l_audit),
    Dataset("risk_register", "risk_register.csv", lambda r: (r["risk_code"],), t_risk, l_risk),
    Dataset("remediation_actions", "remediation_actions.csv", lambda r: (r["risk_id"], r["action"]), t_remediation, l_remediation),
]
DATASET_BY_NAME = {d.name: d for d in DATASETS}


def read_table(path: Path) -> pd.DataFrame:
    """CSV/JSON adapter: everything is read as text and whitespace-trimmed; typing happens in the validators."""
    if path.suffix.lower() == ".json":
        df = pd.read_json(path, dtype=False, orient="records").fillna("").astype(str)
    else:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
    return df.apply(lambda col: col.str.strip())


def run_dataset(ds: Dataset, path: Path, engine: Engine | None = None, today: date | None = None) -> dict:
    """Run one dataset end to end; returns the run summary. Raises nothing for bad rows."""
    engine = engine or get_engine()
    started = datetime.now()
    df = read_table(path)
    checksum = __import__("hashlib").sha256(path.read_bytes()).hexdigest()

    with connect(engine) as conn:
        source_name = f"Synthetic {ds.name}"
        prov.ensure_registry(conn, name=source_name, publisher="Generated by CyberRisk (seed 42)", source_type="SYNTHETIC",
                             official_url=f"file://{path.name}", method="Deterministic synthetic generator", license_notes="Synthetic data; contains no real people or organisations.")
        sid = prov.ensure_data_source(conn, source_name, "SYNTHETIC", path.name)
        run_id = prov.start_run(conn, source_id=sid, name=source_name, version="seed-42", checksum=checksum, retrieved_at=prov.utcnow())
        ctx = Ctx(conn, today or date.today())
        valid: list[dict] = []
        rejected: list[tuple[int, str, Any]] = []
        counts = {"missing": 0, "invalid": 0, "orphan": 0}
        for i, raw in enumerate(df.to_dict("records"), start=2):  # row 1 is the header
            try:
                valid.append(ds.transform(raw, ctx))
            except Reject as rej:
                counts[rej.kind] += 1
                rejected.append((i, f"[{rej.kind}] {rej.reason}", raw))
            except KeyError as exc:
                counts["missing"] += 1
                rejected.append((i, f"[missing] column {exc} absent", raw))
        seen: set = set()
        unique: list[dict] = []
        dups = 0
        for rec in valid:
            k = ds.key(rec)
            if k in seen:
                dups += 1
                continue
            seen.add(k)
            unique.append(rec)
        prov.log_rejections(conn, run_id, rejected)
        loaded = ds.load(conn, unique)
        q = quality_score(len(df), counts["missing"], counts["invalid"], dups, counts["orphan"])
        prov.finish_run(conn, run_id, read=len(df), valid=len(unique), rejected=len(rejected), loaded=loaded, duplicates=dups, quality=q["score"])
        prov.registry_success(conn, source_name, retrieved_at=prov.utcnow(), version="seed-42", checksum=checksum, records=loaded, from_cache=False)
        execute(conn, "UPDATE data_sources SET ingestion_status='HEALTHY', last_run=:t WHERE id=:id", t=prov.utcnow(), id=sid)
    return {"dataset": ds.name, "run_id": run_id, "read": len(df), "valid": len(unique), "rejected": len(rejected), "duplicates": dups,
            "loaded": loaded, "quality_score": q["score"], "penalties": q["penalties"], "seconds": round((datetime.now() - started).total_seconds(), 2)}


def run_all(directory: Path, engine: Engine | None = None, only: list[str] | None = None, today: date | None = None) -> list[dict]:
    from app.risk.service import recalculate_all  # local import: avoids a cycle

    engine = engine or get_engine()
    results = []
    for ds in DATASETS:
        if only and ds.name not in only:
            continue
        p = directory / ds.file
        if p.exists():
            results.append(run_dataset(ds, p, engine, today))
    with connect(engine) as conn:
        recalculate_all(conn, today=today)
    return results
