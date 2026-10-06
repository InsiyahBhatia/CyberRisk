"""Deterministic context assembly: explicitly selected structured facts, each with an evidence id. Gemini never touches the database."""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import Connection

from app.api.dashboard import kpis
from app.db.session import one, rows
from app.grc.service import compliance_summary


@dataclass
class Facts:
    items: dict[str, dict] = field(default_factory=dict)   # evidence id -> fact
    retrieval_query: str = ""
    risk_level: str | None = None                            # deterministic level the answer must match
    deterministic: dict = field(default_factory=dict)        # numbers shown to the user, attached server-side

    def add(self, evidence_id: str, fact: dict) -> None:
        self.items[evidence_id] = {k: (round(v, 2) if isinstance(v, float) else v) for k, v in fact.items() if v is not None}


def risk_facts(conn: Connection, risk_id: int) -> Facts | None:
    r = one(conn, """SELECT r.*, a.asset_tag, a.business_unit, a.criticality AS asset_criticality, a.internet_exposed, a.data_classification, a.environment
                     FROM risks r LEFT JOIN assets a ON a.id=r.asset_id WHERE r.id=:i""", i=risk_id)
    if not r:
        return None
    f = Facts(risk_level=r["risk_level"])
    f.add(f"DB:risk:{r['risk_code']}", {k: r[k] for k in ("risk_code", "title", "category", "status", "treatment", "owner", "likelihood", "impact", "inherent_score",
                                                          "control_effectiveness", "residual_score", "risk_level", "approval_status", "due_date")})
    f.deterministic = {k: round(r[k], 2) if isinstance(r[k], float) else r[k] for k in ("risk_code", "inherent_score", "control_effectiveness", "residual_score", "risk_level", "likelihood", "impact")}
    if r["asset_tag"]:
        f.add(f"DB:asset:{r['asset_tag']}", {k: r[k] for k in ("asset_tag", "business_unit", "asset_criticality", "internet_exposed", "data_classification", "environment")})
        for v in rows(conn, """SELECT id, cve_id, severity, cvss_score, known_exploited, due_date, risk_score, status,
                                      CASE WHEN due_date < date('now') THEN 1 ELSE 0 END AS overdue
                               FROM vulnerabilities WHERE asset_id=:a AND status IN ('OPEN','IN_PROGRESS') ORDER BY risk_score DESC LIMIT 5""", a=r["asset_id"]):
            f.add(f"DB:vuln:{v['id']}", {k: v[k] for k in ("cve_id", "severity", "cvss_score", "known_exploited", "due_date", "overdue", "risk_score", "status")})
        for i in rows(conn, "SELECT incident_code, title, severity, status, category, technique_ids FROM incidents WHERE affected_asset_id=:a ORDER BY detected_at DESC LIMIT 3", a=r["asset_id"]):
            f.add(f"DB:incident:{i['incident_code']}", i)
    for c in rows(conn, """SELECT c.control_code, c.title, c.implementation_status, c.effectiveness, fw.name AS framework,
                                  (SELECT COALESCE(MAX(CASE e.status WHEN 'PRESENT' THEN 3 WHEN 'EXPIRED' THEN 2 WHEN 'NEEDS_REVIEW' THEN 1 ELSE 0 END), 0)
                                   FROM evidence e WHERE e.control_id=c.id) AS ev_rank
                           FROM risk_controls rc JOIN controls c ON c.id=rc.control_id JOIN frameworks fw ON fw.id=c.framework_id WHERE rc.risk_id=:r""", r=risk_id):
        ev = {3: "PRESENT", 2: "EXPIRED", 1: "NEEDS_REVIEW", 0: "MISSING"}[c.pop("ev_rank")]
        f.add(f"DB:control:{c['framework']}/{c['control_code']}", {**c, "evidence_status": ev})
    for t in rows(conn, """SELECT t.technique_id, t.name, t.tactics FROM control_mappings m JOIN attack_techniques t ON t.technique_id=m.external_ref
                           WHERE m.source_type='risk' AND m.source_id=:r""", r=risk_id):
        f.add(f"DB:technique:{t['technique_id']}", t)
    for a in rows(conn, "SELECT id, action, owner, priority, due_date, status, effectiveness_gain FROM remediation_actions WHERE risk_id=:r", r=risk_id):
        f.add(f"DB:action:{a['id']}", a)
    ctl_codes = " ".join(k.split(":", 2)[2] for k in f.items if k.startswith("DB:control:"))
    f.retrieval_query = f"{r['title']} {r['category'] or ''} {ctl_codes}"
    return f


def executive_facts(conn: Connection) -> Facts:
    f = Facts()
    k = kpis(conn)
    f.add("DB:kpi:summary", k)
    for r in rows(conn, "SELECT risk_code, title, residual_score, risk_level, status, owner FROM risks WHERE status!='CLOSED' ORDER BY residual_score DESC LIMIT 5"):
        f.add(f"DB:risk:{r['risk_code']}", r)
    for c in compliance_summary(conn):
        f.add(f"DB:compliance:{c['name']}", {k2: c[k2] for k2 in ("name", "version", "control_coverage", "evidence_coverage", "applicable_controls", "note")})
    for s in rows(conn, "SELECT source_name, source_type, status, retrieval_timestamp, dataset_version, record_count, from_cache FROM source_registry WHERE source_type='PUBLIC'"):
        f.add(f"DB:source:{s['source_name']}", s)
    f.retrieval_query = "executive cyber risk posture priorities vulnerability remediation targets"
    f.deterministic = {"enterprise_risk_score": k["enterprise_risk_score"]}
    return f
