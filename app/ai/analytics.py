"""Natural-language analytics through a SAFE intent layer: question -> fixed intent -> parameterized SQL -> structured result.
The model never writes or executes SQL; it only explains the returned rows.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import Connection

from app.ai.context import Facts
from app.db.session import rows
from app.grc.service import compliance_summary


@dataclass(frozen=True)
class Intent:
    key: str
    title: str
    keywords: tuple[str, ...]
    sql: str | None = None


INTENTS: list[Intent] = [
    Intent("vulns_by_severity", "Open vulnerabilities by severity", ("vulnerab", "severity", "cve", "how many"),
           "SELECT severity, COUNT(*) AS open_count FROM vulnerabilities WHERE status IN ('OPEN','IN_PROGRESS') GROUP BY severity ORDER BY MIN(cvss_score) DESC"),
    Intent("overdue_vulnerabilities", "Overdue vulnerabilities by business unit", ("overdue", "past due", "sla", "late"),
           """SELECT a.business_unit, COUNT(*) AS overdue_count, SUM(v.severity='CRITICAL') AS critical_overdue FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id
              WHERE v.status IN ('OPEN','IN_PROGRESS') AND v.due_date < date('now') GROUP BY a.business_unit ORDER BY overdue_count DESC"""),
    Intent("kev_exposure", "Open known-exploited (CISA KEV) vulnerabilities by business unit", ("kev", "known exploited", "exploited", "actively exploited"),
           """SELECT a.business_unit, COUNT(*) AS open_kev, SUM(a.internet_exposed) AS on_internet_exposed_assets FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id
              WHERE v.known_exploited=1 AND v.status IN ('OPEN','IN_PROGRESS') GROUP BY a.business_unit ORDER BY open_kev DESC"""),
    Intent("risk_by_business_unit", "Open risks and average residual score by business unit", ("business unit", "department", "which unit", "by unit", "highest risk unit"),
           """SELECT a.business_unit, COUNT(*) AS open_risks, ROUND(AVG(r.residual_score),2) AS avg_residual_score, SUM(r.risk_level IN ('HIGH','CRITICAL')) AS high_or_critical
              FROM risks r JOIN assets a ON a.id=r.asset_id WHERE r.status!='CLOSED' GROUP BY a.business_unit ORDER BY avg_residual_score DESC"""),
    Intent("top_risks", "Top open risks by residual score", ("top risk", "highest risk", "biggest risk", "priority risk", "risk register", "risks"),
           "SELECT risk_code, title, residual_score, risk_level, status, owner FROM risks WHERE status!='CLOSED' ORDER BY residual_score DESC LIMIT 10"),
    Intent("vendor_risk", "Vendor residual risk distribution", ("vendor", "supplier", "third party", "third-party"),
           """SELECT CASE WHEN residual_risk>=7 THEN 'High (7-10)' WHEN residual_risk>=4 THEN 'Medium (4-7)' ELSE 'Low (0-4)' END AS band, COUNT(*) AS vendors,
                     SUM(assessment_status='OVERDUE') AS assessments_overdue FROM vendors GROUP BY band ORDER BY MIN(residual_risk) DESC"""),
    Intent("incidents", "Open incidents by severity", ("incident", "breach", "attack"),
           "SELECT severity, COUNT(*) AS open_incidents FROM incidents WHERE status!='CLOSED' GROUP BY severity ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END"),
    Intent("mfa", "MFA adoption by department (active accounts)", ("mfa", "multi-factor", "multifactor", "authentication"),
           """SELECT department, COUNT(*) AS active_accounts, ROUND(100.0*SUM(mfa_enabled)/COUNT(*),1) AS mfa_percent FROM employees WHERE account_status='Active'
              GROUP BY department ORDER BY mfa_percent ASC"""),
    Intent("evidence", "Control evidence status", ("evidence", "expired", "audit readiness"),
           "SELECT status, COUNT(*) AS evidence_records FROM evidence GROUP BY status ORDER BY evidence_records DESC"),
    Intent("compliance", "Control and evidence coverage by framework", ("compliance", "coverage", "framework", "nist", "iso", "soc", "control"), None),
]


def route(question: str) -> Intent | None:
    """Deterministic keyword router. Returns None when nothing matches (the caller abstains)."""
    q = question.lower()
    best, best_score = None, 0
    for it in INTENTS:
        score = sum(1 for k in it.keywords if k in q) + (0.5 * len(it.keywords[0].split()) if it.keywords[0] in q else 0)
        if score > best_score:
            best, best_score = it, score
    return best


def run_intent(conn: Connection, intent: Intent) -> list[dict]:
    if intent.key == "compliance":
        return [{"framework": c["name"], "control_coverage_pct": c["control_coverage"], "evidence_coverage_pct": c["evidence_coverage"], "applicable_controls": c["applicable_controls"]}
                for c in compliance_summary(conn)]
    return rows(conn, intent.sql)  # static, parameter-free SQL owned by the application


def analytics_facts(conn: Connection, question: str) -> tuple[Facts | None, Intent | None]:
    intent = route(question)
    if intent is None:
        return None, None
    data = run_intent(conn, intent)
    f = Facts()
    f.add(f"DB:analytics:{intent.key}", {"title": intent.title, "row_count": len(data), "rows": data[:25]})
    f.retrieval_query = ""
    return f, intent
