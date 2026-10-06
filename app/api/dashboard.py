from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from sqlalchemy import Connection

from app.db.session import get_conn, one, rows, scalar
from app.grc.service import compliance_summary, overall_control_coverage
from app.risk import service as risk_service

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

OPEN_VULN = "('OPEN','IN_PROGRESS')"


def kpis(conn: Connection) -> dict:
    latest_eval = one(conn, "SELECT * FROM ai_eval_runs WHERE status='COMPLETED' ORDER BY id DESC LIMIT 1")
    meta = json.loads(latest_eval["category_scores"]) if latest_eval and latest_eval["category_scores"] else {}
    cats = meta.get("categories", {})
    mfa = one(conn, "SELECT SUM(mfa_enabled) AS m, COUNT(*) AS n FROM employees WHERE account_status='Active'")
    mttr = scalar(conn, "SELECT AVG(julianday(resolved_at) - julianday(discovered_at)) FROM vulnerabilities WHERE status='RESOLVED' AND resolved_at IS NOT NULL")
    return {
        "enterprise_risk_score": round(risk_service.enterprise_score(conn), 1),
        "critical_risks": scalar(conn, "SELECT COUNT(*) FROM risks WHERE risk_level='CRITICAL' AND status!='CLOSED'"),
        "high_risks": scalar(conn, "SELECT COUNT(*) FROM risks WHERE risk_level='HIGH' AND status!='CLOSED'"),
        "critical_findings": scalar(conn, f"SELECT COUNT(*) FROM vulnerabilities WHERE severity='CRITICAL' AND status IN {OPEN_VULN}"),  # noqa: S608
        "open_vulnerabilities": scalar(conn, f"SELECT COUNT(*) FROM vulnerabilities WHERE status IN {OPEN_VULN}"),  # noqa: S608
        "known_exploited_open": scalar(conn, f"SELECT COUNT(*) FROM vulnerabilities WHERE known_exploited=1 AND status IN {OPEN_VULN}"),  # noqa: S608
        "overdue_vulnerabilities": scalar(conn, f"SELECT COUNT(*) FROM vulnerabilities WHERE status IN {OPEN_VULN} AND due_date < date('now')"),  # noqa: S608
        "control_coverage": overall_control_coverage(conn),
        "mfa_adoption": round(100 * (mfa["m"] or 0) / mfa["n"], 1) if mfa and mfa["n"] else None,
        "high_risk_vendors": scalar(conn, "SELECT COUNT(*) FROM vendors WHERE residual_risk >= 7"),
        "open_incidents": scalar(conn, "SELECT COUNT(*) FROM incidents WHERE status != 'CLOSED'"),
        "mean_time_to_remediate_days": round(mttr, 1) if mttr is not None else None,
        "ai_grounding_score": cats.get("rag_grounding"),
        "ai_security_pass_rate": meta.get("security_pass_rate"),
        "ai_eval_mode": latest_eval["mode"] if latest_eval else None,
        "ai_eval_measured": latest_eval is not None,
    }


@router.get("/summary")
def summary(conn: Connection = Depends(get_conn)):
    return {
        "kpis": kpis(conn),
        "risk_levels": rows(conn, "SELECT risk_level AS label, COUNT(*) AS count FROM risks WHERE status!='CLOSED' GROUP BY risk_level"),
        "vulns_by_severity": rows(conn, f"SELECT severity AS label, COUNT(*) AS count FROM vulnerabilities WHERE status IN {OPEN_VULN} GROUP BY severity"),  # noqa: S608
        "top_risks": rows(conn, """SELECT r.id, r.risk_code, r.title, r.residual_score, r.risk_level, r.status, r.owner, a.business_unit
                                   FROM risks r LEFT JOIN assets a ON a.id=r.asset_id WHERE r.status!='CLOSED' ORDER BY r.residual_score DESC LIMIT 6"""),
        "top_vulnerabilities": rows(conn, f"""SELECT v.id, v.cve_id, v.severity, v.cvss_score, v.known_exploited, v.risk_score, a.asset_tag, a.business_unit
                                             FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id WHERE v.status IN {OPEN_VULN}
                                             ORDER BY v.risk_score DESC LIMIT 6"""),  # noqa: S608
        "remediation": rows(conn, "SELECT status AS label, COUNT(*) AS count FROM remediation_actions GROUP BY status"),
        "compliance": [{"name": c["name"], "control_coverage": c["control_coverage"], "evidence_coverage": c["evidence_coverage"]} for c in compliance_summary(conn)],
    }


@router.get("/risk-trend")
def risk_trend(conn: Connection = Depends(get_conn)):
    """Monthly mean residual risk across the register (normalised 0-100)."""
    pts = rows(conn, """SELECT substr(recorded_at,1,7) AS month, ROUND(AVG(score)/25.0*100, 1) AS score, COUNT(DISTINCT risk_id) AS risks
                        FROM risk_history GROUP BY substr(recorded_at,1,7) ORDER BY month""")
    return {"points": pts, "note": "Earlier points are a synthetic historical baseline; the latest point is calculated from live data."}


@router.get("/business-units")
def business_units(conn: Connection = Depends(get_conn)):
    return {"items": rows(conn, f"""SELECT a.business_unit,
               COUNT(DISTINCT a.id) AS assets,
               (SELECT ROUND(AVG(r.residual_score),2) FROM risks r JOIN assets a2 ON a2.id=r.asset_id WHERE a2.business_unit=a.business_unit AND r.status!='CLOSED') AS avg_residual_risk,
               (SELECT COUNT(*) FROM risks r JOIN assets a2 ON a2.id=r.asset_id WHERE a2.business_unit=a.business_unit AND r.status!='CLOSED' AND r.risk_level IN ('HIGH','CRITICAL')) AS high_risks,
               (SELECT COUNT(*) FROM vulnerabilities v JOIN assets a2 ON a2.id=v.asset_id WHERE a2.business_unit=a.business_unit AND v.status IN {OPEN_VULN}) AS open_vulns,
               (SELECT COUNT(*) FROM vulnerabilities v JOIN assets a2 ON a2.id=v.asset_id WHERE a2.business_unit=a.business_unit AND v.status IN {OPEN_VULN} AND v.severity='CRITICAL') AS critical_vulns
        FROM assets a WHERE a.business_unit IS NOT NULL GROUP BY a.business_unit ORDER BY open_vulns DESC""")}  # noqa: S608


@router.get("/heatmap")
def heatmap(conn: Connection = Depends(get_conn)):
    """Likelihood x impact grid of open risks."""
    return {"cells": rows(conn, "SELECT likelihood, impact, COUNT(*) AS count FROM risks WHERE status!='CLOSED' GROUP BY likelihood, impact")}
