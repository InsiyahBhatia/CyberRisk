"""DB-backed risk calculations. All numbers come from app.risk.engine; no LLM involved."""
from __future__ import annotations

import re
from datetime import date, datetime, timezone

from sqlalchemy import Connection

from app.db.session import execute, one, rows, scalar
from app.risk import engine as eng

OPEN_RISK_EXCLUDED = ("CLOSED",)
VENDOR_STATUS_FACTOR = {"COMPLETED": 0.60, "IN_PROGRESS": 0.80, "OVERDUE": 1.0, "NOT_STARTED": 1.0}
VENDOR_FINDING_PENALTY = {"CRITICAL": 0.6, "HIGH": 0.4, "MEDIUM": 0.2, "LOW": 0.0}


def seed_config(conn: Connection) -> None:
    for k, v in eng.DEFAULT_CONFIG.items():
        execute(conn, "INSERT OR IGNORE INTO risk_config (key, value, description) VALUES (:k,:v,:d)", k=k, v=v, d=eng.CONFIG_DESCRIPTIONS.get(k))


def load_config(conn: Connection) -> dict[str, float]:
    return {**eng.DEFAULT_CONFIG, **{r["key"]: r["value"] for r in rows(conn, "SELECT key, value FROM risk_config")}}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def recalc_vulnerabilities(conn: Connection) -> int:
    cfg = load_config(conn)
    items = rows(conn, """SELECT v.id, v.cvss_score, v.exploitability, v.known_exploited, a.criticality, a.internet_exposed
                          FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id""")
    for v in items:
        score = eng.vulnerability_risk(v["cvss_score"], v["criticality"], v["exploitability"], bool(v["internet_exposed"]), bool(v["known_exploited"]), cfg)
        execute(conn, "UPDATE vulnerabilities SET risk_score=:s WHERE id=:id", s=round(score, 4), id=v["id"])
    return len(items)


def risk_effectiveness(conn: Connection, risk_id: int) -> float:
    """Mean effectiveness of the applicable controls linked to the risk (0 when none)."""
    v = scalar(conn, """SELECT AVG(c.effectiveness) FROM risk_controls rc JOIN controls c ON c.id = rc.control_id
                        WHERE rc.risk_id=:r AND c.implementation_status != 'NOT_APPLICABLE'""", r=risk_id)
    return float(v) if v is not None else 0.0


def recalc_risk(conn: Connection, risk: dict, reason: str, record_history: bool = True) -> dict:
    inh = eng.inherent_score(risk["likelihood"], risk["impact"])
    eff = risk_effectiveness(conn, risk["id"])
    res = eng.residual_score(inh, eff)
    level = eng.risk_level(res)
    needs_approval = (risk["treatment"] == "ACCEPT" or risk["status"] == "ACCEPTED") and level in ("HIGH", "CRITICAL")
    approval = risk.get("approval_status") or "NOT_REQUIRED"
    if needs_approval and approval in ("NOT_REQUIRED",):
        approval = "PENDING"
    if not needs_approval and approval == "PENDING":
        approval = "NOT_REQUIRED"
    changed = abs((risk["residual_score"] or 0) - res) > 1e-9 or risk["risk_level"] != level
    execute(conn, """UPDATE risks SET inherent_score=:i, control_effectiveness=:e, residual_score=:r, risk_level=:l,
                     approval_status=:a, updated_at=CURRENT_TIMESTAMP WHERE id=:id""", i=inh, e=eff, r=res, l=level, a=approval, id=risk["id"])
    if record_history and (changed or not scalar(conn, "SELECT 1 FROM risk_history WHERE risk_id=:r LIMIT 1", r=risk["id"])):
        execute(conn, "INSERT INTO risk_history (risk_id, score, risk_level, recorded_at, reason) VALUES (:r,:s,:l,:t,:why)",
                r=risk["id"], s=res, l=level, t=_now(), why=reason)
    return {"inherent": inh, "effectiveness": eff, "residual": res, "level": level, "approval_status": approval}


def recalc_risks(conn: Connection, reason: str = "Recalculated") -> int:
    items = rows(conn, "SELECT * FROM risks")
    for r in items:
        recalc_risk(conn, r, reason)
    return len(items)


def recalc_vendors(conn: Connection) -> int:
    items = rows(conn, "SELECT id, inherent_risk, assessment_status FROM vendors")
    for v in items:
        pen = sum(VENDOR_FINDING_PENALTY.get((f["severity"] or "").upper(), 0) for f in
                  rows(conn, "SELECT severity FROM vendor_findings WHERE vendor_id=:v AND status='OPEN'", v=v["id"]))
        resid = min(10.0, v["inherent_risk"] * VENDOR_STATUS_FACTOR.get(v["assessment_status"], 1.0) + pen)
        execute(conn, "UPDATE vendors SET residual_risk=:r WHERE id=:id", r=round(resid, 2), id=v["id"])
    return len(items)


def recalculate_all(conn: Connection, today: date | None = None, reason: str = "Recalculated after data load") -> dict:
    seed_config(conn)
    return {"vulnerabilities": recalc_vulnerabilities(conn), "risks": recalc_risks(conn, reason), "vendors": recalc_vendors(conn)}


def enterprise_score(conn: Connection) -> float:
    cfg = load_config(conn)
    items = rows(conn, "SELECT residual_score, status FROM risks")
    return eng.enterprise_score([eng.RiskInput(r["residual_score"], r["status"] not in OPEN_RISK_EXCLUDED) for r in items], cfg)


def simulate_risk(conn: Connection, risk_id: int, action_ids: list[int]) -> dict:
    risk = one(conn, "SELECT * FROM risks WHERE id=:id", id=risk_id)
    if not risk:
        raise LookupError("risk not found")
    acts = rows(conn, "SELECT id, action, effectiveness_gain, status FROM remediation_actions WHERE risk_id=:r", r=risk_id)
    by_id = {a["id"]: a for a in acts}
    bad = [i for i in action_ids if i not in by_id]
    if bad:
        raise ValueError(f"actions {bad} do not belong to this risk")
    selected = [by_id[i] for i in dict.fromkeys(action_ids) if by_id[i]["status"] != "COMPLETED"]  # completed actions are already in effectiveness
    sim = eng.simulate(risk["inherent_score"], risk["control_effectiveness"], [a["effectiveness_gain"] for a in selected])
    cfg = load_config(conn)
    all_risks = rows(conn, "SELECT id, residual_score, status FROM risks")
    cur_ent = eng.enterprise_score([eng.RiskInput(r["residual_score"], r["status"] not in OPEN_RISK_EXCLUDED) for r in all_risks], cfg)
    proj_ent = eng.enterprise_score([eng.RiskInput(sim["projected_residual"] if r["id"] == risk_id else r["residual_score"], r["status"] not in OPEN_RISK_EXCLUDED) for r in all_risks], cfg)
    return {**sim, "risk_id": risk_id, "applied_actions": [{"id": a["id"], "action": a["action"], "effectiveness_gain": a["effectiveness_gain"]} for a in selected],
            "enterprise_current": cur_ent, "enterprise_projected": proj_ent, "enterprise_delta": proj_ent - cur_ent,
            "disclaimer": "Projection based on assumed action effectiveness; not a guarantee."}


def next_risk_code(conn: Connection) -> str:
    """Next free R-### code, based on the highest existing numeric suffix (ids and imported codes can diverge)."""
    top = 0
    for r in rows(conn, "SELECT risk_code FROM risks"):
        m = re.fullmatch(r"R-(\d+)", r["risk_code"] or "")
        if m:
            top = max(top, int(m.group(1)))
    return f"R-{top + 1:03d}"
