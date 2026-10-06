"""Compliance calculations. Coverage figures are internal readiness metrics, not certification."""
from __future__ import annotations

from sqlalchemy import Connection

from app.db.session import rows

NOT_APPLICABLE = "NOT_APPLICABLE"


def control_evidence_status(statuses: list[str]) -> str:
    """Roll up a control's evidence records: PRESENT beats EXPIRED beats NEEDS_REVIEW; no record = MISSING."""
    s = set(statuses)
    for candidate in ("PRESENT", "EXPIRED", "NEEDS_REVIEW"):
        if candidate in s:
            return candidate
    return "MISSING"


def controls_with_evidence(conn: Connection, framework_id: int | None = None) -> list[dict]:
    where, params = ("WHERE c.framework_id = :fw", {"fw": framework_id}) if framework_id else ("", {})
    ctl = rows(conn, f"""SELECT c.id, c.control_code, c.title, c.category, c.implementation_status, c.effectiveness, c.owner,
                               f.name AS framework, f.version AS framework_version, f.id AS framework_id
                        FROM controls c JOIN frameworks f ON f.id = c.framework_id {where} ORDER BY f.name, c.control_code""", **params)  # noqa: S608
    ev: dict[int, list[str]] = {}
    for e in rows(conn, "SELECT control_id, status FROM evidence"):
        ev.setdefault(e["control_id"], []).append(e["status"])
    for c in ctl:
        c["evidence_status"] = control_evidence_status(ev.get(c["id"], []))
        c["evidence_count"] = len(ev.get(c["id"], []))
    return ctl


def coverage(controls: list[dict]) -> dict:
    applicable = [c for c in controls if c["implementation_status"] != NOT_APPLICABLE]
    n = len(applicable)
    implemented = sum(1 for c in applicable if c["implementation_status"] == "IMPLEMENTED")
    evidenced = sum(1 for c in applicable if c["evidence_status"] == "PRESENT")
    return {
        "applicable_controls": n, "implemented_controls": implemented, "controls_with_valid_evidence": evidenced,
        "control_coverage": round(100 * implemented / n, 1) if n else 0.0,
        "evidence_coverage": round(100 * evidenced / n, 1) if n else 0.0,
    }


def compliance_summary(conn: Connection) -> list[dict]:
    out = []
    for fw in rows(conn, "SELECT id, name, version, description FROM frameworks WHERE name != 'MITRE ATT&CK' ORDER BY name"):
        ctl = controls_with_evidence(conn, fw["id"])
        by_ev: dict[str, int] = {}
        for c in ctl:
            if c["implementation_status"] != NOT_APPLICABLE:
                by_ev[c["evidence_status"]] = by_ev.get(c["evidence_status"], 0) + 1
        out.append({**fw, **coverage(ctl), "evidence_breakdown": by_ev,
                    "note": "Internal readiness metric from curated synthetic control data; not a certification or audit opinion."})
    return out


def overall_control_coverage(conn: Connection) -> float:
    ctl = [c for c in controls_with_evidence(conn) if c["framework"] != "MITRE ATT&CK"]
    return coverage(ctl)["control_coverage"]
