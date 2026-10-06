"""Live simulation control + feed. Simulated events are always labelled; only organization/demo workspaces may simulate."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from app.analysis import engine as analysis
from app.api.common import audit, not_found
from app.db.session import current_workspace, execute, get_conn, one, rows, scalar
from app.simulation import connectors, runner, sources
from app.tenancy import workspaces as tenancy

router = APIRouter(prefix="/api/sim", tags=["simulation"])
Scenario = Literal["brute_force_takeover", "phishing_to_ransomware", "kev_exploit_edge", "cloud_misconfig", "insider_exfil"]


class StartRequest(BaseModel):
    rate_per_min: float = Field(30, ge=1, le=600)
    speed: float = Field(2.0, ge=0.5, le=10)
    duration_min: int = Field(30, ge=1, le=120)
    scenarios: list[Scenario] = Field(default_factory=lambda: list(sources.SCENARIOS))
    scenario_every_s: float = Field(120, ge=15, le=1800)
    malformed_pct: float = Field(0.03, ge=0, le=0.5)
    seed: int | None = None


class InjectRequest(BaseModel):
    scenario: Scenario
    target: str | None = Field(None, max_length=60)


class TriageRequest(BaseModel):
    status: Literal["INVESTIGATING", "CONTAINED", "CLOSED"]
    analyst: str = Field("analyst", min_length=2, max_length=80)
    note: str | None = Field(None, max_length=500)


def _require_simulatable() -> str:
    slug = current_workspace()
    w = tenancy.get(slug)
    if not w or w["kind"] == "sandbox":
        raise HTTPException(422, "Simulation runs in organization or demo workspaces (the sandbox has no organisation to simulate).")
    return slug


@router.get("/scenarios")
def list_scenarios():
    return {"items": [{"name": k, "description": v} for k, v in sources.SCENARIOS.items()], "connectors": connectors.DISPLAY}


@router.get("/status")
def status(conn: Connection = Depends(get_conn)):
    slug = current_workspace()
    r = runner.get(slug)
    live = runner.running(slug)
    base = {"running": live, "workspace": slug, "limits": runner.LIMITS}
    if r:
        base |= {"simulator": r.sim.status(), "finished": r.finished, "stop_reason": r.reason if r.finished else ""}
    base["stored"] = {"signals": scalar(conn, "SELECT COUNT(*) FROM signals"), "incidents": scalar(conn, "SELECT COUNT(*) FROM incidents WHERE source IN ('correlation','itsm')"),
                      "scenarios": scalar(conn, "SELECT COUNT(*) FROM sim_scenarios")}
    return base


@router.post("/start", status_code=201)
def start(body: StartRequest):
    slug = _require_simulatable()
    try:
        r = runner.start(slug, rate_per_min=body.rate_per_min, scenarios=list(body.scenarios), speed=body.speed, duration_min=body.duration_min, seed=body.seed,
                         scenario_every_s=body.scenario_every_s, malformed_pct=body.malformed_pct)
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return {"started": True, "workspace": slug, "config": r.sim.status()}


@router.post("/stop")
def stop():
    slug = _require_simulatable()
    return {"stopped": runner.stop(slug), "workspace": slug}


@router.post("/inject", status_code=201)
def inject(body: InjectRequest):
    slug = _require_simulatable()
    r = runner.get(slug)
    if not r or not r.is_alive() or r.sim.gen is None:
        raise HTTPException(409, "Start the simulation first, then inject a scenario")
    try:
        return r.sim.inject(body.scenario, body.target)
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get("/feed")
def feed(after_id: int = 0, limit: int = Query(60, ge=1, le=200), min_severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "INFO", source: str | None = Query(None, max_length=20),
         conn: Connection = Depends(get_conn)):
    """Poll with `after_id` to receive only new signals. Newest first."""
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    allowed = order[order.index(min_severity):]
    q = f"""SELECT s.id, s.source, s.kind, s.ts, s.severity, s.host, s.asset_id, s.user, s.src_ip, s.title, s.technique_ids, s.cve_id, s.status, s.incident_id, s.scenario_id,
                   i.incident_code FROM signals s LEFT JOIN incidents i ON i.id=s.incident_id
            WHERE s.id>:a AND s.severity IN ({','.join(repr(x) for x in allowed)}) {"AND s.source=:src" if source else ""} ORDER BY s.id DESC LIMIT :l"""  # noqa: S608 (static severities)
    params = {"a": after_id, "l": limit, **({"src": source} if source else {})}
    items = rows(conn, q, **params)
    for it in items:
        it["unmanaged"] = it["asset_id"] is None and bool(it["host"]) and it["source"] in ("SIEM", "EDR", "Scanner")
    return {"items": items, "latest_id": scalar(conn, "SELECT COALESCE(MAX(id),0) FROM signals")}


@router.get("/signals/{sid}")
def signal(sid: int, conn: Connection = Depends(get_conn)):
    s = one(conn, "SELECT * FROM signals WHERE id=:i", i=sid)
    if not s:
        raise not_found("Signal")
    return {**s, "simulated_notice": "Synthetic event generated by the CyberRisk simulator."}


@router.get("/incidents")
def incidents(status: str | None = Query(None, max_length=20), conn: Connection = Depends(get_conn)):
    cond = "WHERE i.source IN ('correlation','itsm')" + (" AND i.status=:s" if status else "")
    items = rows(conn, f"""SELECT i.id, i.incident_code, i.title, i.severity, i.status, i.category, i.detected_at, i.technique_ids, i.description, i.signal_count, i.source, i.acknowledged_at, i.updated_at,
                                 a.asset_tag, (SELECT COUNT(DISTINCT source) FROM signals s WHERE s.incident_id=i.id) AS source_count
                          FROM incidents i LEFT JOIN assets a ON a.id=i.affected_asset_id {cond}
                          ORDER BY CASE i.status WHEN 'CLOSED' THEN 1 ELSE 0 END, i.id DESC LIMIT 60""", **({"s": status.upper()} if status else {}))  # noqa: S608 (static)
    return {"items": items}


@router.get("/incidents/{iid}")
def incident(iid: int, conn: Connection = Depends(get_conn)):
    inc = one(conn, "SELECT * FROM incidents WHERE id=:i", i=iid)
    if not inc:
        raise not_found("Incident")
    sig = rows(conn, "SELECT id, source, ts, severity, host, user, src_ip, title, technique_ids, raw FROM signals WHERE incident_id=:i ORDER BY ts, id", i=iid)
    techs = []
    for t in dict.fromkeys(t for s in sig for t in (s["technique_ids"] or "").split(",") if t):
        r = one(conn, "SELECT technique_id, name, tactics FROM attack_techniques WHERE technique_id=:t", t=t)
        techs.append(r or {"technique_id": t, "name": None, "tactics": ""})
    return {**inc, "signals": sig, "techniques": techs}


@router.post("/incidents/{iid}/triage")
def triage(iid: int, body: TriageRequest, conn: Connection = Depends(get_conn)):
    """Analyst workflow: acknowledge/investigate, contain, close. Recorded in the audit log."""
    inc = one(conn, "SELECT id, status, acknowledged_at FROM incidents WHERE id=:i", i=iid)
    if not inc:
        raise not_found("Incident")
    if inc["status"] == "CLOSED":
        raise HTTPException(409, "Incident is already closed")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    execute(conn, "UPDATE incidents SET status=:s, acknowledged_at=COALESCE(acknowledged_at,:n), updated_at=:n, resolved_at=CASE WHEN :s='CLOSED' THEN :d ELSE resolved_at END WHERE id=:i",
            s=body.status, n=now, d=now[:10], i=iid)
    audit(conn, f"incident_{body.status.lower()}", "incident", iid, body.note or "", actor=body.analyst)
    return {"id": iid, "status": body.status, "acknowledged_at": inc["acknowledged_at"] or now}


@router.post("/incidents/{iid}/analyze", status_code=201)
def analyze_incident(iid: int, conn: Connection = Depends(get_conn)):
    """Run the log-analysis engine on the incident's raw evidence (same detections as the Analyze page)."""
    inc = one(conn, "SELECT incident_code, title FROM incidents WHERE id=:i", i=iid)
    if not inc:
        raise not_found("Incident")
    raw = rows(conn, "SELECT raw FROM signals WHERE incident_id=:i ORDER BY ts, id", i=iid)
    if not raw:
        raise HTTPException(422, "This incident has no stored raw signals to analyse")
    res = analysis.analyze_logs(conn, ("\n".join(r["raw"] for r in raw)).encode(), f"{inc['incident_code']}.log", f"{inc['incident_code']}: {inc['title']}"[:120])
    audit(conn, "analysis_logs", "analysis", res["id"], f"from incident {inc['incident_code']}")
    return {"analysis_id": res["id"], "severity": res["severity"], "findings": len(res["findings"])}


@router.get("/metrics")
def metrics(points: int = Query(90, ge=5, le=500), conn: Connection = Depends(get_conn)):
    series = rows(conn, "SELECT ts, events, rejected, open_incidents, open_vulns, kev_open, by_source FROM sim_metrics ORDER BY id DESC LIMIT :n", n=points)[::-1]
    for s in series:
        s["by_source"] = json.loads(s["by_source"] or "{}")
    sc = rows(conn, "SELECT id, name, target, started_at, steps, incident_id, detected_at FROM sim_scenarios ORDER BY id DESC LIMIT 20")
    total, detected = len(sc), sum(1 for s in sc if s["incident_id"])
    mtta = scalar(conn, """SELECT AVG((julianday(acknowledged_at) - julianday(detected_at || 'T00:00:00Z')) * 1440) FROM incidents WHERE source='correlation' AND acknowledged_at IS NOT NULL""")
    mttd = scalar(conn, """SELECT AVG((julianday(detected_at) - julianday(started_at)) * 86400) FROM sim_scenarios WHERE detected_at IS NOT NULL""")
    return {"series": series, "scenarios": sc, "detection": {"scenarios": total, "detected": detected, "rate": round(100 * detected / total, 1) if total else None,
                                                             "mean_time_to_detect_s": round(mttd, 1) if mttd is not None else None},
            "incidents": {"open": scalar(conn, "SELECT COUNT(*) FROM incidents WHERE source IN ('correlation','itsm') AND status!='CLOSED'"),
                          "closed": scalar(conn, "SELECT COUNT(*) FROM incidents WHERE source IN ('correlation','itsm') AND status='CLOSED'")},
            "unmanaged_hosts": rows(conn, "SELECT host, COUNT(*) AS signals FROM signals WHERE asset_id IS NULL AND host!='' AND source IN ('SIEM','EDR') GROUP BY host ORDER BY signals DESC LIMIT 8")}


@router.delete("/data")
def reset(conn: Connection = Depends(get_conn)):
    """Remove simulated signals/incidents/metrics from this workspace (assets and vulnerabilities loaded by the feed are kept)."""
    slug = _require_simulatable()
    if runner.running(slug):
        raise HTTPException(409, "Stop the simulation first")
    n = scalar(conn, "SELECT COUNT(*) FROM signals")
    execute(conn, "DELETE FROM signals")                     # children first: signals and scenarios reference incidents
    execute(conn, "DELETE FROM sim_scenarios")
    execute(conn, "DELETE FROM incidents WHERE source IN ('correlation','itsm')")
    execute(conn, "DELETE FROM sim_metrics")
    audit(conn, "simulation_reset", "workspace", slug, f"{n} signals removed")
    return {"removed_signals": n}
