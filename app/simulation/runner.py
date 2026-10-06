"""Live simulation: generate vendor-shaped events, ingest them through connectors and the real ETL transforms, correlate into incidents.

One Simulator per workspace. `tick()` does one synchronous batch (used by the background thread and by tests).
Everything it creates is labelled simulated (source names start with 'Sim ·', signals.simulated=1).
"""
from __future__ import annotations

import json
import logging
import random
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import Connection

from app.db import session as db
from app.db.session import connect, execute, one, rows, scalar
from app.etl import provenance as prov
from app.etl.pipeline import DATASET_BY_NAME, Ctx, Reject as ETLReject, run_dataset
from app.etl.quality import quality_score
from app.risk import service as risk_service
from app.simulation import connectors, estate as est, sources

log = logging.getLogger("cyberrisk.simulation")
SEV_W = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
TITLE_BY_TECH = [("T1486", "Ransomware activity", "Ransomware"), ("T1490", "Backup destruction (ransomware precursor)", "Ransomware"), ("T1003", "Credential dumping", "Unauthorized Access"),
                 ("T1567", "Data exfiltration to cloud storage", "Data Exposure"), ("T1530", "Cloud data exposure", "Data Exposure"), ("T1078", "Possible account compromise", "Unauthorized Access"),
                 ("T1110", "Brute-force attack", "Unauthorized Access"), ("T1190", "Exploitation of a public-facing application", "Malware"), ("T1021", "Lateral movement", "Unauthorized Access"),
                 ("T1059", "Suspicious command execution", "Malware"), ("T1566", "Phishing", "Phishing")]
LIMITS = {"rate_per_min": (1, 600), "speed": (0.5, 10.0), "duration_min": (1, 120)}
KEEP_SIGNALS, KEEP_METRICS = 5000, 2000


class Simulator:
    def __init__(self, slug: str, rate_per_min: float = 30, scenarios: list[str] | None = None, speed: float = 2.0, duration_min: int = 30, seed: int | None = None,
                 scenario_every_s: float = 120, malformed_pct: float = 0.03):
        self.slug = slug
        self.rate = float(rate_per_min)
        self.enabled = list(scenarios if scenarios is not None else sources.SCENARIOS)
        bad = [s for s in self.enabled if s not in sources.SCENARIOS]
        if bad:
            raise ValueError(f"unknown scenarios {bad}")
        self.speed, self.duration_min = float(speed), int(duration_min)
        self.scenario_every_s, self.malformed_pct = scenario_every_s, malformed_pct
        self.rnd = random.Random(seed if seed is not None else int(time.time()))
        self.started_at: datetime | None = None
        self.last_tick: datetime | None = None
        self.last_scenario: datetime | None = None
        self.pending: list[tuple[datetime, object, int, str]] = []  # (due, builder, scenario_id, name)
        self.estate: est.Estate | None = None
        self.gen: sources.Generator | None = None
        self.stats: dict[str, dict] = {s: {"events": 0, "rejected": 0, "batches": 0, "ms": 0.0, "last_ts": None} for s in sources.SOURCES}
        self.totals = Counter()
        self.errors = 0
        self.last_error = ""
        self._by_name: dict[str, est.Host] = {}
        self._registered: set[str] = set()

    # ------------------------------------------------------------------ setup
    def prepare(self) -> None:
        engine = db.engine_for(self.slug)
        with connect(engine) as conn:
            n_assets = scalar(conn, "SELECT COUNT(*) FROM assets")
        if n_assets < 10:
            self._seed_estate(engine)
        with connect(engine) as conn:
            self.estate = est.load_estate(conn, self.rnd)
            cves = rows(conn, "SELECT cve_id, cvss_score, in_kev FROM cve_catalog WHERE cvss_score IS NOT NULL ORDER BY cve_id LIMIT 400")
        self._by_name = self.estate.by_name()
        self.gen = sources.Generator(self.estate, self.rnd, cves)
        self.started_at = self.last_tick = datetime.now(timezone.utc)

    def _seed_estate(self, engine) -> None:
        """An empty workspace has no inventory for events to refer to: sync a small simulated CMDB through the normal assets ETL."""
        import csv

        out = db.workspace_dir(self.slug) / "simulation"
        out.mkdir(parents=True, exist_ok=True)
        rows_ = est.generated_assets(random.Random(7))
        path = out / "cmdb_sync.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows_[0]))
            w.writeheader()
            w.writerows(rows_)
        run_dataset(DATASET_BY_NAME["assets"], path, engine)

    # ------------------------------------------------------------------ scenarios
    def inject(self, name: str, target: str | None = None, now: datetime | None = None) -> dict:
        if self.gen is None:
            raise RuntimeError("simulator not prepared")
        now = now or datetime.now(timezone.utc)
        host = self._by_name.get((target or "").lower()) if target else None
        if target and host is None:
            raise ValueError(f"unknown target asset '{target}'")
        plan = self.gen.scenario(name, host)
        with connect(db.engine_for(self.slug)) as conn:
            sid = execute(conn, "INSERT INTO sim_scenarios (name, target, started_at, steps) VALUES (:n,:t,:s,:k)", n=name, t=plan.target, s=now.strftime("%Y-%m-%dT%H:%M:%SZ"), k=len(plan.steps)).lastrowid
        for off, builder in plan.steps:
            self.pending.append((now + timedelta(seconds=off / self.speed), builder, sid, name))
        self.last_scenario = now
        self.totals["scenarios_injected"] += 1
        return {"scenario_id": sid, "name": name, "target": plan.target, "steps": len(plan.steps), "completes_in_s": round(max(o for o, _ in plan.steps) / self.speed, 1)}

    # ------------------------------------------------------------------ one batch
    def tick(self, now: datetime | None = None) -> dict:
        if self.gen is None:
            self.prepare()
        now = now or datetime.now(timezone.utc)
        dt = min(max((now - self.last_tick).total_seconds(), 0.0), 5.0)
        self.last_tick = now
        emits: list[sources.Emit] = []
        due = [p for p in self.pending if p[0] <= now]
        self.pending = [p for p in self.pending if p[0] > now]
        ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        for _, builder, sid, _name in sorted(due, key=lambda p: p[0]):
            e = builder(ts)
            e.scenario_id = sid
            emits.append(e)
        expected = self.rate * dt / 60.0
        for _ in range(int(expected) + (1 if self.rnd.random() < expected - int(expected) else 0)):
            emits.append(self.gen.noise(ts))
        if self.enabled and (self.last_scenario is None or (now - self.last_scenario).total_seconds() >= self.scenario_every_s * self.rnd.uniform(0.6, 1.4)):
            self.inject(self.rnd.choice(self.enabled), now=now)
            self.last_scenario = now
        by_src: dict[str, list[sources.Emit]] = defaultdict(list)
        for e in emits:
            by_src[e.source].append(self._maybe_corrupt(e))
        summary = {"events": 0, "rejected": 0, "signals": 0, "incidents_opened": 0, "by_source": {}}
        with connect(db.engine_for(self.slug)) as conn:
            for src, batch in by_src.items():
                t0 = time.perf_counter()
                res = self._process_batch(conn, src, batch)
                st = self.stats[src]
                st["events"] += res["read"]; st["rejected"] += res["rejected"]; st["batches"] += 1; st["ms"] += (time.perf_counter() - t0) * 1000; st["last_ts"] = ts
                summary["events"] += res["read"]; summary["rejected"] += res["rejected"]; summary["signals"] += res["signals"]; summary["by_source"][src] = res["read"]
            opened = self._correlate(conn, now)
            summary["incidents_opened"] = opened
            open_inc = scalar(conn, "SELECT COUNT(*) FROM incidents WHERE status!='CLOSED' AND source IN ('correlation','itsm')")
            ov = scalar(conn, "SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('OPEN','IN_PROGRESS')")
            kev = scalar(conn, "SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('OPEN','IN_PROGRESS') AND known_exploited=1")
            if summary["events"] or opened:
                execute(conn, "INSERT INTO sim_metrics (ts, events, rejected, open_incidents, open_vulns, kev_open, by_source) VALUES (:t,:e,:r,:o,:v,:k,:b)",
                        t=ts, e=summary["events"], r=summary["rejected"], o=open_inc, v=ov, k=kev, b=json.dumps(summary["by_source"]))
            self._prune(conn)
        self.totals["events"] += summary["events"]; self.totals["rejected"] += summary["rejected"]; self.totals["incidents_opened"] += opened
        return summary

    def _maybe_corrupt(self, e: sources.Emit) -> sources.Emit:
        """Real feeds contain malformed records. Corrupt a small share so the rejection path is exercised and visible."""
        if e.scenario_id is None and self.rnd.random() < self.malformed_pct:
            raw = dict(e.raw)
            key = {"SIEM": "urgency", "EDR": "created_timestamp", "ITSM": "priority", "Scanner": "cvss_base_score", "IAM": "outcome", "Cloud": "eventTime", "Email": "verdict"}[e.source]
            raw[key] = self.rnd.choice(["", "??", "n/a"]) if key != "outcome" else {}
            return sources.Emit(e.source, raw, e.scenario_id)
        return e

    # ------------------------------------------------------------------ ingestion
    def _resolve(self, conn: Connection, s: connectors.Signal) -> tuple[int | None, str]:
        key = (s.host or "").lower()
        h = self._by_name.get(key)
        if h is None and s.src_ip:
            h = next((x for x in self.estate.hosts if x.ip == s.src_ip), None)
        return (h.asset_id if h else None), (h.tag if h else s.host)

    def _process_batch(self, conn: Connection, src: str, batch: list[sources.Emit]) -> dict:
        name = f"Sim · {connectors.DISPLAY[src]}"
        if name not in self._registered:
            prov.ensure_registry(conn, name=name, publisher="CyberRisk simulator", source_type="SYNTHETIC", official_url="simulation://" + src.lower(), method="Simulated integration feed",
                                 license_notes="Synthetic events imitating the structure of the named product category. No real vendor API is called.")
            self._registered.add(name)
        sid = prov.ensure_data_source(conn, name, "SYNTHETIC")
        run_id = prov.start_run(conn, source_id=sid, name=name, version="live", checksum=None, retrieved_at=prov.utcnow())
        norm = connectors.CONNECTORS[src]
        rejected: list[tuple[int, str, object]] = []
        ok: list[tuple[connectors.Signal, int | None]] = []
        for i, e in enumerate(batch, 1):
            try:
                ok.append((norm(e.raw), e.scenario_id))
            except connectors.Reject as exc:
                rejected.append((i, f"[invalid] {exc}", e.raw))
            except Exception as exc:  # a connector bug must not stop the feed
                rejected.append((i, f"[error] {type(exc).__name__}", e.raw))
        loaded, ctx = 0, Ctx(conn)
        keep: list[tuple[connectors.Signal, int | None]] = []
        vuln_loaded = 0
        for s, scen in ok:
            aid, tag = self._resolve(conn, s)
            s.extra["asset_id"], s.extra["tag"] = aid, tag
            if src == "Scanner" and s.cve:
                try:
                    rec = DATASET_BY_NAME["vulnerability_scan"].transform({"cve_id": s.cve, "asset_tag": tag, "scanner_cvss": str(s.extra["cvss"]), "exploitability": "ACTIVE" if s.severity == "CRITICAL" else "MEDIUM",
                                                                           "status": "OPEN", "discovered_at": s.ts[:10], "due_date": "", "resolved_at": ""}, ctx)
                    DATASET_BY_NAME["vulnerability_scan"].load(conn, [rec])
                    vuln_loaded += 1
                except ETLReject as exc:
                    rejected.append((0, f"[{exc.kind}] {exc.reason}", {"cve": s.cve, "host": s.host}))
                    continue
            elif src == "ITSM" and s.extra.get("is_incident"):
                try:
                    rec = DATASET_BY_NAME["incidents"].transform({"incident_id": s.extra["number"], "title": s.title.split(": ", 1)[-1], "category": "Security", "severity": s.severity,
                                                                  "status": "OPEN", "affected_asset_id": tag if aid else "", "detected_at": s.ts[:10], "resolved_at": "", "description": s.description,
                                                                  "mitre_technique_ids": ""}, ctx)
                    DATASET_BY_NAME["incidents"].load(conn, [rec])
                    execute(conn, "UPDATE incidents SET source='itsm', signal_count=1, updated_at=:t WHERE incident_code=:c", t=s.ts, c=s.extra["number"])
                    s.extra["incident_id"] = scalar(conn, "SELECT id FROM incidents WHERE incident_code=:c", c=s.extra["number"])
                except ETLReject as exc:
                    rejected.append((0, f"[{exc.kind}] {exc.reason}", {"ticket": s.extra["number"]}))
                    continue
            keep.append((s, scen))
        if vuln_loaded:
            risk_service.recalc_vulnerabilities(conn)
        now_s = prov.utcnow()
        for s, scen in keep:
            inc = s.extra.get("incident_id")
            execute(conn, """INSERT INTO signals (source, kind, ts, ingested_at, severity, host, asset_id, user, src_ip, title, description, technique_ids, cve_id, raw, status, incident_id, scenario_id)
                             VALUES (:so,:k,:ts,:ing,:sev,:h,:a,:u,:ip,:ti,:d,:t,:c,:r,:st,:inc,:sc)""",
                    so=s.source, k=s.kind, ts=s.ts, ing=now_s, sev=s.severity, h=s.extra.get("tag") or s.host, a=s.extra.get("asset_id"), u=s.user, ip=s.src_ip, ti=s.title[:200], d=s.description[:600],
                    t=",".join(s.techniques), c=s.cve or None, r=s.raw[:800], st="CORRELATED" if inc else "NEW", inc=inc, sc=scen)
            loaded += 1
        prov.log_rejections(conn, run_id, rejected)
        q = quality_score(len(batch), invalid=len(rejected))
        prov.finish_run(conn, run_id, read=len(batch), valid=len(ok), rejected=len(rejected), loaded=loaded, duplicates=0, quality=q["score"])
        prov.registry_success(conn, name, retrieved_at=now_s, version="live", checksum="n/a", records=self.stats[src]["events"] + len(batch), from_cache=False)
        return {"read": len(batch), "rejected": len(rejected), "signals": loaded}

    # ------------------------------------------------------------------ correlation
    def _correlate(self, conn: Connection, now: datetime) -> int:
        since = (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        sigs = rows(conn, """SELECT id, source, ts, severity, host, asset_id, user, src_ip, title, technique_ids, incident_id, status, scenario_id FROM signals
                             WHERE severity!='INFO' AND kind!='finding' AND ts>=:s AND (status='NEW' OR incident_id IN (SELECT id FROM incidents WHERE status!='CLOSED')) ORDER BY id""", s=since)
        if not any(s["status"] == "NEW" for s in sigs):
            return 0
        parent: dict[str, str] = {}

        def find(x):
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def keys(s):
            k = []
            if s["host"]:
                k.append("h:" + s["host"].lower())
            if SEV_W[s["severity"]] >= 2:
                if s["user"] and s["user"].lower() not in ("system", "anonymous", ""):
                    k.append("u:" + s["user"].lower())
                if s["src_ip"] and not s["src_ip"].startswith("10."):
                    k.append("i:" + s["src_ip"])
            return k
        for s in sigs:
            ks = keys(s) or [f"s:{s['id']}"]
            for k in ks[1:]:
                parent[find(k)] = find(ks[0])
            find(ks[0])
        comps: dict[str, list[dict]] = defaultdict(list)
        for s in sigs:
            comps[find((keys(s) or [f"s:{s['id']}"])[0])].append(s)
        opened = 0
        for members in comps.values():
            new = [m for m in members if m["status"] == "NEW"]
            if not new:
                continue
            existing = Counter(m["incident_id"] for m in members if m["incident_id"])
            score = sum(SEV_W[m["severity"]] for m in members)
            srcs = {m["source"] for m in members}
            max_sev = max((m["severity"] for m in members), key=lambda x: SEV_W[x])
            if existing:
                self._update_incident(conn, existing.most_common(1)[0][0], members, new)
            elif SEV_W[max_sev] >= 2 and (score >= 6 or max_sev == "CRITICAL" or (len(srcs) >= 2 and score >= 4)):  # noise alone (all LOW) never opens an incident
                self._open_incident(conn, members)
                opened += 1
        return opened

    def _summary(self, members: list[dict]) -> tuple[str, str, str, list[str], str]:
        techs = []
        for m in members:
            for t in (m["technique_ids"] or "").split(","):
                if t and t not in techs:
                    techs.append(t)
        title, cat = "Correlated suspicious activity", "Unauthorized Access"
        for prefix, t, c in TITLE_BY_TECH:
            if any(x == prefix or x.startswith(prefix + ".") for x in techs):
                title, cat = t, c
                break
        sev = max((m["severity"] for m in members), key=lambda x: SEV_W[x])
        if len({m["source"] for m in members}) >= 3 and sev not in ("CRITICAL",):
            sev = LEVELS[LEVELS.index(sev) + 1]  # corroborated by several independent sources
        counts = Counter(m["source"] for m in members)
        tops = [m["title"] for m in sorted(members, key=lambda m: -SEV_W[m["severity"]])[:3]]
        desc = f"{len(members)} signals from {len(counts)} source(s) ({', '.join(f'{k}×{v}' for k, v in counts.most_common())}) between {min(m['ts'] for m in members)} and {max(m['ts'] for m in members)}. Top: " + "; ".join(tops)
        return title, cat, sev, techs, desc

    def _open_incident(self, conn: Connection, members: list[dict]) -> int:
        title, cat, sev, techs, desc = self._summary(members)
        hosts = Counter(m["host"] for m in members if m["host"])
        top_host = hosts.most_common(1)[0][0] if hosts else None
        aid = next((m["asset_id"] for m in members if m["host"] == top_host and m["asset_id"]), None)
        last = max((int(c.split("-")[1]) for c in [r["incident_code"] for r in rows(conn, "SELECT incident_code FROM incidents WHERE incident_code LIKE 'SIM-%'")] if c.split("-")[1].isdigit()), default=0)
        code = f"SIM-{last + 1:04d}"
        first_ts = min(m["ts"] for m in members)
        iid = execute(conn, """INSERT INTO incidents (incident_code,title,severity,status,category,detected_at,affected_asset_id,description,technique_ids,source,signal_count,updated_at)
                               VALUES (:c,:t,:s,'OPEN',:cat,:d,:a,:desc,:tech,'correlation',:n,:u)""",
                      c=code, t=f"{title}" + (f" on {top_host}" if top_host else ""), s=sev if sev != "INFO" else "LOW", cat=cat, d=first_ts[:10], a=aid, desc=desc, tech=",".join(techs), n=len(members), u=prov.utcnow()).lastrowid
        ids = [m["id"] for m in members]
        execute(conn, f"UPDATE signals SET status='CORRELATED', incident_id=:i WHERE id IN ({','.join(str(int(x)) for x in ids)})", i=iid)  # noqa: S608 (ints only)
        self._link_scenarios(conn, members, iid)
        return iid

    def _update_incident(self, conn: Connection, iid: int, members: list[dict], new: list[dict]) -> None:
        title, cat, sev, techs, desc = self._summary(members)
        cur = one(conn, "SELECT severity, technique_ids FROM incidents WHERE id=:i", i=iid)
        sev2 = max([cur["severity"], sev if sev != "INFO" else "LOW"], key=lambda x: SEV_W[x])
        merged = list(dict.fromkeys([t for t in (cur["technique_ids"] or "").split(",") if t] + techs))
        hosts = Counter(m["host"] for m in members if m["host"])
        top_host = hosts.most_common(1)[0][0] if hosts else None
        # the title/category follow the most advanced technique seen so far, so an incident that grows into ransomware is labelled as such
        execute(conn, "UPDATE incidents SET title=:ti, category=:cat, severity=:s, technique_ids=:t, signal_count=:n, description=:d, updated_at=:u WHERE id=:i",
                ti=title + (f" on {top_host}" if top_host else ""), cat=cat, s=sev2, t=",".join(merged), n=len(members), d=desc, u=prov.utcnow(), i=iid)
        ids = [m["id"] for m in new]
        execute(conn, f"UPDATE signals SET status='CORRELATED', incident_id=:i WHERE id IN ({','.join(str(int(x)) for x in ids)})", i=iid)  # noqa: S608 (ints only)
        self._link_scenarios(conn, new, iid)

    def _link_scenarios(self, conn: Connection, members: list[dict], iid: int) -> None:
        for sc in {m["scenario_id"] for m in members if m["scenario_id"]}:
            execute(conn, "UPDATE sim_scenarios SET incident_id=:i, detected_at=:t WHERE id=:s AND incident_id IS NULL", i=iid, t=prov.utcnow(), s=sc)

    def _prune(self, conn: Connection) -> None:
        execute(conn, "DELETE FROM signals WHERE id <= (SELECT COALESCE(MAX(id),0) - :k FROM signals)", k=KEEP_SIGNALS)
        execute(conn, "DELETE FROM sim_metrics WHERE id <= (SELECT COALESCE(MAX(id),0) - :k FROM sim_metrics)", k=KEEP_METRICS)

    # ------------------------------------------------------------------ status
    def status(self) -> dict:
        return {"slug": self.slug, "rate_per_min": self.rate, "speed": self.speed, "scenarios": self.enabled, "duration_min": self.duration_min, "started_at": self.started_at.isoformat() if self.started_at else None,
                "totals": dict(self.totals), "errors": self.errors, "last_error": self.last_error, "pending_steps": len(self.pending),
                "connectors": {s: {**{k: v for k, v in st.items() if k != "ms"}, "avg_batch_ms": round(st["ms"] / st["batches"], 1) if st["batches"] else None,
                                   "health": "idle" if not st["batches"] else ("degraded" if st["events"] >= 15 and st["rejected"] / st["events"] > 0.2 else "healthy")} for s, st in self.stats.items()}}


class Runner(threading.Thread):
    """Background loop for one workspace. Stops on request, when the duration elapses, or after repeated failures."""

    def __init__(self, sim: Simulator, tick_s: float = 1.0):
        super().__init__(daemon=True, name=f"sim-{sim.slug}")
        self.sim, self.tick_s = sim, tick_s
        self.stop_event = threading.Event()
        self.finished = False
        self.reason = ""

    def run(self) -> None:
        consecutive = 0
        try:
            with db.use_workspace(self.sim.slug):
                self.sim.prepare()
                deadline = time.time() + self.sim.duration_min * 60
                while not self.stop_event.is_set():
                    t0 = time.time()
                    try:
                        self.sim.tick()
                        consecutive = 0
                    except Exception as exc:  # keep running through transient DB contention; stop if it persists
                        consecutive += 1
                        self.sim.errors += 1
                        self.sim.last_error = f"{type(exc).__name__}: {exc}"[:200]
                        log.warning("simulation tick failed: %s", self.sim.last_error)
                        if consecutive >= 10:
                            self.reason = "stopped after repeated errors"
                            break
                    if time.time() >= deadline:
                        self.reason = "duration elapsed"
                        break
                    self.stop_event.wait(max(0.1, self.tick_s - (time.time() - t0)))
        except Exception as exc:  # prepare() failure etc.
            self.sim.last_error = f"{type(exc).__name__}: {exc}"[:200]
            self.reason = "failed to start"
        finally:
            self.finished = True
            self.reason = self.reason or "stopped by user"


_runners: dict[str, Runner] = {}
_lock = threading.Lock()


def start(slug: str, **cfg) -> Runner:
    for k, (lo, hi) in LIMITS.items():
        if k in cfg and not lo <= float(cfg[k]) <= hi:
            raise ValueError(f"{k} must be between {lo} and {hi}")
    with _lock:
        cur = _runners.get(slug)
        if cur and cur.is_alive():
            raise RuntimeError("A simulation is already running in this workspace")
        r = Runner(Simulator(slug, **cfg))
        _runners[slug] = r
    r.start()
    return r


def stop(slug: str, wait: float = 5.0) -> bool:
    r = _runners.get(slug)
    if not r or not r.is_alive():
        return False
    r.stop_event.set()
    r.join(wait)
    return True


def get(slug: str) -> Runner | None:
    return _runners.get(slug)


def running(slug: str) -> bool:
    r = _runners.get(slug)
    return bool(r and r.is_alive())


def stop_all() -> None:
    for slug in list(_runners):
        stop(slug, 2.0)
