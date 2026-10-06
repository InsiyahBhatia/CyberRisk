"""Live simulation: connectors, ETL ingestion, correlation, scenarios, lifecycle, API."""
import time
from datetime import datetime, timedelta, timezone

import pytest

from app.db.session import connect, rows, scalar, use_workspace
from app.simulation import connectors, estate, runner, sources
from app.simulation.runner import Simulator

T0 = datetime(2026, 10, 6, 10, 0, 0, tzinfo=timezone.utc)
KEV_CVE = "CVE-2024-3400"


@pytest.fixture()
def reference(seeded):
    with connect(seeded) as c:
        c.exec_driver_sql(f"INSERT OR REPLACE INTO cve_catalog (cve_id, cvss_score, severity, in_kev, description) VALUES ('{KEV_CVE}', 10.0, 'CRITICAL', 1, 'PAN-OS'), ('CVE-2023-0001', 6.5, 'MEDIUM', 0, 'x')")
        c.exec_driver_sql(f"INSERT OR REPLACE INTO kev_entries (cve_id, vulnerability_name) VALUES ('{KEV_CVE}', 'PAN-OS Command Injection')")
    return seeded


def sim(**kw):
    kw = {"rate_per_min": 0, "scenarios": [], "speed": 1.0, "malformed_pct": 0.0, "seed": 1, **kw}
    s = Simulator("demo", **kw)
    s.prepare()
    s.last_tick = T0 - timedelta(seconds=1)
    return s


def drive(s: Simulator, seconds: int, start: datetime = T0):
    out = []
    for k in range(seconds + 1):
        out.append(s.tick(now=start + timedelta(seconds=k)))
    return out


def corr_incidents(c):
    return rows(c, "SELECT * FROM incidents WHERE source='correlation' ORDER BY id")


# ------------------------------------------------------------------ connectors
GOOD = {
    "SIEM": {"_time": "2026-10-06T10:00:00Z", "search_name": "Brute Force", "urgency": "high", "src": "198.51.100.1", "dest": "web-01", "user": "bob", "mitre_technique_id": "T1110", "_raw": "x"},
    "EDR": {"created_timestamp": "2026-10-06T10:00:00Z", "device": {"hostname": "web-01", "local_ip": "10.1.1.1"}, "username": "bob", "max_severity_displayname": "Critical",
            "behaviors": [{"tactic": "Impact", "technique_id": "T1490", "filename": "vssadmin.exe", "cmdline": "vssadmin delete shadows /all"}]},
    "ITSM": {"number": "INC0000001", "sys_class_name": "incident", "short_description": "Server down", "description": "d", "priority": "1 - Critical", "category": "Security", "cmdb_ci": "web-01", "caller_id": "bob", "opened_at": "2026-10-06 10:00:00"},
    "Scanner": {"plugin_name": "p", "cve": ["CVE-2024-3400"], "asset": {"hostname": "web-01", "ipv4": "10.1.1.1"}, "severity": "critical", "cvss_base_score": "9.8", "first_found": "2026-10-06T10:00:00Z"},
    "IAM": {"published": "2026-10-06T10:00:00Z", "eventType": "user.session.start", "outcome": {"result": "FAILURE"}, "actor": {"alternateId": "bob@corp.example"}, "client": {"ipAddress": "198.51.100.1", "geographicalContext": {"country": "RU"}}},
    "Cloud": {"eventTime": "2026-10-06T10:00:00Z", "eventName": "PutBucketAcl", "userIdentity": {"userName": "bob"}, "sourceIPAddress": "10.0.0.1", "requestParameters": {"bucketName": "b", "AccessControlList": "AllUsers READ"}},
    "Email": {"received": "2026-10-06T10:00:00Z", "reported_by": "bob", "subject": "Urgent", "sender": "x@y.example", "verdict": "malicious", "urls": ["hxxp://x[.]example"], "attachments": ["a.xlsm"]},
}


@pytest.mark.parametrize("src", list(GOOD))
def test_every_connector_normalises_a_valid_payload(src):
    s = connectors.CONNECTORS[src](GOOD[src])
    assert s.source == src and s.ts == "2026-10-06T10:00:00Z" and s.title and s.severity in connectors.SEVERITIES and s.raw


def test_connector_specifics():
    assert connectors.siem(GOOD["SIEM"]).techniques == ["T1110"] and connectors.edr(GOOD["EDR"]).severity == "CRITICAL"
    t = connectors.itsm(GOOD["ITSM"])
    assert t.severity == "CRITICAL" and t.extra["is_incident"] and t.ts == "2026-10-06T10:00:00Z"
    assert connectors.iam(GOOD["IAM"]).severity == "LOW" and connectors.iam({**GOOD["IAM"], "outcome": {"result": "SUCCESS"}}).severity == "MEDIUM"  # success from RU
    assert connectors.cloud(GOOD["Cloud"]).severity == "HIGH" and connectors.email(GOOD["Email"]).techniques == ["T1566"]


@pytest.mark.parametrize("src,patch,why", [
    ("SIEM", {"urgency": "??"}, "severity"), ("SIEM", {"_time": ""}, "timestamp"), ("SIEM", {"mitre_technique_id": "X99"}, "ATT&CK"), ("SIEM", {"search_name": ""}, "rule"),
    ("EDR", {"behaviors": []}, "behavior"), ("EDR", {"max_severity_displayname": "n/a"}, "severity"), ("ITSM", {"priority": "urgent"}, "priority"), ("ITSM", {"opened_at": "yesterday"}, "timestamp"),
    ("Scanner", {"cvss_base_score": "abc"}, "CVSS"), ("Scanner", {"cvss_base_score": "14"}, "outside"), ("Scanner", {"cve": ["CVE-bad"]}, "CVE"), ("Scanner", {"asset": {}}, "asset"),
    ("IAM", {"outcome": {}}, "outcome"), ("IAM", {"eventType": "weird.event"}, "unsupported"), ("Cloud", {"eventName": "Nope"}, "unsupported"), ("Email", {"verdict": "maybe"}, "verdict"),
])
def test_malformed_payloads_are_rejected_with_a_reason(src, patch, why):
    with pytest.raises(connectors.Reject, match=why):
        connectors.CONNECTORS[src]({**GOOD[src], **patch})


# ------------------------------------------------------------------ scenarios + correlation
EXPECT = {
    "brute_force_takeover": {"T1110", "T1078"}, "phishing_to_ransomware": {"T1566", "T1003", "T1490", "T1486"}, "kev_exploit_edge": {"T1190", "T1071"},
    "cloud_misconfig": {"T1530"}, "insider_exfil": {"T1567", "T1078"},
}


@pytest.mark.parametrize("name", list(sources.SCENARIOS))
def test_each_storyline_becomes_exactly_one_incident_and_is_marked_detected(reference, name):
    s = sim()
    info = s.inject(name, now=T0)
    drive(s, int(info["completes_in_s"]) + 3)
    with connect(reference) as c:
        inc = corr_incidents(c)
        assert len(inc) == 1, [i["title"] for i in inc]
        techs = set(inc[0]["technique_ids"].split(","))
        assert EXPECT[name] <= techs, techs
        assert inc[0]["severity"] in ("HIGH", "CRITICAL") and inc[0]["status"] == "OPEN" and inc[0]["incident_code"].startswith("SIM-") and inc[0]["signal_count"] >= 3
        sc = rows(c, "SELECT * FROM sim_scenarios")[0]
        assert sc["incident_id"] == inc[0]["id"] and sc["detected_at"] and sc["steps"] == info["steps"]
        assert scalar(c, "SELECT COUNT(*) FROM signals WHERE status='NEW' AND severity!='INFO' AND kind!='finding'") == 0     # everything meaningful is correlated


def test_incident_is_updated_not_duplicated_as_the_attack_progresses(reference):
    s = sim()
    s.inject("phishing_to_ransomware", now=T0)
    seen = []
    for k in range(0, 75):
        s.tick(now=T0 + timedelta(seconds=k))
        with connect(reference) as c:
            seen.append((len(corr_incidents(c)), (corr_incidents(c) or [{}])[0].get("signal_count"), (corr_incidents(c) or [{}])[0].get("severity")))
    counts = [n for n, _, _ in seen]
    assert max(counts) == 1 and counts[-1] == 1
    sigs = [x for _, x, _ in seen if x]
    assert sigs == sorted(sigs) and sigs[-1] > sigs[0]                       # grows as evidence arrives
    assert seen[-1][2] == "CRITICAL"                                         # escalated as the chain advanced
    with connect(reference) as c:
        inc = corr_incidents(c)[0]
        assert "ransomware" in inc["title"].lower() and inc["category"] == "Ransomware"   # title/category follow the most advanced technique, not the first alert


def test_noise_alone_never_opens_an_incident(reference):
    s = sim(rate_per_min=600)
    res = drive(s, 90)
    assert sum(r["events"] for r in res) > 400
    with connect(reference) as c:
        assert corr_incidents(c) == []
        assert scalar(c, "SELECT COUNT(DISTINCT source) FROM signals") >= 5   # every integration produced events
        assert scalar(c, "SELECT COUNT(*) FROM signals WHERE simulated=1") == scalar(c, "SELECT COUNT(*) FROM signals")


def test_two_concurrent_attacks_stay_separate(reference):
    s = sim()
    hosts = [h.tag for h in s.estate.hosts if h.exposed][:2]
    s.inject("brute_force_takeover", hosts[0], now=T0)
    s.inject("brute_force_takeover", hosts[1], now=T0)
    drive(s, 50)
    with connect(reference) as c:
        inc = corr_incidents(c)
        assert len(inc) == 2 and len({i["affected_asset_id"] for i in inc}) == 2
        assert scalar(c, "SELECT COUNT(*) FROM sim_scenarios WHERE incident_id IS NOT NULL") == 2


def test_injecting_unknown_scenario_or_target_fails():
    with pytest.raises(ValueError):
        Simulator("demo", scenarios=["nope"])


def test_inject_validation(reference):
    s = sim()
    with pytest.raises(ValueError, match="unknown target"):
        s.inject("brute_force_takeover", "no-such-asset", now=T0)
    with pytest.raises(ValueError):
        s.gen.scenario("nope")


# ------------------------------------------------------------------ ETL integration
def test_each_batch_is_a_tracked_etl_run_with_quality_and_rejections(reference):
    s = sim(rate_per_min=600, malformed_pct=1.0)
    drive(s, 20)
    with connect(reference) as c:
        runs = rows(c, "SELECT * FROM etl_runs WHERE source_name LIKE 'Sim · %'")
        assert runs and {r["status"] for r in runs} == {"SUCCESS"}
        assert all(r["records_read"] == r["records_valid"] + r["records_rejected"] for r in runs)
        assert sum(r["records_rejected"] for r in runs) > 0 and min(r["quality_score"] for r in runs) < 100
        rej = rows(c, "SELECT reason FROM etl_rejections WHERE etl_run_id IN (SELECT id FROM etl_runs WHERE source_name LIKE 'Sim · %') LIMIT 50")
        assert rej and all(r["reason"].startswith("[invalid]") or r["reason"].startswith("[error]") for r in rej)
        reg = rows(c, "SELECT source_type, publisher FROM source_registry WHERE source_name LIKE 'Sim · %'")
        assert len(reg) >= 5 and {r["source_type"] for r in reg} == {"SYNTHETIC"}              # always labelled synthetic


def test_scanner_findings_load_through_the_vulnerability_pipeline_with_kev_enrichment(reference):
    s = sim()
    host = next(h for h in s.estate.hosts)
    ts = T0.strftime("%Y-%m-%dT%H:%M:%SZ")
    s.pending.append((T0, lambda t: s.gen.finding(t, host, {"cve_id": KEV_CVE, "cvss_score": 10.0, "in_kev": True}), 0, "x"))
    s.pending.append((T0, lambda t: s.gen.finding(t, estate.Host("GHOST-1", "ghost-1", "10.0.0.9"), {"cve_id": KEV_CVE, "cvss_score": 10.0, "in_kev": True}), 0, "x"))
    s.tick(now=T0)
    with connect(reference) as c:
        v = rows(c, "SELECT v.*, a.asset_tag FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id WHERE v.cve_id=:c AND a.asset_tag=:t", c=KEV_CVE, t=host.tag)[0]
        assert v["known_exploited"] == 1 and v["cvss_score"] == 10.0 and v["severity"] == "CRITICAL" and v["risk_score"] > 60     # real KEV flag + recalculated priority score
        rej = rows(c, "SELECT reason FROM etl_rejections WHERE reason LIKE '[orphan]%' ORDER BY id DESC LIMIT 1")
        assert rej and "GHOST-1" in rej[0]["reason"]                                                                              # unknown asset rejected like any import
        assert scalar(c, "SELECT COUNT(*) FROM vulnerabilities WHERE asset_id IS NULL") == 0


def test_security_tickets_flow_through_incident_etl(reference):
    s = sim()
    host = s.estate.hosts[0]
    s.pending.append((T0, lambda t: s.gen.ticket(t, "Security", "Possible malware on laptop", "AV flagged a dropper.", "2 - High", host, "bob"), 0, "x"))
    s.pending.append((T0, lambda t: s.gen.ticket(t, "Access", "Password reset request", "routine", "4 - Low", None, "bob", "sc_request"), 0, "x"))
    s.tick(now=T0)
    with connect(reference) as c:
        inc = rows(c, "SELECT * FROM incidents WHERE source='itsm'")
        assert len(inc) == 1 and inc[0]["severity"] == "HIGH" and inc[0]["incident_code"].startswith("INC") and inc[0]["affected_asset_id"] == host.asset_id
        assert scalar(c, "SELECT COUNT(*) FROM signals WHERE source='ITSM'") == 2                                                 # the routine request is a signal, not an incident


def test_empty_workspace_gets_a_simulated_cmdb_through_the_assets_etl(client):
    org = client.post("/api/workspaces", json={"name": "Sim Org"}).json()
    s = Simulator(org["slug"], rate_per_min=0, scenarios=[], malformed_pct=0, seed=2)
    with use_workspace(org["slug"]):
        s.prepare()
        with connect() as c:
            assert scalar(c, "SELECT COUNT(*) FROM assets") == 24 and scalar(c, "SELECT COUNT(*) FROM etl_runs WHERE source_name='Synthetic assets'") == 1
    assert len(s.estate.hosts) == 24 and any(h.exposed for h in s.estate.hosts)


def test_same_seed_same_time_gives_identical_events(reference):
    def run():
        s = sim(rate_per_min=300, seed=42)
        s.inject("brute_force_takeover", now=T0)
        drive(s, 20)
        with connect(reference) as c:
            out = [(r["source"], r["ts"], r["title"], r["host"]) for r in rows(c, "SELECT source, ts, title, host FROM signals ORDER BY id")]
            for t in ("signals", "sim_scenarios", "incidents", "sim_metrics"):
                if t == "incidents":
                    c.exec_driver_sql("DELETE FROM incidents WHERE source IN ('correlation','itsm')")
                else:
                    c.exec_driver_sql(f"DELETE FROM {t}")
        return out
    a, b = run(), run()
    assert a and a == b


def test_retention_prunes_old_signals(reference, monkeypatch):
    monkeypatch.setattr(runner, "KEEP_SIGNALS", 50)
    s = sim(rate_per_min=600)
    drive(s, 30)
    with connect(reference) as c:
        assert scalar(c, "SELECT COUNT(*) FROM signals") <= 51


# ------------------------------------------------------------------ lifecycle + API
def test_limits_and_double_start(reference):
    with pytest.raises(ValueError):
        runner.start("demo", rate_per_min=100000)
    r = runner.start("demo", rate_per_min=60, scenarios=[], duration_min=1, seed=3)
    try:
        with pytest.raises(RuntimeError, match="already running"):
            runner.start("demo", rate_per_min=60)
    finally:
        runner.stop("demo")
    assert not r.is_alive()


def test_background_thread_ingests_and_stops_cleanly(reference):
    r = runner.start("demo", rate_per_min=600, scenarios=["brute_force_takeover"], speed=10, duration_min=1, seed=5, scenario_every_s=15)
    deadline = time.time() + 20
    while time.time() < deadline and r.sim.totals["events"] < 30:
        time.sleep(0.3)
    assert runner.stop("demo") and not r.is_alive() and r.finished
    assert r.sim.totals["events"] >= 30 and r.sim.errors == 0
    with connect(reference) as c:
        assert scalar(c, "SELECT COUNT(*) FROM signals") >= 30 and scalar(c, "SELECT COUNT(*) FROM sim_metrics") >= 1


def test_runner_stops_when_duration_elapses(reference):
    s = Simulator("demo", rate_per_min=60, scenarios=[], seed=6)
    s.duration_min = 0.02            # ~1.2 s
    r = runner.Runner(s, tick_s=0.3)
    r.start()
    r.join(10)
    assert not r.is_alive() and r.reason == "duration elapsed"


def test_api_end_to_end(client, reference):
    st = client.get("/api/sim/status").json()
    assert st["running"] is False and "limits" in st
    assert client.post("/api/sim/inject", json={"scenario": "brute_force_takeover"}).status_code == 409           # must start first
    assert client.post("/api/sim/start", json={"rate_per_min": 5000}).status_code == 422
    assert client.post("/api/sim/start", json={"scenarios": ["nope"]}).status_code == 422
    sb = client.post("/api/sim/start", json={}, headers={"X-Workspace": "sandbox"})
    assert sb.status_code == 422 and "sandbox" in sb.text.lower()
    r = client.post("/api/sim/start", json={"rate_per_min": 600, "speed": 10, "scenarios": [], "duration_min": 1, "malformed_pct": 0.1, "seed": 9})
    assert r.status_code == 201
    try:
        assert client.post("/api/sim/start", json={}).status_code == 409
        inj = client.post("/api/sim/inject", json={"scenario": "kev_exploit_edge"})
        assert inj.status_code == 201 and inj.json()["steps"] == 5
        assert client.post("/api/sim/inject", json={"scenario": "kev_exploit_edge", "target": "nope"}).status_code == 422
        deadline = time.time() + 25
        inc = []
        while time.time() < deadline and not inc:
            time.sleep(0.5)
            inc = client.get("/api/sim/incidents").json()["items"]
            inc = [i for i in inc if i["source"] == "correlation"]
        assert inc, "scenario was not detected in time"
        feed = client.get("/api/sim/feed?limit=20").json()
        assert feed["items"] and feed["latest_id"] >= feed["items"][0]["id"]
        newest = feed["latest_id"]
        time.sleep(1.5)
        assert all(i["id"] > newest for i in client.get(f"/api/sim/feed?after_id={newest}").json()["items"])           # polling returns only new items
        assert client.get("/api/sim/feed?min_severity=CRITICAL").json()["items"] == [] or all(i["severity"] == "CRITICAL" for i in client.get("/api/sim/feed?min_severity=CRITICAL").json()["items"])
        sig = client.get(f"/api/sim/signals/{feed['items'][0]['id']}").json()
        assert "Synthetic" in sig["simulated_notice"]
        assert client.get("/api/sim/status").json()["running"] is True
    finally:
        assert client.post("/api/sim/stop").json()["stopped"] is True
    d = client.get(f"/api/sim/incidents/{inc[0]['id']}").json()
    assert d["signals"] and d["techniques"] and "T1190" in {t["technique_id"] for t in d["techniques"]}
    ack = client.post(f"/api/sim/incidents/{inc[0]['id']}/triage", json={"status": "INVESTIGATING", "analyst": "Dana", "note": "looking"}).json()
    assert ack["status"] == "INVESTIGATING" and ack["acknowledged_at"]
    assert client.post(f"/api/sim/incidents/{inc[0]['id']}/triage", json={"status": "CLOSED", "analyst": "Dana"}).status_code == 200
    assert client.post(f"/api/sim/incidents/{inc[0]['id']}/triage", json={"status": "CLOSED", "analyst": "Dana"}).status_code == 409
    an = client.post(f"/api/sim/incidents/{inc[1 if len(inc) > 1 else 0]['id']}/analyze")
    assert an.status_code == 201 and an.json()["findings"] >= 1                                                      # raw evidence goes through the same detection engine
    m = client.get("/api/sim/metrics").json()
    assert m["series"] and m["detection"]["scenarios"] >= 1 and m["detection"]["detected"] >= 1 and m["detection"]["mean_time_to_detect_s"] is not None
    assert client.get("/api/etl/runs?page_size=200").json()["items"]                                                  # batches appear in Ingestion History
    assert client.delete("/api/sim/data").json()["removed_signals"] > 0
    assert client.get("/api/sim/incidents").json()["items"] == []


def test_simulation_never_touches_other_workspaces(client, reference):
    org = client.post("/api/workspaces", json={"name": "Quiet Org"}).json()
    before = client.get("/api/incidents", headers={"X-Workspace": org["slug"]}).json()["total"]
    s = sim(rate_per_min=300)
    s.inject("brute_force_takeover", now=T0)
    drive(s, 40)
    assert client.get("/api/incidents", headers={"X-Workspace": org["slug"]}).json()["total"] == before == 0
    with use_workspace(org["slug"]), connect() as c:
        assert scalar(c, "SELECT COUNT(*) FROM signals") == 0
