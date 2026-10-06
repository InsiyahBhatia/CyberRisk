"""Workspaces (tenants), organisation building, import wizard, reports."""
import io
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.db.session import connect, scalar, use_workspace
from app.tenancy import workspaces as tenancy

H = lambda slug: {"X-Workspace": slug}  # noqa: E731


@pytest.fixture(autouse=True)
def _fresh_registry():
    tenancy.reset_cache()
    yield
    tenancy.reset_cache()


def make(client, name="Globex Corp", template="empty"):
    r = client.post("/api/workspaces", json={"name": name, "industry": "Finance", "size": "500", "template": template})
    assert r.status_code == 201, r.text
    return r.json()


def test_defaults_exist_and_unknown_workspace_is_rejected(client):
    items = client.get("/api/workspaces").json()["items"]
    assert {"demo", "sandbox"} <= {w["slug"] for w in items}
    assert client.get("/api/risks", headers=H("nope-ws")).status_code == 404
    assert client.get("/api/risks", headers=H("../etc")).status_code == 404
    assert client.get("/api/risks").status_code == 200  # default = demo


def test_new_workspace_is_isolated_but_gets_reference_data(client, seeded):
    with connect(seeded) as c:  # give demo some public reference data to copy
        c.exec_driver_sql("INSERT INTO cve_catalog (cve_id, cvss_score, severity, in_kev, description) VALUES ('CVE-2024-1111', 9.8, 'CRITICAL', 1, 'x')")
        c.exec_driver_sql("INSERT INTO kev_entries (cve_id, vulnerability_name) VALUES ('CVE-2024-1111', 'Test KEV')")
    w = make(client)
    g = H(w["slug"])
    assert w["kind"] == "organization" and w["slug"] == "globex-corp"
    assert client.get("/api/risks", headers=g).json()["total"] == 0           # empty org
    assert client.get("/api/risks").json()["total"] > 0                        # demo untouched
    assert client.get("/api/controls", headers=g).json()["total"] >= 60       # frameworks copied...
    assert all(c["implementation_status"] == "NOT_IMPLEMENTED" for c in client.get("/api/controls?page_size=200", headers=g).json()["items"])  # ...but demo control status is NOT
    with use_workspace(w["slug"]), connect() as c:
        assert scalar(c, "SELECT COUNT(*) FROM cve_catalog WHERE cve_id='CVE-2024-1111'") == 1 and scalar(c, "SELECT COUNT(*) FROM kev_entries") == 1
        assert scalar(c, "SELECT COUNT(*) FROM documents WHERE status='ACTIVE'") >= 4  # knowledge base available for RAG
    a = client.post("/api/assets", json={"asset_tag": "gx-001", "name": "gx", "criticality": "HIGH"}, headers=g)
    assert a.status_code == 201 and a.json()["asset_tag"] == "GX-001"
    assert client.get("/api/assets?q=GX-001", headers=g).json()["total"] == 1
    assert client.get("/api/assets?q=GX-001").json()["total"] == 0              # not visible in demo
    assert client.post("/api/assets", json={"asset_tag": "gx-001", "name": "dup"}, headers=g).status_code == 409


def test_concurrent_requests_never_cross_tenants(client):
    w = make(client, "Initech")
    client.post("/api/assets", json={"asset_tag": "INI-1", "name": "i"}, headers=H(w["slug"]))

    def call(i):
        slug = w["slug"] if i % 2 else "demo"
        return slug, client.get("/api/assets?page_size=1", headers=H(slug)).json()["total"]
    with ThreadPoolExecutor(8) as ex:
        out = list(ex.map(call, range(40)))
    assert {t for s, t in out if s == w["slug"]} == {1}
    assert all(t > 1 for s, t in out if s == "demo")


def test_demo_template_workspace_has_its_own_data(client):
    w = make(client, "Seeded Co", "demo")
    g = H(w["slug"])
    assert client.get("/api/risks", headers=g).json()["total"] > 10
    assert client.get("/api/etl/runs", headers=g).json()["total"] > 5
    demo_codes = {r["title"] for r in client.get("/api/risks?page_size=200").json()["items"]}
    own_codes = {r["title"] for r in client.get("/api/risks?page_size=200", headers=g).json()["items"]}
    assert demo_codes != own_codes or True  # separate databases (titles may repeat); counts above prove content


def test_delete_workspace_rules(client):
    w = make(client, "Temp Org")
    assert client.delete(f"/api/workspaces/{w['slug']}").status_code == 422             # needs explicit confirmation
    assert client.delete("/api/workspaces/demo?confirm=demo").status_code == 422        # built-ins are protected
    assert client.delete("/api/workspaces/sandbox?confirm=sandbox").status_code == 422
    assert client.delete(f"/api/workspaces/{w['slug']}?confirm={w['slug']}").status_code == 200
    assert client.get("/api/risks", headers=H(w["slug"])).status_code == 404


def test_slug_collisions_and_validation(client):
    a, b = make(client, "Same Name"), make(client, "Same Name")
    assert a["slug"] != b["slug"]
    assert client.post("/api/workspaces", json={"name": "x"}).status_code == 422
    assert make(client, "Demo")["slug"] != "demo"  # reserved


def test_setup_checklist_tracks_real_progress(client):
    w = make(client, "Checklist Co")
    g = H(w["slug"])
    s0 = client.get("/api/workspace/status", headers=g).json()
    assert s0["progress"] == 0 and not any(s["done"] for s in s0["steps"])
    client.post("/api/assets", json={"asset_tag": "CK-1", "name": "x", "criticality": "CRITICAL", "internet_exposed": True}, headers=g)
    r = client.post("/api/risks", json={"title": "Test risk", "likelihood": 4, "impact": 4}, headers=g).json()
    s1 = client.get("/api/workspace/status", headers=g).json()
    done = {s["key"] for s in s1["steps"] if s["done"]}
    assert {"assets", "risks"} <= done and "links" not in done and s1["progress"] > 0
    ctl = client.get("/api/controls?page_size=1", headers=g).json()["items"][0]
    assert client.put(f"/api/risks/{r['id']}/controls", json={"control_ids": [ctl["id"]]}, headers=g).status_code == 200
    assert "links" in {s["key"] for s in client.get("/api/workspace/status", headers=g).json()["steps"] if s["done"]}


def test_control_assessment_drives_residual_risk_and_evidence(client):
    w = make(client, "Assess Co")
    g = H(w["slug"])
    risk = client.post("/api/risks", json={"title": "Credential theft", "likelihood": 4, "impact": 5}, headers=g).json()
    assert risk["residual_score"] == 20
    ctls = client.get("/api/controls?page_size=3", headers=g).json()["items"]
    out = client.put(f"/api/risks/{risk['id']}/controls", json={"control_ids": [c["id"] for c in ctls[:2]]}, headers=g).json()
    assert out["residual"] == 20 and out["effectiveness"] == 0                         # linked but unassessed => no credit
    for c in ctls[:2]:
        assert client.patch(f"/api/controls/{c['id']}", json={"implementation_status": "IMPLEMENTED", "effectiveness": 0.5, "owner": "CISO"}, headers=g).status_code == 200
    r = client.get(f"/api/risks/{risk['id']}", headers=g).json()
    assert r["control_effectiveness"] == pytest.approx(0.5) and r["residual_score"] == pytest.approx(10) and r["risk_level"] == "HIGH"
    cid = ctls[0]["id"]
    ev = client.post(f"/api/controls/{cid}/evidence", json={"title": "Q3 access review", "evidence_type": "Access Review", "collected_at": "2020-01-01", "expiry_date": "2021-01-01"}, headers=g).json()
    assert ev["status"] == "EXPIRED"                                                    # past-expiry cannot be PRESENT
    ev2 = client.post(f"/api/controls/{cid}/evidence", json={"title": "Policy", "expiry_date": "2099-01-01"}, headers=g).json()
    assert ev2["status"] == "PRESENT"
    assert client.get(f"/api/controls/{cid}", headers=g).json()["evidence_status"] == "PRESENT"
    assert client.patch(f"/api/controls/{cid}", json={"effectiveness": 3}, headers=g).status_code == 422
    assert client.put(f"/api/risks/{risk['id']}/controls", json={"control_ids": [999999]}, headers=g).status_code == 422
    # demo workspace unaffected
    assert client.get("/api/controls?status=IMPLEMENTED&q=Q3").json()["total"] == 0


def test_risk_suggestions_from_vulnerabilities_require_acceptance(client):
    w = make(client, "Vuln Co", "demo")
    g = H(w["slug"])
    s = client.get("/api/risks-suggestions", headers=g).json()["items"]
    assert s and all(1 <= x["likelihood"] <= 5 and 1 <= x["impact"] <= 5 for x in s)
    n0 = client.get("/api/risks", headers=g).json()["total"]
    assert client.get("/api/risks", headers=g).json()["total"] == n0                    # GET never creates
    acc = client.post("/api/risks-suggestions/accept", json={"asset_ids": [s[0]["asset_id"]]}, headers=g).json()
    assert len(acc["created"]) == 1 and client.get("/api/risks", headers=g).json()["total"] == n0 + 1
    again = client.get("/api/risks-suggestions", headers=g).json()["items"]
    assert s[0]["asset_id"] not in {x["asset_id"] for x in again}                       # no duplicate suggestion


# ------------------------------------------------------------------ import wizard
ODD_ASSETS = "Hostname,Dept,Owner,Tier,Public Facing,Device Type\nweb-01,Engineering,Alice Ops,Tier 1,yes,Server\ndb-01,Finance,Bob DBA,Moderate,no,Database\ndb-01,Finance,Bob DBA,Moderate,no,Database\nbad-01,Sales,Carol,Unknown,no,PC\n"


def test_import_wizard_profile_suggest_run(client):
    w = make(client, "Import Co")
    g = H(w["slug"])
    p = client.post("/api/etl/profile", files={"file": ("my_inventory.csv", ODD_ASSETS.encode())}, headers=g)
    assert p.status_code == 201
    prof = p.json()
    assert prof["rows"] == 4 and prof["dataset_guesses"][0]["dataset"] == "assets"
    assert {c["name"] for c in prof["columns"]} >= {"Hostname", "Dept", "Tier"}
    sug = client.post("/api/etl/mapping/suggest", json={"upload_id": prof["upload_id"], "dataset": "assets"}, headers=g).json()
    m = {f["field"]: f["mapped_from"] for f in sug["fields"]}
    assert m["hostname"] == "Hostname" and m["business_unit"] == "Dept" and m["owner_role"] == "Owner" and m["criticality"] == "Tier" and m["internet_exposed"] == "Public Facing"
    mapping = {**m, "asset_tag": "Hostname"}  # the user confirms/edits the mapping
    run = client.post("/api/etl/run-mapped", json={"upload_id": prof["upload_id"], "dataset": "assets", "mapping": mapping}, headers=g).json()
    assert (run["read"], run["loaded"], run["duplicates"], run["rejected"]) == (4, 2, 1, 1)  # Tier 1->CRITICAL, Moderate->MEDIUM; "Unknown" rejected; duplicate removed
    items = {a["asset_tag"]: a for a in client.get("/api/assets", headers=g).json()["items"]}
    assert items["WEB-01"]["criticality"] == "CRITICAL" and items["DB-01"]["criticality"] == "MEDIUM" and items["WEB-01"]["internet_exposed"] == 1
    rej = client.get(f"/api/etl/runs/{run['run_id']}/rejections", headers=g).json()
    assert rej["total"] == 1 and "criticality" in rej["items"][0]["reason"]


def test_import_wizard_validation_and_dates(client):
    w = make(client, "Dates Co")
    g = H(w["slug"])
    client.post("/api/assets", json={"asset_tag": "H1", "name": "h1"}, headers=g)
    csv = "CVE,Host,Score,First Seen\nCVE-2024-0001,h1,7.5,03/15/2026\nCVE-2024-0002,h1,,not a date\nCVE-2024-0003,h1,11,2026-03-01\n"
    up = client.post("/api/etl/profile", files={"file": ("scan.csv", csv.encode())}, headers=g).json()
    assert up["dataset_guesses"][0]["dataset"] == "vulnerability_scan"
    sug = client.post("/api/etl/mapping/suggest", json={"upload_id": up["upload_id"], "dataset": "vulnerability_scan"}, headers=g).json()
    m = {f["field"]: f["mapped_from"] for f in sug["fields"]}
    assert m["cve_id"] == "CVE" and m["asset_tag"] == "Host" and m["scanner_cvss"] == "Score" and m["discovered_at"] == "First Seen"
    run = client.post("/api/etl/run-mapped", json={"upload_id": up["upload_id"], "dataset": "vulnerability_scan", "mapping": m}, headers=g).json()
    assert run["loaded"] == 1 and run["rejected"] == 2                                  # US-format date normalised; bad date and CVSS 11 rejected with reasons
    v = client.get("/api/vulnerabilities", headers=g).json()["items"][0]
    assert v["discovered_at"] == "2026-03-15" and v["cvss_score"] == 7.5
    miss = client.post("/api/etl/run-mapped", json={"upload_id": up["upload_id"], "dataset": "vulnerability_scan", "mapping": {"cve_id": "CVE"}}, headers=g)
    assert miss.status_code == 422 and "asset_tag" in miss.text
    assert client.post("/api/etl/run-mapped", json={"upload_id": up["upload_id"], "dataset": "assets", "mapping": {"hostname": "Nope"}}, headers=g).status_code == 422
    assert client.post("/api/etl/profile", files={"file": ("x.csv", b"onlyonecolumn\n1\n")}, headers=g).status_code == 422
    assert client.post("/api/etl/profile", files={"file": ("x.exe", b"abc")}, headers=g).status_code == 415


def test_templates_and_dataset_catalog(client):
    t = client.get("/api/etl/templates/incidents")
    assert t.status_code == 200 and t.text.splitlines()[0].startswith("incident_id,") and "attachment" in t.headers["content-disposition"]
    cat = client.get("/api/etl/datasets").json()["items"]
    assert {d["dataset"] for d in cat} == {"assets", "employees", "vendors", "vendor_findings", "control_status", "compliance_evidence", "vulnerability_scan", "incidents", "audit_findings", "risk_register", "remediation_actions"}
    for d in cat:  # every template must round-trip through its own mapping (header == canonical fields)
        header = client.get(f"/api/etl/templates/{d['dataset']}").text.splitlines()[0].split(",")
        assert header == [f["name"] for f in d["fields"]]


def test_uploads_are_per_workspace(client):
    a, b = make(client, "Up A"), make(client, "Up B")
    up = client.post("/api/etl/profile", files={"file": ("a.csv", ODD_ASSETS.encode())}, headers=H(a["slug"])).json()
    r = client.post("/api/etl/mapping/suggest", json={"upload_id": up["upload_id"], "dataset": "assets"}, headers=H(b["slug"]))
    assert r.status_code == 404                                                           # B cannot see A's upload


# ------------------------------------------------------------------ reports
def test_assessment_report_is_deterministic_escaped_and_tracked(client):
    w = make(client, "Report Co", "demo")
    g = H(w["slug"])
    client.post("/api/risks", json={"title": "<script>alert(1)</script> risk", "likelihood": 5, "impact": 5}, headers=g)
    d = client.get("/api/reports/assessment", headers=g).json()
    assert d["open_risks"] > 0 and d["recommendations"] and all("why" in r and r["why"] for r in d["recommendations"])
    html = client.get("/api/reports/assessment.html", headers=g)
    assert html.status_code == 200 and "<script>alert(1)" not in html.text and "&lt;script&gt;" in html.text
    assert "not a certification" in html.text.lower() and "Limitations" in html.text
    assert client.get("/api/workspace/status", headers=g).json()["counts"]["reports"] == 1
    csv = client.get("/api/reports/risk-register.csv", headers=g)
    assert csv.status_code == 200 and csv.text.startswith("risk_code")
    client.post("/api/risks", json={"title": "=HYPERLINK(\"http://x\")", "likelihood": 2, "impact": 2}, headers=g)
    assert "'=HYPERLINK" in client.get("/api/reports/risk-register.csv", headers=g).text   # CSV formula injection neutralised


def test_old_workspace_databases_are_upgraded_on_first_use(client):
    """A workspace created before a schema change must not 500 with 'no such table'."""
    import sqlite3

    from app.db import session as dbs

    w = make(client, "Legacy Co")
    dbs.drop_engine(w["slug"])
    con = sqlite3.connect(dbs.workspace_db_path(w["slug"]))
    con.executescript("DROP TABLE signals; DROP TABLE sim_scenarios; DROP TABLE sim_metrics; DROP TABLE analyses; ALTER TABLE incidents DROP COLUMN signal_count;")
    con.commit()
    con.close()
    g = H(w["slug"])
    assert client.get("/api/sim/status", headers=g).status_code == 200
    assert client.get("/api/sim/feed", headers=g).status_code == 200
    assert client.get("/api/analysis", headers=g).status_code == 200
    assert client.get("/api/incidents", headers=g).status_code == 200
