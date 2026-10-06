import pytest

from app.db.session import connect, scalar
from app.grc.service import control_evidence_status, coverage


def test_evidence_rollup_and_coverage_formulas():
    assert control_evidence_status([]) == "MISSING"
    assert control_evidence_status(["EXPIRED", "PRESENT"]) == "PRESENT"
    assert control_evidence_status(["EXPIRED", "NEEDS_REVIEW"]) == "EXPIRED"
    ctl = [{"implementation_status": "IMPLEMENTED", "evidence_status": "PRESENT"},
           {"implementation_status": "IMPLEMENTED", "evidence_status": "EXPIRED"},
           {"implementation_status": "PARTIAL", "evidence_status": "MISSING"},
           {"implementation_status": "NOT_APPLICABLE", "evidence_status": "MISSING"}]
    c = coverage(ctl)
    assert c["applicable_controls"] == 3
    assert c["control_coverage"] == pytest.approx(66.7, abs=0.1)  # implemented / applicable
    assert c["evidence_coverage"] == pytest.approx(33.3, abs=0.1)  # valid evidence / applicable


def test_risk_scores_in_db_match_engine(seeded):
    from app.risk import engine as e
    from app.db.session import rows

    with connect(seeded) as c:
        for r in rows(c, "SELECT * FROM risks"):
            assert r["inherent_score"] == e.inherent_score(r["likelihood"], r["impact"])
            assert r["residual_score"] == pytest.approx(r["inherent_score"] * (1 - r["control_effectiveness"]))
            assert r["risk_level"] == e.risk_level(r["residual_score"])
        assert scalar(c, "SELECT COUNT(*) FROM risk_history") >= scalar(c, "SELECT COUNT(*) FROM risks")


def test_vulnerability_risk_scores_calculated(seeded):
    with connect(seeded) as c:
        assert scalar(c, "SELECT COUNT(*) FROM vulnerabilities WHERE risk_score IS NULL") == 0
        assert scalar(c, "SELECT MAX(risk_score) FROM vulnerabilities") <= 100


# ------------------------------------------------------------------ API
def test_health_never_exposes_secrets(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and "key" not in r.text.lower().replace("gemini_configured", "")


@pytest.mark.parametrize("url", ["/api/dashboard/summary", "/api/dashboard/risk-trend", "/api/dashboard/business-units", "/api/dashboard/heatmap",
                                 "/api/risks", "/api/vulnerabilities", "/api/incidents", "/api/controls", "/api/compliance/summary",
                                 "/api/vendors", "/api/etl/runs", "/api/data-sources"])
def test_read_endpoints_ok(client, url):
    assert client.get(url).status_code == 200


def test_pagination_filtering_sorting(client):
    r = client.get("/api/risks?page_size=5&sort=residual_score&order=desc").json()
    assert len(r["items"]) == 5 and r["total"] >= 5
    scores = [x["residual_score"] for x in r["items"]]
    assert scores == sorted(scores, reverse=True)
    high = client.get("/api/risks?level=HIGH&page_size=200").json()["items"]
    assert high and all(x["risk_level"] == "HIGH" for x in high)
    assert client.get("/api/risks?page_size=100000").json()["page_size"] == 200  # capped
    assert client.get("/api/risks?sort=residual_score;DROP TABLE risks").status_code == 200  # whitelist, no injection
    assert client.get("/api/risks?level=NOPE").status_code == 422


def test_not_found_and_error_format(client):
    r = client.get("/api/risks/999999")
    assert r.status_code == 404 and r.json()["error"]["code"] == 404
    bad = client.post("/api/risks", json={"title": "ab", "likelihood": 9, "impact": 0})
    assert bad.status_code == 422 and bad.json()["error"]["details"]


def test_risk_detail_includes_mappings_and_controls(client):
    rid = client.get("/api/risks?page_size=1").json()["items"][0]["id"]
    d = client.get(f"/api/risks/{rid}").json()
    assert d["controls"] and d["mappings"] and "curated" in d["mapping_note"].lower()
    assert all(m["origin"] in ("CURATED", "AI_SUGGESTED") for m in d["mappings"])


def test_create_and_update_risk_recomputes_deterministically(client):
    c = client.post("/api/risks", json={"title": "Test risk", "likelihood": 4, "impact": 5, "owner": "Tester"})
    assert c.status_code == 201
    r = c.json()
    assert r["inherent_score"] == 20 and r["residual_score"] == 20 and r["risk_level"] == "CRITICAL"
    u = client.patch(f"/api/risks/{r['id']}", json={"likelihood": 2, "impact": 2}).json()
    assert u["inherent_score"] == 4 and u["risk_level"] == "LOW"
    hist = client.get(f"/api/risks/{r['id']}/history").json()["items"]
    assert len(hist) == 2


def test_accepting_high_risk_requires_human_approval(client):
    r = client.post("/api/risks", json={"title": "Accept me", "likelihood": 5, "impact": 5}).json()
    p = client.patch(f"/api/risks/{r['id']}", json={"status": "ACCEPTED", "treatment": "ACCEPT"}).json()
    assert p["approval_status"] == "PENDING"
    d = client.post(f"/api/risks/{r['id']}/approval", json={"decision": "APPROVED", "reviewer": "CISO", "comments": "ok"}).json()
    assert d["approval_status"] == "APPROVED"
    assert client.post(f"/api/risks/{r['id']}/approval", json={"decision": "APPROVED", "reviewer": "CISO"}).status_code == 409


def test_simulation_endpoint_is_deterministic_and_labelled(client):
    items = client.get("/api/risks?page_size=200").json()["items"]
    for it in items:
        acts = [a for a in client.get(f"/api/risks/{it['id']}").json()["remediation"] if a["status"] != "COMPLETED"]
        if acts:
            break
    body = {"action_ids": [a["id"] for a in acts]}
    s1, s2 = client.post(f"/api/risks/{it['id']}/simulate", json=body).json(), client.post(f"/api/risks/{it['id']}/simulate", json=body).json()
    assert s1 == s2 and s1["is_projection"] and "not a guarantee" in s1["disclaimer"]
    assert s1["projected_residual"] < s1["current_residual"] or s1["current_residual"] == 0
    assert client.post(f"/api/risks/{it['id']}/simulate", json={"action_ids": [99999999]}).status_code == 422
    # simulation never changes stored data
    assert client.get(f"/api/risks/{it['id']}").json()["residual_score"] == s1["current_residual"]


def test_compliance_summary_not_a_certification(client):
    fw = client.get("/api/compliance/summary").json()["frameworks"]
    assert {f["name"] for f in fw} == {"NIST CSF", "ISO/IEC 27001", "SOC 2"}
    assert all("not a certification" in f["note"].lower() for f in fw)
    assert all(0 <= f["control_coverage"] <= 100 and 0 <= f["evidence_coverage"] <= 100 for f in fw)


def test_etl_upload_validation(client):
    assert client.post("/api/etl/upload", data={"dataset": "assets"}, files={"file": ("x.exe", b"abc")}).status_code == 415
    assert client.post("/api/etl/upload", data={"dataset": "assets"}, files={"file": ("x.csv", b"")}).status_code == 422
    assert client.post("/api/etl/upload", data={"dataset": "nope"}, files={"file": ("x.csv", b"a")}).status_code == 422
    big = b"a" * (10 * 1024 * 1024 + 5)
    assert client.post("/api/etl/upload", data={"dataset": "assets"}, files={"file": ("x.csv", big)}).status_code == 413


def test_etl_upload_and_run_roundtrip(client):
    csv = ("asset_id,asset_tag,hostname,asset_type,business_unit,owner_role,criticality,internet_exposed,data_classification,environment,status\n"
           "A1,UPL-0001,up,Server,Eng,Own,High,no,Internal,Prod,Active\nA2,UPL-0002,up2,Server,Eng,,High,no,Internal,Prod,Active\n").encode()
    up = client.post("/api/etl/upload", data={"dataset": "assets"}, files={"file": ("a.csv", csv)}).json()
    run = client.post("/api/etl/run", json={"dataset": "assets", "upload_id": up["upload_id"]}).json()
    assert run["loaded"] == 1 and run["rejected"] == 1
    rej = client.get(f"/api/etl/runs/{run['run_id']}/rejections").json()
    assert rej["total"] == 1 and "owner_role" in rej["items"][0]["reason"]


def test_data_sources_label_public_vs_synthetic(client):
    items = client.get("/api/data-sources").json()["items"]
    types = {i["source_type"] for i in items}
    assert types == {"PUBLIC", "SYNTHETIC"}
