import json
from datetime import date

import pytest

from app.config import get_settings
from app.db.session import connect, rows, scalar
from app.etl.pipeline import DATASET_BY_NAME, run_dataset
from app.etl.quality import quality_score

ASSET_HEADER = "asset_id,asset_tag,hostname,asset_type,business_unit,owner_role,criticality,internet_exposed,data_classification,environment,status\n"
VULN_HEADER = "cve_id,asset_tag,scanner_cvss,exploitability,status,discovered_at,due_date,resolved_at\n"


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_quality_score_formula():
    q = quality_score(100, missing=2, invalid=4, duplicates=10, orphans=1)
    assert q["score"] == pytest.approx(100 - 2 - 4 - 5 - 1)
    assert quality_score(0)["score"] == 0
    assert quality_score(10, invalid=10, missing=10)["score"] == 0  # clamped


def test_asset_normalisation_validation_dedupe_and_rejection_logging(engine, tmp_path):
    p = write(tmp_path, "assets.csv", ASSET_HEADER +
              "A1,web-01,web-01,Server,Engineering,Ops Lead,Critical,yes,Internal,Production,Active\n"
              "A1,WEB-01,web-01,Server,Engineering,Ops Lead,CRITICAL,YES,Internal,Production,active\n"  # duplicate after normalisation
              "A2,db-01,db-01,Database,Finance,,High,no,Restricted,Production,Active\n"                # missing owner
              "A3,app-01,app-01,Web Application,Sales,Ops Lead,Banana,no,Internal,Production,Active\n"  # invalid enum
              "A4,net-01,net-01,Network Device,IT,Ops Lead,Low,perhaps,Internal,Production,Active\n")  # invalid bool
    res = run_dataset(DATASET_BY_NAME["assets"], p, engine)
    assert (res["read"], res["loaded"], res["rejected"], res["duplicates"]) == (5, 1, 3, 1)
    with connect(engine) as c:
        a = rows(c, "SELECT * FROM assets")
        assert len(a) == 1 and a[0]["asset_tag"] == "WEB-01" and a[0]["criticality"] == "CRITICAL" and a[0]["internet_exposed"] == 1
        rej = rows(c, "SELECT * FROM etl_rejections WHERE etl_run_id=:r ORDER BY source_row", r=res["run_id"])
        assert [r["source_row"] for r in rej] == [4, 5, 6]
        assert "missing" in rej[0]["reason"] and "owner_role" in rej[0]["reason"]
        assert json.loads(rej[0]["raw_payload"])["asset_tag"] == "db-01"  # raw payload preserved
        run = rows(c, "SELECT * FROM etl_runs WHERE id=:r", r=res["run_id"])[0]
        assert run["records_read"] == run["records_valid"] + run["records_rejected"] + run["duplicates_removed"]
        assert run["source_checksum"] and run["status"] == "SUCCESS"
    assert res["quality_score"] < 100


def test_no_row_is_silently_dropped(engine, tmp_path):
    p = write(tmp_path, "assets.csv", ASSET_HEADER + "".join(
        f"A{i},t-{i % 3},h,Server,BU,Own,{'Low' if i % 4 else 'bogus'},no,x,Prod,Active\n" for i in range(20)))
    r = run_dataset(DATASET_BY_NAME["assets"], p, engine)
    assert r["read"] == r["loaded"] + r["rejected"] + r["duplicates"]


def test_vulnerability_rules_referential_integrity_and_cvss(engine, tmp_path):
    run_dataset(DATASET_BY_NAME["assets"], write(tmp_path, "assets.csv", ASSET_HEADER +
                "A1,web-01,w,Server,Eng,Own,Critical,yes,Internal,Production,Active\n"), engine)
    with connect(engine) as c:
        c.exec_driver_sql("INSERT INTO cve_catalog (cve_id, cvss_score, in_kev, description) VALUES ('CVE-2024-0001', 9.8, 1, 'catalog desc')")
    p = write(tmp_path, "vuln.csv", VULN_HEADER +
              "CVE-2024-0001,web-01,5.0,High,open,2026-09-01,2026-09-15,\n"       # valid; NVD CVSS overrides scanner value
              "cve-2024-0001,WEB-01,5.0,High,Open,2026-09-01,2026-09-15,\n"       # duplicate after normalisation
              "CVE-2024-0002,web-01,N/A,High,open,2026-09-01,2026-09-15,\n"       # malformed CVSS
              "CVE-2024-0003,web-01,11.7,High,open,2026-09-01,2026-09-15,\n"      # CVSS out of range
              "CVE-2024-0004,ghost,6.0,High,open,2026-09-01,2026-09-15,\n"        # orphan asset
              "NOT-A-CVE,web-01,6.0,High,open,2026-09-01,2026-09-15,\n"           # bad CVE id
              "CVE-2024-0005,web-01,4.5,Low,closed,2026-09-01,2026-09-15,2026-09-03\n")  # alias closed -> RESOLVED
    r = run_dataset(DATASET_BY_NAME["vulnerability_scan"], p, engine)
    assert (r["loaded"], r["rejected"], r["duplicates"]) == (2, 4, 1)
    with connect(engine) as c:
        v = {x["cve_id"]: x for x in rows(c, "SELECT * FROM vulnerabilities")}
        assert v["CVE-2024-0001"]["cvss_score"] == 9.8 and v["CVE-2024-0001"]["severity"] == "CRITICAL"
        assert v["CVE-2024-0001"]["known_exploited"] == 1 and v["CVE-2024-0001"]["status"] == "OPEN"
        assert v["CVE-2024-0005"]["status"] == "RESOLVED"
        reasons = [x["reason"] for x in rows(c, "SELECT reason FROM etl_rejections")]
        assert sum("[orphan]" in x for x in reasons) == 1 and sum("[invalid]" in x for x in reasons) == 3


def test_json_adapter(engine, tmp_path):
    p = tmp_path / "assets.json"
    p.write_text(json.dumps([{"asset_id": "A1", "asset_tag": "x-1", "hostname": "x", "asset_type": "Server", "business_unit": "Eng", "owner_role": "o",
                              "criticality": "low", "internet_exposed": "no", "data_classification": "Internal", "environment": "Prod", "status": "Active"}]))
    assert run_dataset(DATASET_BY_NAME["assets"], p, engine)["loaded"] == 1


def test_evidence_past_expiry_cannot_be_present(seeded):
    with connect(seeded) as c:
        bad = scalar(c, "SELECT COUNT(*) FROM evidence WHERE status='PRESENT' AND expiry_date < '2026-10-01'")
        assert bad == 0
        assert scalar(c, "SELECT COUNT(*) FROM evidence WHERE status='EXPIRED'") > 0


def test_full_synthetic_load_is_reproducible(engine, tmp_path):
    from app.demo import synthetic

    a, b = tmp_path / "a", tmp_path / "b"
    synthetic.generate(a, today=date(2026, 10, 1))
    synthetic.generate(b, today=date(2026, 10, 1))
    for f in a.glob("*.csv"):
        assert f.read_bytes() == (b / f.name).read_bytes(), f.name


def test_seeded_database_has_deliberate_quality_issues_and_no_silent_drops(seeded):
    with connect(seeded) as c:
        for r in rows(c, "SELECT * FROM etl_runs WHERE source_name LIKE 'Synthetic%'"):
            assert r["records_read"] == r["records_valid"] + r["records_rejected"] + r["duplicates_removed"], r["source_name"]
        assert scalar(c, "SELECT SUM(records_rejected) FROM etl_runs") > 10
        assert scalar(c, "SELECT SUM(duplicates_removed) FROM etl_runs") > 10
        assert scalar(c, "SELECT COUNT(*) FROM source_registry WHERE source_type='SYNTHETIC'") >= 10
    assert get_settings().data_dir.name == "data"
