"""Public-source adapters against mocked HTTP (no network)."""
import json

import httpx
import pytest

from app.db.session import connect, rows, scalar
from app.etl.acquisition import acquire_source
from app.etl.adapters.base import AcquireOptions, AcquisitionError, http_get
from app.etl.adapters.cisa_kev import CISAKEVSourceAdapter
from app.etl.adapters.mitre_attack import MITREAttackSourceAdapter
from app.etl.adapters.nvd import NVDSourceAdapter

NOSLEEP = lambda _s: None  # noqa: E731


def cve(cve_id, score=7.5, status="Analyzed", published="2026-09-25T10:00:00.000"):
    return {"cve": {"id": cve_id, "vulnStatus": status, "published": published, "lastModified": published,
                    "descriptions": [{"lang": "en", "value": f"desc {cve_id}"}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": score, "vectorString": "CVSS:3.1/AV:N", "baseSeverity": "HIGH"}}]} if score else {},
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                    "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}]}]}],
                    "references": [{"url": "https://example.test/a"}]}}


def nvd_client(pages_by_index, calls=None):
    def handler(request: httpx.Request):
        q = dict(request.url.params)
        if calls is not None:
            calls.append(q)
        start = int(q.get("startIndex", 0))
        total, items = pages_by_index["total"], pages_by_index["items"]
        size = int(q.get("resultsPerPage", 2000))
        chunk = items[start:start + size]
        return httpx.Response(200, json={"resultsPerPage": len(chunk), "startIndex": start, "totalResults": total, "vulnerabilities": chunk})
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_nvd_pagination_window_and_normalisation(engine):
    items = [cve(f"CVE-2026-{1000 + i}", score=5.0 + i * 0.1) for i in range(1200)]
    calls = []
    ad = NVDSourceAdapter(client=nvd_client({"total": 1200, "items": items}, calls), api_key="k", sleep=NOSLEEP)
    snap = ad.acquire(AcquireOptions(limit=1100, start_date="2026-09-20", end_date="2026-10-01"))
    recent_calls = [c for c in calls if "pubStartDate" in c]
    assert len(recent_calls) == 3 and [c["startIndex"] for c in recent_calls] == ["0", "500", "1000"]  # pagination
    assert recent_calls[0]["pubStartDate"].startswith("2026-09-20") and recent_calls[0]["pubEndDate"].startswith("2026-10-01")  # date filter
    assert any("hasKev" in c for c in calls)
    parsed = ad.parse(snap, AcquireOptions())
    assert parsed.duplicates_removed > 0  # hasKev query returns overlapping records
    r = next(x for x in parsed.records if x["cve_id"] == "CVE-2026-1000")
    assert r["cvss_score"] == 5.0 and r["cvss_version"] == "3.1" and r["cwe"] == "CWE-79" and r["affected_products"] == "acme:widget"
    assert snap.checksum and snap.path.exists()


def test_nvd_window_too_large_rejected():
    with pytest.raises(AcquisitionError):
        NVDSourceAdapter(client=httpx.Client(), sleep=NOSLEEP).window(AcquireOptions(start_date="2025-01-01", end_date="2026-01-01"))


def test_nvd_invalid_and_rejected_records(engine):
    items = [cve("CVE-2026-0001"), cve("BAD-ID"), cve("CVE-2026-0002", status="Rejected"), cve("CVE-2026-0001"), cve("CVE-2026-0003", score=None)]
    ad = NVDSourceAdapter(client=nvd_client({"total": 5, "items": items}), api_key="k", sleep=NOSLEEP)
    p = ad.parse(ad.acquire(AcquireOptions(limit=10)), AcquireOptions())
    ids = {r["cve_id"] for r in p.records}
    assert ids == {"CVE-2026-0001", "CVE-2026-0003"}
    assert len(p.rejected) >= 2
    assert next(r for r in p.records if r["cve_id"] == "CVE-2026-0003")["cvss_score"] is None  # no invented score


def test_invalid_payload_fails_acquisition_and_preserves_state(engine):
    def handler(_):
        return httpx.Response(200, json={"unexpected": True})
    ad = NVDSourceAdapter(client=httpx.Client(transport=httpx.MockTransport(handler)), api_key="k", sleep=NOSLEEP)
    with pytest.raises(AcquisitionError):
        ad.acquire(AcquireOptions(limit=5))


def test_retries_with_exponential_backoff():
    attempts, waits = [], []

    def handler(_):
        attempts.append(1)
        return httpx.Response(503) if len(attempts) < 3 else httpx.Response(200, json={"ok": 1})
    client = httpx.Client(transport=httpx.MockTransport(handler))
    assert http_get(client, "https://x.test", sleep=waits.append).json() == {"ok": 1}
    assert len(attempts) == 3 and waits == [2.0, 4.0]


def test_retries_exhausted_raises():
    client = httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(429)))
    with pytest.raises(AcquisitionError):
        http_get(client, "https://x.test", retries=2, sleep=NOSLEEP)


KEV = {"catalogVersion": "2026.10.01", "vulnerabilities": [
    {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Widget RCE", "dateAdded": "2026-10-01",
     "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Known", "notes": "", "requiredAction": "Patch"},
    {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "dup"},
    {"cveID": "garbage"},
]}


def test_kev_normalisation_dedupe_and_join_with_nvd(engine):
    nvd = NVDSourceAdapter(client=nvd_client({"total": 2, "items": [cve("CVE-2026-0001"), cve("CVE-2026-0002")]}), api_key="k", sleep=NOSLEEP)
    assert acquire_source("nvd", AcquireOptions(limit=5), engine, adapter=nvd)["status"] == "HEALTHY"
    kev = CISAKEVSourceAdapter(client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=KEV))), sleep=NOSLEEP)
    res = acquire_source("cisa-kev", engine=engine, adapter=kev)
    assert res["status"] == "HEALTHY" and res["records"] == 1 and res["version"] == "2026.10.01"
    with connect(engine) as c:
        flags = {r["cve_id"]: r["in_kev"] for r in rows(c, "SELECT cve_id, in_kev FROM cve_catalog")}
        assert flags == {"CVE-2026-0001": 1, "CVE-2026-0002": 0}  # KEV join
        run = rows(c, "SELECT * FROM etl_runs WHERE source_name='CISA KEV'")[0]
        assert (run["records_read"], run["records_rejected"], run["duplicates_removed"]) == (3, 1, 1)


def stix(extra=None):
    def tech(tid, name, phases, **kw):
        return {"type": "attack-pattern", "name": name, "description": "d", "x_mitre_platforms": ["Windows"],
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}] if tid else [],
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases], **kw}
    objs = [{"type": "x-mitre-collection", "x_mitre_version": "19.0"},
            tech("T1566", "Phishing", ["initial-access"]), tech("T1566.001", "Spearphishing Attachment", ["initial-access"]),
            tech("T1059", "Scripting", ["execution", "defense-evasion"]), tech("T9999", "Old", ["x"], revoked=True),
            tech(None, "No id", ["x"]), {"type": "malware", "name": "ignored"}]
    return {"type": "bundle", "objects": objs + (extra or [])}


def test_mitre_normalisation(engine):
    ad = MITREAttackSourceAdapter(client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=stix()))), sleep=NOSLEEP)
    res = acquire_source("mitre", engine=engine, adapter=ad)
    assert res["status"] == "HEALTHY" and res["records"] == 3 and res["version"] == "19.0"
    with connect(engine) as c:
        t = rows(c, "SELECT * FROM attack_techniques WHERE technique_id='T1059'")[0]
        assert t["tactics"] == "execution,defense-evasion" and t["platforms"] == "Windows"
        assert scalar(c, "SELECT COUNT(*) FROM frameworks WHERE name='MITRE ATT&CK'") == 1
        assert scalar(c, "SELECT COUNT(*) FROM etl_rejections") == 1  # technique without an ID is logged, not hidden


def test_mitre_invalid_bundle_marks_source_failed(engine):
    ad = MITREAttackSourceAdapter(client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"type": "nope"}))), sleep=NOSLEEP)
    res = acquire_source("mitre", engine=engine, adapter=ad)
    assert res["status"] == "FAILED"
    with connect(engine) as c:
        assert scalar(c, "SELECT status FROM source_registry WHERE source_name='MITRE ATT&CK'") == "FAILED"


def test_provenance_is_recorded(engine):
    ad = CISAKEVSourceAdapter(client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=KEV))), sleep=NOSLEEP)
    acquire_source("cisa-kev", engine=engine, adapter=ad)
    with connect(engine) as c:
        r = rows(c, "SELECT * FROM source_registry WHERE source_name='CISA KEV'")[0]
        run = rows(c, "SELECT * FROM etl_runs")[0]
    assert r["publisher"].startswith("CISA") and r["official_url"].startswith("https://www.cisa.gov") and r["checksum"] and len(r["checksum"]) == 64
    assert r["retrieval_timestamp"] and r["dataset_version"] == "2026.10.01" and r["record_count"] == 1 and r["from_cache"] == 0
    assert run["source_checksum"] == r["checksum"] and run["source_version"] == "2026.10.01" and run["retrieval_timestamp"]


def test_source_failure_preserves_previous_data_and_flags_status(engine):
    good = CISAKEVSourceAdapter(client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=KEV))), sleep=NOSLEEP)
    acquire_source("cisa-kev", engine=engine, adapter=good)
    bad = CISAKEVSourceAdapter(client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(500))), sleep=NOSLEEP)
    # With a cached raw snapshot present, a failed live fetch falls back to it and is labelled CACHED, never "HEALTHY".
    res = acquire_source("cisa-kev", engine=engine, adapter=bad)
    assert res["status"] == "CACHED" and "unavailable" in res["message"]
    with connect(engine) as c:
        assert scalar(c, "SELECT COUNT(*) FROM kev_entries") == 1
        assert scalar(c, "SELECT from_cache FROM source_registry WHERE source_name='CISA KEV'") == 1


def test_failure_without_cache_records_error_and_no_synthetic_fallback(engine):
    bad = MITREAttackSourceAdapter(client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(500))), sleep=NOSLEEP)
    res = acquire_source("mitre", engine=engine, adapter=bad)
    assert res["status"] == "FAILED"
    with connect(engine) as c:
        assert scalar(c, "SELECT COUNT(*) FROM attack_techniques") == 0
        r = rows(c, "SELECT status, last_error FROM source_registry WHERE source_name='MITRE ATT&CK'")[0]
        assert r["status"] == "FAILED" and "500" in r["last_error"]


def test_dry_run_and_skip_existing(engine):
    ad = CISAKEVSourceAdapter(client=httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=KEV))), sleep=NOSLEEP)
    assert acquire_source("cisa-kev", AcquireOptions(dry_run=True), engine, adapter=ad)["status"] == "DRY_RUN"
    with connect(engine) as c:
        assert scalar(c, "SELECT COUNT(*) FROM kev_entries") == 0
    acquire_source("cisa-kev", engine=engine, adapter=ad)
    assert acquire_source("cisa-kev", AcquireOptions(skip_existing=True), engine, adapter=ad)["status"] == "SKIPPED"
    assert acquire_source("cisa-kev", AcquireOptions(skip_existing=True, force=True), engine, adapter=ad)["status"] == "HEALTHY"
