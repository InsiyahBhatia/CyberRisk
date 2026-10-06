"""Public-source acquisition orchestration: official source -> raw snapshot -> validate -> normalise -> dedupe -> SQLite."""
from __future__ import annotations

from typing import Callable

from sqlalchemy import Connection
from sqlalchemy.engine import Engine

from app.db.session import connect, execute, get_engine
from app.etl import provenance as prov
from app.etl.adapters.base import AcquireOptions, AcquisitionError, ParseResult, Snapshot, SourceAdapter
from app.etl.adapters.cisa_kev import CISAKEVSourceAdapter
from app.etl.adapters.mitre_attack import MITREAttackSourceAdapter
from app.etl.adapters.nist_csf import NISTFrameworkSourceAdapter
from app.etl.adapters.nvd import NVDSourceAdapter
from app.etl.quality import quality_score

ADAPTERS: dict[str, type[SourceAdapter]] = {
    "nvd": NVDSourceAdapter,
    "cisa-kev": CISAKEVSourceAdapter,
    "mitre": MITREAttackSourceAdapter,
    "nist": NISTFrameworkSourceAdapter,
}
ORDER = ["nist", "cisa-kev", "nvd", "mitre"]


# ---- loaders (upserts; never delete existing valid data) ------------------
def load_cves(conn: Connection, records: list[dict]) -> int:
    for r in records:
        execute(conn, """INSERT INTO cve_catalog (cve_id, description, published_at, last_modified_at, cvss_version, cvss_score,
                            cvss_vector, severity, cwe, affected_products, reference_urls)
                         VALUES (:cve_id,:description,:published_at,:last_modified_at,:cvss_version,:cvss_score,:cvss_vector,
                                 :severity,:cwe,:affected_products,:reference_urls)
                         ON CONFLICT(cve_id) DO UPDATE SET description=excluded.description, last_modified_at=excluded.last_modified_at,
                            cvss_version=excluded.cvss_version, cvss_score=excluded.cvss_score, cvss_vector=excluded.cvss_vector,
                            severity=excluded.severity, cwe=excluded.cwe, affected_products=excluded.affected_products,
                            reference_urls=excluded.reference_urls""", **r)
    link_kev(conn)
    return len(records)


def load_kev(conn: Connection, records: list[dict]) -> int:
    for r in records:
        execute(conn, """INSERT INTO kev_entries (cve_id, vendor_project, product, vulnerability_name, date_added, due_date,
                            known_ransomware_use, notes, required_action)
                         VALUES (:cve_id,:vendor_project,:product,:vulnerability_name,:date_added,:due_date,:known_ransomware_use,:notes,:required_action)
                         ON CONFLICT(cve_id) DO UPDATE SET vendor_project=excluded.vendor_project, product=excluded.product,
                            vulnerability_name=excluded.vulnerability_name, date_added=excluded.date_added, due_date=excluded.due_date,
                            known_ransomware_use=excluded.known_ransomware_use, notes=excluded.notes, required_action=excluded.required_action""", **r)
    link_kev(conn)
    return len(records)


def link_kev(conn: Connection) -> None:
    """Enrichment: flag catalog CVEs and organisational findings that appear in CISA KEV."""
    execute(conn, "UPDATE cve_catalog SET in_kev = CASE WHEN cve_id IN (SELECT cve_id FROM kev_entries) THEN 1 ELSE 0 END")
    execute(conn, "UPDATE vulnerabilities SET known_exploited = CASE WHEN cve_id IN (SELECT cve_id FROM kev_entries) THEN 1 ELSE 0 END")


def load_attack(conn: Connection, records: list[dict]) -> int:
    version = records[0]["version"] if records else None
    execute(conn, """INSERT INTO frameworks (name, version, description, source_reference)
                     VALUES ('MITRE ATT&CK', :v, 'MITRE ATT&CK Enterprise adversary techniques (threat context, not a control framework).', 'https://attack.mitre.org/')
                     ON CONFLICT(name) DO UPDATE SET version=excluded.version""", v=version)
    for r in records:
        execute(conn, """INSERT INTO attack_techniques (technique_id, name, tactics, description, platforms, version)
                         VALUES (:technique_id,:name,:tactics,:description,:platforms,:version)
                         ON CONFLICT(technique_id) DO UPDATE SET name=excluded.name, tactics=excluded.tactics,
                            description=excluded.description, platforms=excluded.platforms, version=excluded.version""", **r)
    return len(records)


def load_frameworks(conn: Connection, records: list[dict]) -> int:
    for r in records:
        execute(conn, """INSERT INTO frameworks (name, version, description, source_reference) VALUES (:framework,:framework_version,:framework_description,:source_reference)
                         ON CONFLICT(name) DO UPDATE SET version=excluded.version, description=excluded.description, source_reference=excluded.source_reference""", **r)
        execute(conn, """INSERT INTO controls (control_code, framework_id, title, description, category)
                         VALUES (:control_code, (SELECT id FROM frameworks WHERE name=:framework), :title, :description, :category)
                         ON CONFLICT(framework_id, control_code) DO UPDATE SET title=excluded.title,
                            description=excluded.description, category=excluded.category""", **r)
    return len(records)


LOADERS: dict[str, Callable[[Connection, list[dict]], int]] = {
    "nvd": load_cves, "cisa-kev": load_kev, "mitre": load_attack, "nist": load_frameworks,
}


def acquire_source(key: str, opts: AcquireOptions | None = None, engine: Engine | None = None,
                   adapter: SourceAdapter | None = None) -> dict:
    """Acquire one public source. Always returns a status dict; never raises for source failures."""
    opts = opts or AcquireOptions()
    engine = engine or get_engine()
    ad = adapter or ADAPTERS[key]()
    summary: dict = {"source": key, "name": ad.name, "status": "FAILED", "records": 0, "message": ""}

    with connect(engine) as conn:
        prov.ensure_registry(conn, name=ad.name, publisher=ad.publisher, source_type=ad.source_type,
                             official_url=ad.official_url, method=ad.acquisition_method, license_notes=ad.license_notes)
        source_id = prov.ensure_data_source(conn, ad.name, "PUBLIC")
        existing = prov.source_status(conn, ad.name)

    if opts.skip_existing and not opts.force and existing and existing["status"] in ("HEALTHY", "CACHED"):
        return {**summary, "status": "SKIPPED", "records": existing["record_count"], "message": "already acquired (--skip-existing)"}
    if opts.dry_run:
        return {**summary, "status": "DRY_RUN", "message": f"would acquire {ad.name} via {ad.acquisition_method} from {ad.official_url}"}

    snapshot: Snapshot | None = None
    acquire_error = ""
    try:
        if opts.offline and ad.needs_network:
            raise AcquisitionError("offline mode requested")
        snapshot = ad.acquire(opts)
    except (AcquisitionError, OSError) as exc:
        acquire_error = str(exc)
        snapshot = ad.cached_snapshot()  # fall back to a previously preserved raw snapshot, clearly flagged

    if snapshot is None:
        with connect(engine) as conn:
            prov.registry_failure(conn, ad.name, acquire_error)
        return {**summary, "message": f"acquisition failed and no cached snapshot exists: {acquire_error}"}

    try:
        parsed: ParseResult = ad.parse(snapshot, opts)
    except (AcquisitionError, ValueError, KeyError) as exc:
        with connect(engine) as conn:
            prov.registry_failure(conn, ad.name, f"payload validation failed: {exc}")
        return {**summary, "message": f"payload validation failed: {exc}"}

    with connect(engine) as conn:
        run_id = prov.start_run(conn, source_id=source_id, name=ad.name, version=snapshot.version,
                                checksum=snapshot.checksum, retrieved_at=snapshot.retrieved_at)
        prov.log_rejections(conn, run_id, parsed.rejected)
        loaded = LOADERS[key](conn, parsed.records)
        q = quality_score(parsed.records_read, invalid=len(parsed.rejected), duplicates=parsed.duplicates_removed)
        prov.finish_run(conn, run_id, read=parsed.records_read, valid=len(parsed.records), rejected=len(parsed.rejected),
                        loaded=loaded, duplicates=parsed.duplicates_removed, quality=q["score"])
        prov.registry_success(conn, ad.name, retrieved_at=snapshot.retrieved_at, version=snapshot.version,
                              checksum=snapshot.checksum, records=loaded, from_cache=snapshot.from_cache)
        execute(conn, "UPDATE data_sources SET ingestion_status=:s, last_run=:t, file_name=:f WHERE id=:id",
                s="CACHED" if snapshot.from_cache else "HEALTHY", t=snapshot.retrieved_at, f=snapshot.path.name, id=source_id)

    msg = f"{loaded} records loaded"
    if snapshot.from_cache:
        msg = f"Live acquisition unavailable ({acquire_error}); loaded from cached snapshot. {msg}"
    return {**summary, "status": "CACHED" if snapshot.from_cache else "HEALTHY", "records": loaded,
            "message": msg, "quality": q["score"], "checksum": snapshot.checksum, "version": snapshot.version}


def acquire_all(opts: AcquireOptions | None = None, engine: Engine | None = None) -> list[dict]:
    return [acquire_source(k, opts, engine) for k in ORDER]
