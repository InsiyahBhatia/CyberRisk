"""Source registry + ETL run bookkeeping (provenance is never silently discarded)."""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import Connection

from app.db.session import execute, one, scalar
from app.etl.adapters.base import utcnow


def ensure_data_source(conn: Connection, name: str, source_type: str, file_name: str | None = None) -> int:
    execute(conn, """INSERT INTO data_sources (source_name, source_type, file_name, ingestion_status)
                     VALUES (:n, :t, :f, 'PENDING') ON CONFLICT(source_name) DO NOTHING""",
            n=name, t=source_type, f=file_name)
    return scalar(conn, "SELECT id FROM data_sources WHERE source_name = :n", n=name)


def ensure_registry(conn: Connection, *, name: str, publisher: str, source_type: str, official_url: str,
                    method: str, license_notes: str) -> None:
    execute(conn, """INSERT INTO source_registry (source_name, publisher, source_type, official_url, acquisition_method, license_notes)
                     VALUES (:n,:p,:t,:u,:m,:l)
                     ON CONFLICT(source_name) DO UPDATE SET publisher=:p, official_url=:u, acquisition_method=:m, license_notes=:l""",
            n=name, p=publisher, t=source_type, u=official_url, m=method, l=license_notes)


def registry_success(conn: Connection, name: str, *, retrieved_at: str, version: str | None, checksum: str,
                     records: int, from_cache: bool) -> None:
    execute(conn, """UPDATE source_registry SET retrieval_timestamp=:ts, dataset_version=:v, checksum=:c, record_count=:r,
                     last_successful_run=:now, status=:st, from_cache=:fc, last_error=NULL WHERE source_name=:n""",
            ts=retrieved_at, v=version, c=checksum, r=records, now=utcnow(),
            st="CACHED" if from_cache else "HEALTHY", fc=int(from_cache), n=name)


def registry_failure(conn: Connection, name: str, error: str) -> None:
    """Mark failed/stale; previous valid data and its metadata are left untouched."""
    execute(conn, "UPDATE source_registry SET status='FAILED', last_error=:e WHERE source_name=:n", e=error[:500], n=name)


def start_run(conn: Connection, *, source_id: int | None, name: str, version: str | None, checksum: str | None,
              retrieved_at: str | None) -> int:
    res = execute(conn, """INSERT INTO etl_runs (source_id, source_name, source_version, source_checksum, retrieval_timestamp, started_at, status)
                           VALUES (:sid,:n,:v,:c,:r,:s,'RUNNING')""",
                  sid=source_id, n=name, v=version, c=checksum, r=retrieved_at, s=utcnow())
    return res.lastrowid


def finish_run(conn: Connection, run_id: int, *, read: int, valid: int, rejected: int, loaded: int, duplicates: int,
               quality: float, status: str = "SUCCESS", error: str | None = None) -> None:
    execute(conn, """UPDATE etl_runs SET completed_at=:c, records_read=:r, records_valid=:v, records_rejected=:rej,
                     records_loaded=:l, duplicates_removed=:d, quality_score=:q, status=:s, error_message=:e WHERE id=:id""",
            c=utcnow(), r=read, v=valid, rej=rejected, l=loaded, d=duplicates, q=quality, s=status, e=error, id=run_id)


def log_rejections(conn: Connection, run_id: int, rejected: list[tuple[int, str, Any]]) -> None:
    for row, reason, payload in rejected:
        execute(conn, "INSERT INTO etl_rejections (etl_run_id, source_row, reason, raw_payload) VALUES (:r,:row,:why,:p)",
                r=run_id, row=row, why=reason, p=json.dumps(payload, default=str)[:4000])


def fail_run(conn: Connection, run_id: int, error: str) -> None:
    finish_run(conn, run_id, read=0, valid=0, rejected=0, loaded=0, duplicates=0, quality=0.0, status="FAILED", error=error[:500])


def source_status(conn: Connection, name: str) -> dict | None:
    return one(conn, "SELECT * FROM source_registry WHERE source_name=:n", n=name)
