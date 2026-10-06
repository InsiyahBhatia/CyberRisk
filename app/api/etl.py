from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from app.api.common import audit, not_found, paged
from app.config import get_settings
from app.db.session import connect, current_workspace, workspace_dir, get_conn, get_engine, one, rows, scalar
from app.etl.acquisition import ADAPTERS, acquire_source
from app.etl.adapters.base import AcquireOptions
from app.etl.pipeline import DATASET_BY_NAME, run_dataset
from app.risk.service import recalculate_all

router = APIRouter(prefix="/api", tags=["etl"])
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_SUFFIX = {".csv", ".json"}
SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]")
DatasetName = Literal[tuple(DATASET_BY_NAME)]  # type: ignore[valid-type]


class RunRequest(BaseModel):
    dataset: DatasetName
    upload_id: str | None = Field(None, max_length=120)  # file name returned by /etl/upload; omitted = bundled synthetic file


class AcquireRequest(BaseModel):
    source: Literal["nvd", "cisa-kev", "mitre", "nist"]
    limit: int | None = Field(None, ge=1, le=2000)
    start_date: str | None = Field(None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str | None = Field(None, pattern=r"^\d{4}-\d{2}-\d{2}$")


@router.post("/etl/upload", status_code=201)
async def upload(dataset: DatasetName = Form(...), file: UploadFile = File(...), conn: Connection = Depends(get_conn)):
    suffix = "." + (file.filename or "").rsplit(".", 1)[-1].lower() if "." in (file.filename or "") else ""
    if suffix not in ALLOWED_SUFFIX:
        raise HTTPException(415, "Only .csv and .json files are accepted")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds 10 MB limit")
    if not data.strip():
        raise HTTPException(422, "File is empty")
    d = workspace_dir(current_workspace()) / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    name = f"{dataset}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}{suffix}"
    (d / name).write_bytes(data)
    audit(conn, "upload", "dataset", dataset, f"{SAFE_NAME.sub('_', file.filename or '')} -> {name}")
    return {"upload_id": name, "dataset": dataset, "bytes": len(data)}


@router.post("/etl/run")
def run(body: RunRequest):
    ds = DATASET_BY_NAME[body.dataset]
    if body.upload_id:
        path = workspace_dir(current_workspace()) / "uploads" / SAFE_NAME.sub("_", body.upload_id)
    else:
        path = workspace_dir(current_workspace()) / "synthetic" / ds.file
    if not path.is_file():
        raise HTTPException(404, "Input file not found; upload one first or run `python -m app.demo.setup`")
    result = run_dataset(ds, path, get_engine())
    with connect() as c2:
        recalculate_all(c2, reason=f"Recalculated after ETL run {result['run_id']}")
        audit(c2, "etl_run", "dataset", body.dataset, f"run {result['run_id']}")
    return result


@router.post("/etl/acquire")
def acquire(body: AcquireRequest):
    opts = AcquireOptions(limit=body.limit, start_date=body.start_date, end_date=body.end_date)
    return acquire_source(body.source, opts)


@router.get("/etl/runs")
def runs(status: str | None = None, page: int = 1, page_size: int = 25, conn: Connection = Depends(get_conn)):
    where, p = ("WHERE status=:s", {"s": status.upper()}) if status else ("", {})
    sel = f"""SELECT id, source_name, source_version, source_checksum, retrieval_timestamp, started_at, completed_at, records_read, records_valid,
                     records_rejected, records_loaded, duplicates_removed, quality_score, status, error_message,
                     ROUND((julianday(completed_at) - julianday(started_at)) * 86400, 1) AS duration_seconds FROM etl_runs {where}"""  # noqa: S608
    return paged(conn, sel, f"SELECT COUNT(*) FROM etl_runs {where}", p, {"id": "id", "started_at": "started_at", "quality_score": "quality_score"},  # noqa: S608
                 "id", "desc", page, page_size, "id")


@router.get("/etl/runs/{run_id}")
def run_detail(run_id: int, conn: Connection = Depends(get_conn)):
    r = one(conn, "SELECT * FROM etl_runs WHERE id=:i", i=run_id)
    if not r:
        raise not_found("ETL run")
    return r


@router.get("/etl/runs/{run_id}/rejections")
def rejections(run_id: int, page: int = 1, page_size: int = 50, conn: Connection = Depends(get_conn)):
    if not scalar(conn, "SELECT 1 FROM etl_runs WHERE id=:i", i=run_id):
        raise not_found("ETL run")
    return paged(conn, "SELECT id, source_row, reason, raw_payload FROM etl_rejections WHERE etl_run_id=:r",
                 "SELECT COUNT(*) FROM etl_rejections WHERE etl_run_id=:r", {"r": run_id}, {"id": "id"}, "id", "asc", page, page_size, "id")


@router.get("/data-sources")
def data_sources(conn: Connection = Depends(get_conn)):
    """Source registry with provenance. Freshness is the last successful acquisition time, not a real-time claim."""
    return {"items": rows(conn, """SELECT source_name, publisher, source_type, official_url, acquisition_method, license_notes, retrieval_timestamp,
                                          dataset_version, checksum, record_count, last_successful_run, status, from_cache, last_error
                                   FROM source_registry ORDER BY source_type DESC, source_name""")}


# ------------------------------------------------------------------ bring-your-own-dataset wizard
from fastapi.responses import PlainTextResponse  # noqa: E402

from app.etl import mapping as etl_mapping  # noqa: E402


class SuggestRequest(BaseModel):
    upload_id: str = Field(max_length=120)
    dataset: DatasetName


class MappedRunRequest(BaseModel):
    upload_id: str = Field(max_length=120)
    dataset: DatasetName
    mapping: dict[str, str | None]


def _upload_path(upload_id: str):
    p = workspace_dir(current_workspace()) / "uploads" / SAFE_NAME.sub("_", upload_id)
    if not p.is_file():
        raise HTTPException(404, "Uploaded file not found; upload it again")
    return p


@router.get("/etl/datasets")
def etl_datasets():
    return {"items": [{"dataset": d, "fields": [{"name": f.name, "required": f.required, "default": f.default, "kind": f.kind, "example": f.example} for f in fields]}
                      for d, fields in etl_mapping.SPECS.items()]}


@router.get("/etl/templates/{dataset}", response_class=PlainTextResponse)
def etl_template(dataset: DatasetName):
    return PlainTextResponse(etl_mapping.template_csv(dataset), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{dataset}_template.csv"'})


@router.post("/etl/profile", status_code=201)
async def etl_profile(file: UploadFile = File(...), conn: Connection = Depends(get_conn)):
    """Step 1 of the import wizard: store the file, profile its columns, and rank which dataset type it most resembles."""
    suffix = "." + (file.filename or "").rsplit(".", 1)[-1].lower() if "." in (file.filename or "") else ""
    if suffix not in ALLOWED_SUFFIX:
        raise HTTPException(415, "Only .csv and .json files are accepted")
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds 10 MB limit")
    if not data.strip():
        raise HTTPException(422, "File is empty")
    d = workspace_dir(current_workspace()) / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    name = f"import_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}{suffix}"
    path = d / name
    path.write_bytes(data)
    try:
        df = etl_mapping.load_upload(path)
    except Exception:
        path.unlink(missing_ok=True)
        raise HTTPException(422, "Could not parse the file as a table (check delimiter / JSON records)")
    if df.empty or len(df.columns) < 2:
        path.unlink(missing_ok=True)
        raise HTTPException(422, "File has no rows or fewer than two columns")
    cols = [str(c) for c in df.columns]
    audit(conn, "profile_upload", "file", name, f"{len(df)} rows, {len(cols)} columns")
    return {"upload_id": name, "rows": len(df), "columns": etl_mapping.profile(df), "sample_rows": df.head(5).astype(str).to_dict("records"),
            "dataset_guesses": etl_mapping.detect_dataset(cols)[:4]}


@router.post("/etl/mapping/suggest")
def etl_suggest(body: SuggestRequest):
    df = etl_mapping.load_upload(_upload_path(body.upload_id))
    return etl_mapping.suggest([str(c) for c in df.columns], body.dataset)


@router.post("/etl/run-mapped")
def etl_run_mapped(body: MappedRunRequest):
    """Step 3: apply the user-confirmed mapping, write the canonical file, and run the standard validated ETL."""
    src = _upload_path(body.upload_id)
    df = etl_mapping.load_upload(src)
    try:
        mapped = etl_mapping.apply_mapping(df, body.dataset, body.mapping)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    spec = etl_mapping.SPECS[body.dataset]
    missing = [f.name for f in spec if f.required and not f.default and not body.mapping.get(f.name)]
    if missing:
        raise HTTPException(422, f"Required fields without a source column: {missing}")
    out = src.with_name(f"{body.dataset}_mapped_{datetime.now(timezone.utc).strftime('%H%M%S%f')}.csv")
    mapped.to_csv(out, index=False)
    result = run_dataset(DATASET_BY_NAME[body.dataset], out, get_engine())
    with connect() as c2:
        recalculate_all(c2, reason=f"Recalculated after import run {result['run_id']}")
        audit(c2, "import_mapped", "dataset", body.dataset, f"run {result['run_id']} from {body.upload_id}")
    return {**result, "mapping_used": {k: v for k, v in body.mapping.items() if v}, "defaults_applied": [f.name for f in spec if not body.mapping.get(f.name)]}
