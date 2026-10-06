"""Common source-adapter interface for public data acquisition."""
from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import httpx

from app.config import get_settings


class AcquisitionError(RuntimeError):
    """Raised when an official source cannot be acquired or fails validation."""


@dataclass
class AcquireOptions:
    limit: int | None = None
    start_date: str | None = None  # YYYY-MM-DD
    end_date: str | None = None
    force: bool = False
    skip_existing: bool = False
    dry_run: bool = False
    offline: bool = False  # use cached raw snapshots only (clearly flagged as cached)


@dataclass
class Snapshot:
    path: Path
    checksum: str
    retrieved_at: str
    version: str | None = None
    from_cache: bool = False


@dataclass
class ParseResult:
    records: list[dict] = field(default_factory=list)
    rejected: list[tuple[int, str, Any]] = field(default_factory=list)  # (row, reason, payload)
    duplicates_removed: int = 0
    records_read: int = 0


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def raw_dir(name: str) -> Path:
    d = get_settings().data_dir / "raw" / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def latest_cached(directory: Path, pattern: str) -> Path | None:
    files = sorted(directory.glob(pattern))
    return files[-1] if files else None


def http_get(
    client: httpx.Client,
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    retries: int = 4,
    backoff: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
) -> httpx.Response:
    """GET with exponential backoff on 403/429/5xx and transport errors."""
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            resp = client.get(url, params=params, headers=headers)
            if resp.status_code in (403, 429) or resp.status_code >= 500:
                last = AcquisitionError(f"HTTP {resp.status_code} from {url}")
            else:
                resp.raise_for_status()
                return resp
        except httpx.TransportError as exc:
            last = exc
        if attempt < retries:
            sleep(backoff * (2**attempt))
    raise AcquisitionError(f"Request failed after {retries + 1} attempts: {last}")


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class SourceAdapter(ABC):
    name: str
    publisher: str
    official_url: str
    acquisition_method: str
    license_notes: str
    source_type = "PUBLIC"
    needs_network = True
    raw_subdir: str

    def __init__(self, client: httpx.Client | None = None, sleep: Callable[[float], None] = time.sleep):
        self._client = client
        self._sleep = sleep

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=120, follow_redirects=True, headers={"User-Agent": "CyberRisk/1.0"})
        return self._client

    @abstractmethod
    def acquire(self, opts: AcquireOptions) -> Snapshot:
        """Fetch the official source and store the raw snapshot (never overwrite old ones)."""

    @abstractmethod
    def parse(self, snapshot: Snapshot, opts: AcquireOptions) -> ParseResult:
        """Validate the raw payload and normalise records."""

    def cached_snapshot(self) -> Snapshot | None:
        """Most recent raw snapshot on disk, flagged as cached."""
        return None
