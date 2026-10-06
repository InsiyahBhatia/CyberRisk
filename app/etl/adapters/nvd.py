"""NVD CVE API 2.0 adapter (pagination, date windows, retries, raw caching)."""
from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta, timezone

from app.config import get_settings
from app.etl.adapters.base import (
    AcquireOptions, AcquisitionError, ParseResult, Snapshot, SourceAdapter,
    http_get, latest_cached, raw_dir, sha256_file, utcnow, write_json,
)
from app.risk.engine import cvss_severity

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
PAGE_SIZE = 500
DEFAULT_WINDOW_DAYS = 14
MAX_WINDOW_DAYS = 120  # NVD limit for pubStartDate/pubEndDate ranges
METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _nvd_ts(d: date, end: bool = False) -> str:
    return f"{d.isoformat()}T{'23:59:59.999' if end else '00:00:00.000'}"


class NVDSourceAdapter(SourceAdapter):
    name = "NVD"
    publisher = "NIST National Vulnerability Database"
    official_url = "https://nvd.nist.gov/developers/vulnerabilities"
    acquisition_method = "NVD CVE API 2.0 (REST)"
    license_notes = "NVD data is public domain (U.S. Government). Respect API rate limits; an API key raises them."
    raw_subdir = "nvd"

    def __init__(self, *args, api_key: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.api_key = get_settings().nvd_api_key if api_key is None else api_key

    # ---- acquisition -----------------------------------------------------
    def window(self, opts: AcquireOptions) -> tuple[date, date]:
        s = get_settings()
        end_s = opts.end_date or s.nvd_end_date
        start_s = opts.start_date or s.nvd_start_date
        end = date.fromisoformat(end_s) if end_s else datetime.now(timezone.utc).date()
        start = date.fromisoformat(start_s) if start_s else end - timedelta(days=DEFAULT_WINDOW_DAYS)
        if start > end:
            raise AcquisitionError("NVD start date is after end date")
        if (end - start).days > MAX_WINDOW_DAYS:
            raise AcquisitionError(f"NVD date window may not exceed {MAX_WINDOW_DAYS} days")
        return start, end

    def _fetch_pages(self, base_params: dict, limit: int) -> list[dict]:
        headers = {"apiKey": self.api_key} if self.api_key else None
        pause = 0.6 if self.api_key else 6.0  # public rate limit: 5 req / 30 s
        pages, start_index, fetched = [], 0, 0
        while fetched < limit:
            params = {**base_params, "startIndex": start_index, "resultsPerPage": min(PAGE_SIZE, limit - fetched)}
            resp = http_get(self.client, NVD_URL, params=params, headers=headers, sleep=self._sleep)
            try:
                page = resp.json()
            except ValueError as exc:
                raise AcquisitionError(f"NVD response is not JSON: {exc}") from exc
            if "vulnerabilities" not in page or "totalResults" not in page:
                raise AcquisitionError("NVD payload missing 'vulnerabilities'/'totalResults'")
            pages.append(page)
            got = len(page["vulnerabilities"])
            fetched += got
            start_index += got
            if got == 0 or start_index >= page["totalResults"]:
                break
            self._sleep(pause)
        return pages

    def acquire(self, opts: AcquireOptions) -> Snapshot:
        limit = opts.limit or get_settings().nvd_max_records
        start, end = self.window(opts)
        recent_params = {"pubStartDate": _nvd_ts(start), "pubEndDate": _nvd_ts(end, True)}
        recent = self._fetch_pages(recent_params, limit)
        # Second bounded query: CVEs that NVD flags as present in CISA KEV (gives real CVSS for KEV CVEs).
        kev_limit = min(100, limit)
        kev = self._fetch_pages({"hasKev": ""}, kev_limit)
        ts = utcnow()
        path = raw_dir(self.raw_subdir) / f"nvd_{ts.replace(':', '')}.json"
        write_json(path, {
            "retrieved_at": ts,
            "api_version": "2.0",
            "queries": [{"label": "recent", "params": recent_params, "pages": recent},
                        {"label": "has_kev", "params": {"hasKev": True}, "pages": kev}],
        })
        version = f"API 2.0; published {start.isoformat()}..{end.isoformat()} + hasKev"
        return Snapshot(path, sha256_file(path), ts, version=version)

    def cached_snapshot(self) -> Snapshot | None:
        p = latest_cached(raw_dir(self.raw_subdir), "nvd_*.json")
        if not p:
            return None
        return Snapshot(p, sha256_file(p), utcnow(), version="cached snapshot", from_cache=True)

    # ---- parsing ---------------------------------------------------------
    @staticmethod
    def _best_metric(metrics: dict) -> dict | None:
        for key in METRIC_KEYS:
            entries = metrics.get(key) or []
            if entries:
                primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
                data = primary.get("cvssData", {})
                score = data.get("baseScore")
                if score is None:
                    continue
                return {
                    "version": data.get("version"),
                    "score": float(score),
                    "vector": data.get("vectorString"),
                    "severity": (data.get("baseSeverity") or primary.get("baseSeverity") or "").upper() or None,
                }
        return None

    @staticmethod
    def _products(configurations: list) -> list[str]:
        out: list[str] = []
        for conf in configurations or []:
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    parts = m.get("criteria", "").split(":")
                    if len(parts) > 4 and m.get("vulnerable", True):
                        item = f"{parts[3]}:{parts[4]}"
                        if item not in out:
                            out.append(item)
        return out[:10]

    def parse(self, snapshot: Snapshot, opts: AcquireOptions) -> ParseResult:
        payload = json.loads(snapshot.path.read_text(encoding="utf-8"))
        queries = payload.get("queries")
        if not isinstance(queries, list):
            raise AcquisitionError("NVD snapshot invalid: 'queries' missing")
        result = ParseResult()
        seen: set[str] = set()
        idx = 0
        for q in queries:
            for page in q.get("pages", []):
                for item in page.get("vulnerabilities", []):
                    idx += 1
                    result.records_read += 1
                    cve = item.get("cve") or {}
                    cve_id = str(cve.get("id", "")).strip().upper()
                    if not CVE_RE.match(cve_id):
                        result.rejected.append((idx, f"invalid CVE id: {cve_id!r}", {"id": cve_id}))
                        continue
                    if cve.get("vulnStatus") == "Rejected":
                        result.rejected.append((idx, "CVE marked Rejected by NVD", {"id": cve_id}))
                        continue
                    if cve_id in seen:
                        result.duplicates_removed += 1
                        continue
                    seen.add(cve_id)
                    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
                    metric = self._best_metric(cve.get("metrics", {}))
                    cwe = [d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                           if d.get("value", "").startswith("CWE-")]
                    result.records.append({
                        "cve_id": cve_id,
                        "description": desc,
                        "published_at": cve.get("published"),
                        "last_modified_at": cve.get("lastModified"),
                        "cvss_version": metric["version"] if metric else None,
                        "cvss_score": metric["score"] if metric else None,
                        "cvss_vector": metric["vector"] if metric else None,
                        "severity": (metric["severity"] or cvss_severity(metric["score"])) if metric else None,
                        "cwe": ",".join(dict.fromkeys(cwe)),
                        "affected_products": ",".join(self._products(cve.get("configurations", []))),
                        "reference_urls": ",".join(r["url"] for r in cve.get("references", [])[:10]),
                    })
        return result
