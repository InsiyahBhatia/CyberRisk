"""CISA Known Exploited Vulnerabilities catalog (official JSON feed)."""
from __future__ import annotations

import json
import re

from app.etl.adapters.base import (
    AcquireOptions, AcquisitionError, ParseResult, Snapshot, SourceAdapter,
    http_get, latest_cached, raw_dir, sha256_file, utcnow,
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVSourceAdapter(SourceAdapter):
    name = "CISA KEV"
    publisher = "CISA (U.S. Cybersecurity and Infrastructure Security Agency)"
    official_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    acquisition_method = "Official JSON feed"
    license_notes = "U.S. Government work; CISA permits reuse. KEV membership is a prioritisation signal, not proof of compromise."
    raw_subdir = "cisa_kev"

    def acquire(self, opts: AcquireOptions) -> Snapshot:
        resp = http_get(self.client, KEV_URL, sleep=self._sleep)
        try:
            payload = resp.json()
        except ValueError as exc:
            raise AcquisitionError(f"KEV response is not JSON: {exc}") from exc
        if "vulnerabilities" not in payload:
            raise AcquisitionError("KEV payload missing 'vulnerabilities'")
        ts = utcnow()
        path = raw_dir(self.raw_subdir) / f"kev_{ts.replace(':', '')}.json"
        path.write_bytes(resp.content)
        return Snapshot(path, sha256_file(path), ts, version=payload.get("catalogVersion"))

    def cached_snapshot(self) -> Snapshot | None:
        p = latest_cached(raw_dir(self.raw_subdir), "kev_*.json")
        if not p:
            return None
        version = json.loads(p.read_text(encoding="utf-8")).get("catalogVersion")
        return Snapshot(p, sha256_file(p), utcnow(), version=version, from_cache=True)

    def parse(self, snapshot: Snapshot, opts: AcquireOptions) -> ParseResult:
        payload = json.loads(snapshot.path.read_text(encoding="utf-8"))
        items = payload.get("vulnerabilities")
        if not isinstance(items, list):
            raise AcquisitionError("KEV payload invalid: 'vulnerabilities' is not a list")
        result = ParseResult(records_read=len(items))
        seen: set[str] = set()
        for i, item in enumerate(items):
            cve = str(item.get("cveID", "")).strip().upper()
            if not CVE_RE.match(cve):
                result.rejected.append((i, f"invalid cveID: {cve!r}", item))
                continue
            if cve in seen:
                result.duplicates_removed += 1
                continue
            seen.add(cve)
            result.records.append({
                "cve_id": cve,
                "vendor_project": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
                "due_date": item.get("dueDate"),
                "known_ransomware_use": item.get("knownRansomwareCampaignUse"),
                "notes": item.get("notes"),
                "required_action": item.get("requiredAction"),
            })
        if opts.limit:
            result.records = result.records[: opts.limit]
        return result
