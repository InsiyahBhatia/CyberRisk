"""MITRE ATT&CK Enterprise (official STIX 2.1 bundle from the mitre-attack/attack-stix-data repo)."""
from __future__ import annotations

import json
import re

from app.etl.adapters.base import (
    AcquireOptions, AcquisitionError, ParseResult, Snapshot, SourceAdapter,
    http_get, latest_cached, raw_dir, sha256_file, utcnow,
)

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class MITREAttackSourceAdapter(SourceAdapter):
    name = "MITRE ATT&CK"
    publisher = "The MITRE Corporation"
    official_url = "https://attack.mitre.org/"
    acquisition_method = "Official STIX 2.1 JSON (attack-stix-data)"
    license_notes = "ATT&CK content is available under MITRE's terms of use (royalty-free licence; attribution required)."
    raw_subdir = "mitre"

    def acquire(self, opts: AcquireOptions) -> Snapshot:
        resp = http_get(self.client, ATTACK_URL, sleep=self._sleep)
        try:
            payload = resp.json()
        except ValueError as exc:
            raise AcquisitionError(f"ATT&CK response is not JSON: {exc}") from exc
        if payload.get("type") != "bundle" or "objects" not in payload:
            raise AcquisitionError("ATT&CK payload is not a STIX bundle")
        ts = utcnow()
        path = raw_dir(self.raw_subdir) / f"enterprise-attack_{ts.replace(':', '')}.json"
        path.write_bytes(resp.content)
        return Snapshot(path, sha256_file(path), ts, version=self._version(payload))

    @staticmethod
    def _version(payload: dict) -> str | None:
        for obj in payload.get("objects", []):
            if obj.get("type") == "x-mitre-collection":
                return obj.get("x_mitre_version")
        return None

    def cached_snapshot(self) -> Snapshot | None:
        p = latest_cached(raw_dir(self.raw_subdir), "enterprise-attack_*.json")
        if not p:
            return None
        return Snapshot(p, sha256_file(p), utcnow(), version=self._version(json.loads(p.read_text(encoding="utf-8"))), from_cache=True)

    def parse(self, snapshot: Snapshot, opts: AcquireOptions) -> ParseResult:
        payload = json.loads(snapshot.path.read_text(encoding="utf-8"))
        objects = payload.get("objects")
        if not isinstance(objects, list):
            raise AcquisitionError("ATT&CK bundle invalid: 'objects' is not a list")
        patterns = [o for o in objects if o.get("type") == "attack-pattern"]
        result = ParseResult(records_read=len(patterns))
        seen: set[str] = set()
        for i, obj in enumerate(patterns):
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            tid = next((r.get("external_id") for r in obj.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if not tid or not TECH_RE.match(tid):
                result.rejected.append((i, f"missing/invalid technique id: {tid!r}", {"name": obj.get("name")}))
                continue
            if tid in seen:
                result.duplicates_removed += 1
                continue
            seen.add(tid)
            tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                       if p.get("kill_chain_name") == "mitre-attack"]
            result.records.append({
                "technique_id": tid,
                "name": obj.get("name"),
                "tactics": ",".join(tactics),
                "description": (obj.get("description") or "")[:2000],
                "platforms": ",".join(obj.get("x_mitre_platforms", [])),
                "version": snapshot.version,
            })
        if opts.limit:
            result.records = result.records[: opts.limit]
        return result
