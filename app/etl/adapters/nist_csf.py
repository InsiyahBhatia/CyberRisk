"""Curated, version-controlled GRC framework catalog (NIST CSF 2.0, ISO 27001:2022, SOC 2).

This is a project-curated subset, not an official machine-readable NIST feed, and is labelled as such.
"""
from __future__ import annotations

import json
from pathlib import Path

from app.etl.adapters.base import AcquireOptions, ParseResult, Snapshot, SourceAdapter, sha256_file, utcnow

CATALOG_PATH = Path(__file__).resolve().parents[2] / "grc" / "data" / "frameworks.json"


class NISTFrameworkSourceAdapter(SourceAdapter):
    name = "GRC Frameworks"
    publisher = "NIST / ISO / AICPA public framework names; curated by this project"
    official_url = "https://www.nist.gov/cyberframework"
    acquisition_method = "Curated version-controlled mapping file (app/grc/data/frameworks.json)"
    license_notes = "Framework titles referenced; descriptions are project-authored paraphrases. Not an official assessment."
    raw_subdir = "nist"
    needs_network = False

    def acquire(self, opts: AcquireOptions) -> Snapshot:
        return Snapshot(CATALOG_PATH, sha256_file(CATALOG_PATH), utcnow(), version="NIST CSF 2.0 / ISO 27001:2022 / SOC 2 2017 (curated)")

    def parse(self, snapshot: Snapshot, opts: AcquireOptions) -> ParseResult:
        data = json.loads(snapshot.path.read_text(encoding="utf-8"))
        result = ParseResult()
        for fw in data["frameworks"]:
            for i, row in enumerate(fw["controls"]):
                result.records_read += 1
                if len(row) != 4 or not all(row):
                    result.rejected.append((i, "malformed control row", row))
                    continue
                code, title, category, desc = row
                result.records.append({
                    "framework": fw["name"], "framework_version": fw["version"],
                    "framework_description": fw["description"], "source_reference": fw["source_reference"],
                    "control_code": code, "title": title, "category": category, "description": desc,
                })
        return result
