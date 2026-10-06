"""CLI: python -m app.etl.acquire --source nvd|cisa-kev|mitre|nist | --all"""
from __future__ import annotations

import argparse
import sys

from app.db.session import get_engine, init_schema
from app.etl.acquisition import ADAPTERS, acquire_all, acquire_source
from app.etl.adapters.base import AcquireOptions


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Acquire public cybersecurity data with provenance tracking.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--source", choices=sorted(ADAPTERS))
    g.add_argument("--all", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--limit", type=int)
    p.add_argument("--start-date")
    p.add_argument("--end-date")
    p.add_argument("--force", action="store_true")
    p.add_argument("--skip-existing", action="store_true")
    a = p.parse_args(argv)

    init_schema(get_engine())
    opts = AcquireOptions(limit=a.limit, start_date=a.start_date, end_date=a.end_date,
                          force=a.force, skip_existing=a.skip_existing, dry_run=a.dry_run)
    results = acquire_all(opts) if a.all else [acquire_source(a.source, opts)]
    for r in results:
        print(f"{r['name']:<16} {r['status']:<9} records={r['records']:<6} {r['message']}")
    return 0 if all(r["status"] in ("HEALTHY", "SKIPPED", "DRY_RUN", "CACHED") for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
