"""python -m app.demo.setup [--offline]

1. create DB  2. acquire bounded public data (NVD, CISA KEV, MITRE ATT&CK, frameworks)
3. generate synthetic org data  4. run ETL  5. enrich/calc risk  6. report exactly what succeeded/failed
"""
from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone

from app.config import get_settings
from app.db.session import connect, execute, get_engine, init_schema, rows, scalar
from app.demo import synthetic
from app.etl.acquisition import ORDER, acquire_source
from app.etl.adapters.base import AcquireOptions
from app.etl.pipeline import run_all
from app.rag import ingest as rag_ingest


def backfill_history(conn, months: int = 6) -> int:
    """Seed a synthetic monthly trend so the trend chart has data; rows are labelled as synthetic baseline."""
    n = 0
    now = datetime.now(timezone.utc)
    for r in rows(conn, "SELECT id, residual_score, risk_level FROM risks"):
        if scalar(conn, "SELECT COUNT(*) FROM risk_history WHERE risk_id=:r", r=r["id"]) > 1:
            continue
        rnd = random.Random(synthetic.SEED * 1000 + r["id"])
        score = r["residual_score"]
        series = []
        for m in range(1, months + 1):
            score = max(0.5, min(25.0, score * (1 + rnd.uniform(-0.02, 0.12))))  # earlier months trend slightly higher
            series.append((m, score))
        for m, s in series:
            from app.risk.engine import risk_level
            execute(conn, "INSERT INTO risk_history (risk_id, score, risk_level, recorded_at, reason) VALUES (:r,:s,:l,:t,'Synthetic historical baseline')",
                    r=r["id"], s=round(s, 3), l=risk_level(s), t=(now - timedelta(days=30 * m)).strftime("%Y-%m-%dT%H:%M:%SZ"))
            n += 1
    return n


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--offline", action="store_true", help="skip network acquisition; use cached raw snapshots if present")
    p.add_argument("--nvd-limit", type=int, default=get_settings().nvd_max_records)
    a = p.parse_args(argv)

    engine = get_engine()
    init_schema(engine)
    print("[1/5] Database initialised")

    report = []
    print("[2/5] Acquiring public data")
    for key in ORDER:
        opts = AcquireOptions(limit=a.nvd_limit if key == "nvd" else None, offline=a.offline)
        report.append(acquire_source(key, opts, engine))
        r = report[-1]
        print(f"      {r['name']:<16} {r['status']:<8} {r['records']:>6} records  {r['message']}")

    print("[3/5] Generating synthetic organisational data (seed 42)")
    counts = synthetic.generate(engine=engine)
    print("      " + ", ".join(f"{k}={v}" for k, v in counts.items()))

    print("[4/5] Running ETL")
    for r in run_all(get_settings().data_dir / "synthetic", engine):
        print(f"      {r['dataset']:<20} read={r['read']:<4} loaded={r['loaded']:<4} rejected={r['rejected']:<3} dups={r['duplicates']:<3} quality={r['quality_score']}")

    with connect(engine) as conn:
        n = backfill_history(conn)
        docs = rag_ingest.ingest_knowledge_base(conn) + rag_ingest.ingest_reference_data(conn)
    print(f"[5/5] Risk engine calculated; {n} synthetic baseline history points added")
    print("      Knowledge base: " + ", ".join(f"{d['file']}={d['status']}({d['chunks']})" for d in docs))

    failed = [r for r in report if r["status"] == "FAILED"]
    print("\nPublic sources: " + ("; ".join(f"{r['name']}={r['status']}" for r in report)))
    if failed:
        print("WARNING: some public sources failed; existing data was preserved and nothing was replaced with synthetic records.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
