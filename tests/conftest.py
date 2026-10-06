import os
import shutil
import tempfile
from datetime import date
from pathlib import Path

import pytest

# Isolate every test run from the real data/ directory and database.
_TMP = Path(tempfile.mkdtemp(prefix="cyberrisk_test_"))
os.environ["DATA_ROOT"] = str(_TMP / "data")
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["GEMINI_API_KEY"] = ""  # tests must never reach a real LLM provider, whatever is in .env
os.environ["GROQ_API_KEY"] = ""
os.environ["LLM_PROVIDER"] = "auto"

from app.config import get_settings  # noqa: E402
from app.db import session  # noqa: E402


@pytest.fixture()
def engine():
    """Fresh database per test."""
    get_settings.cache_clear()
    session.get_engine.cache_clear()
    db = Path(get_settings().db_path)
    if db.exists():
        db.unlink()
    shutil.rmtree(get_settings().data_dir / "raw", ignore_errors=True)  # cached snapshots must not leak between tests
    eng = session.get_engine()
    session.init_schema(eng)
    yield eng
    eng.dispose()
    session.get_engine.cache_clear()


@pytest.fixture()
def seeded(engine):
    """Database with frameworks + synthetic org data loaded through the real ETL (no network)."""
    from app.demo import synthetic
    from app.etl.acquisition import acquire_source
    from app.etl.pipeline import run_all

    acquire_source("nist", engine=engine)
    out = get_settings().data_dir / "synthetic"
    synthetic.generate(out, engine=engine, today=date(2026, 10, 1))
    run_all(out, engine, today=date(2026, 10, 1))
    return engine


@pytest.fixture()
def client(seeded):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c
