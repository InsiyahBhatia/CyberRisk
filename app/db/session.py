"""SQLite engine / connection helpers (SQLAlchemy Core, parameterized SQL only)."""
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import Connection, create_engine, event, text
from sqlalchemy.engine import Engine

from app.config import get_settings

SCHEMA_FILE = Path(__file__).with_name("schema.sql")


def make_engine(db_path: Path | str) -> Engine:
    if str(db_path) != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}", future=True)

    @event.listens_for(engine, "connect")
    def _pragma(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys = ON")
        cur.execute("PRAGMA busy_timeout = 8000")  # the simulator writes while the API reads/writes
        if str(db_path) != ":memory:":
            cur.execute("PRAGMA journal_mode = WAL")
        cur.close()

    return engine


DEFAULT_WORKSPACE = "demo"
_current_workspace: ContextVar[str] = ContextVar("workspace", default=DEFAULT_WORKSPACE)
_engines: dict[str, Engine] = {}
_lock = threading.Lock()


def workspace_dir(slug: str) -> Path:
    """Data directory for a workspace. The demo workspace keeps the original layout (data/)."""
    base = get_settings().data_dir
    return base if slug == DEFAULT_WORKSPACE else base / "workspaces" / slug


def workspace_db_path(slug: str) -> Path:
    return get_settings().db_path if slug == DEFAULT_WORKSPACE else workspace_dir(slug) / "cyberrisk.db"


def current_workspace() -> str:
    return _current_workspace.get()


@contextmanager
def use_workspace(slug: str) -> Iterator[None]:
    token = _current_workspace.set(slug)
    try:
        yield
    finally:
        _current_workspace.reset(token)


def set_workspace(slug: str):
    return _current_workspace.set(slug)


def engine_for(slug: str) -> Engine:
    path = str(workspace_db_path(slug))
    with _lock:
        if path not in _engines:
            eng = make_engine(path)
            if path != ":memory:" and Path(path).exists():
                init_schema(eng)  # idempotent: upgrades workspaces created by an older release (new tables/columns) on first use
            _engines[path] = eng
        return _engines[path]


def get_engine() -> Engine:
    """Engine for the workspace bound to the current request/context (tenant isolation = one database per workspace)."""
    return engine_for(current_workspace())


def _clear_engines() -> None:
    with _lock:
        for e in _engines.values():
            e.dispose()
        _engines.clear()


get_engine.cache_clear = _clear_engines  # type: ignore[attr-defined]  # kept for callers/tests that reset state


def drop_engine(slug: str) -> None:
    path = str(workspace_db_path(slug))
    with _lock:
        e = _engines.pop(path, None)
    if e:
        e.dispose()


# columns added after the first release; CREATE TABLE IF NOT EXISTS cannot add them to existing databases
MIGRATIONS = {"incidents": [("source", "TEXT DEFAULT 'manual'"), ("acknowledged_at", "TEXT"), ("signal_count", "INTEGER DEFAULT 0"), ("updated_at", "TEXT"), ("scenario_id", "INTEGER")]}


def _migrate(raw) -> None:
    for table, cols in MIGRATIONS.items():
        have = {r[1] for r in raw.execute(f"PRAGMA table_info({table})")}  # noqa: S608 (static names)
        for name, decl in cols:
            if name not in have:
                raw.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")  # noqa: S608


def init_schema(engine: Engine) -> None:
    ddl = SCHEMA_FILE.read_text(encoding="utf-8")
    raw = engine.raw_connection()
    try:
        raw.executescript(ddl)
        _migrate(raw)
        raw.commit()
    finally:
        raw.close()


@contextmanager
def connect(engine: Engine | None = None) -> Iterator[Connection]:
    """Transactional connection: commits on success, rolls back on error."""
    with (engine or get_engine()).begin() as conn:
        yield conn


def rows(conn: Connection, sql: str, **params: Any) -> list[dict]:
    return [dict(r) for r in conn.execute(text(sql), params).mappings().all()]


def one(conn: Connection, sql: str, **params: Any) -> dict | None:
    r = conn.execute(text(sql), params).mappings().first()
    return dict(r) if r else None


def scalar(conn: Connection, sql: str, **params: Any) -> Any:
    return conn.execute(text(sql), params).scalar()


def execute(conn: Connection, sql: str, **params: Any):
    return conn.execute(text(sql), params)


def get_conn() -> Iterator[Connection]:
    """FastAPI dependency."""
    with connect() as conn:
        yield conn
