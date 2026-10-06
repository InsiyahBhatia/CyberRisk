"""Shared API helpers: pagination, sorting whitelist, error format, audit logging."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Connection

from app.db.session import execute, rows, scalar

MAX_PAGE_SIZE = 200


def paged(conn: Connection, select_sql: str, count_sql: str, params: dict[str, Any], sort_map: dict[str, str],
          sort: str | None, order: str, page: int, page_size: int, default_sort: str) -> dict:
    """Run a paginated query. `sort` must be a key of `sort_map`: client text never reaches the SQL string."""
    page = max(1, page)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    col = sort_map.get(sort or "", sort_map[default_sort])
    direction = "ASC" if order.lower() == "asc" else "DESC"
    total = scalar(conn, count_sql, **params)
    items = rows(conn, f"{select_sql} ORDER BY {col} {direction} LIMIT :_limit OFFSET :_offset",  # noqa: S608 (whitelisted)
                 **params, _limit=page_size, _offset=(page - 1) * page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


def audit(conn: Connection, action: str, entity: str, entity_id: Any, detail: str = "", actor: str = "system") -> None:
    execute(conn, "INSERT INTO audit_log (ts, actor, action, entity, entity_id, detail) VALUES (:t,:a,:ac,:e,:i,:d)",
            t=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), a=actor, ac=action, e=entity, i=str(entity_id), d=detail[:500])


def not_found(what: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"{what} not found")


def install_error_handlers(app: FastAPI) -> None:
    """Consistent error body: {"error": {"code", "message", "details"?}}."""

    @app.exception_handler(HTTPException)
    async def _http(_: Request, exc: HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.status_code, "message": str(exc.detail)}})

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError):
        details = [{"field": ".".join(str(p) for p in e["loc"]), "message": e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"error": {"code": 422, "message": "Validation failed", "details": details}})

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception):
        return JSONResponse(status_code=500, content={"error": {"code": 500, "message": "Internal server error"}})
