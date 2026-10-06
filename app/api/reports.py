from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy import Connection

from app.api.common import audit
from app.db.session import get_conn, rows
from app.reports import build

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/assessment")
def assessment_data(conn: Connection = Depends(get_conn)):
    """Preview of the risk assessment as JSON (same data the HTML report renders)."""
    return build.build_assessment(conn)


@router.get("/assessment.html", response_class=HTMLResponse)
def assessment_html(download: bool = False, conn: Connection = Depends(get_conn)):
    d = build.build_assessment(conn)
    audit(conn, "report_generated", "report", "risk-assessment", f"{d['open_risks']} open risks")
    headers = {"Content-Disposition": 'attachment; filename="risk-assessment.html"'} if download else {}
    return HTMLResponse(build.render_assessment(d), headers=headers)


@router.get("/risk-register.csv", response_class=PlainTextResponse)
def risk_register_csv(conn: Connection = Depends(get_conn)):
    data = rows(conn, """SELECT r.risk_code, r.title, r.category, a.asset_tag, r.likelihood, r.impact, r.inherent_score, r.control_effectiveness, r.residual_score, r.risk_level,
                                r.status, r.treatment, r.owner, r.due_date, r.approval_status FROM risks r LEFT JOIN assets a ON a.id=r.asset_id ORDER BY r.residual_score DESC""")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(data[0].keys() if data else ["risk_code"])
    for r in data:
        w.writerow([("'" + str(v) if isinstance(v, str) and v[:1] in "=+-@" else v) for v in r.values()])  # neutralise spreadsheet formula injection
    return PlainTextResponse(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="risk-register.csv"'})
