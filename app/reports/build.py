"""Report data + rendering. Everything is calculated from the workspace database; recommendations are rule-based and cite their numbers."""
from __future__ import annotations

import html
from datetime import datetime, timezone

from sqlalchemy import Connection

from app.api.dashboard import kpis
from app.db.session import current_workspace, rows, scalar
from app.grc.service import compliance_summary, controls_with_evidence
from app.risk.service import enterprise_score
from app.tenancy import workspaces as tenancy


def build_assessment(conn: Connection) -> dict:
    ws = tenancy.get(current_workspace()) or {"name": current_workspace()}
    k = kpis(conn)
    risks = rows(conn, """SELECT r.id, r.risk_code, r.title, r.category, r.inherent_score, r.control_effectiveness, r.residual_score, r.risk_level, r.status, r.treatment, r.owner, r.due_date,
                                 r.approval_status, a.asset_tag, a.business_unit,
                                 (SELECT COUNT(*) FROM risk_controls rc WHERE rc.risk_id=r.id) AS control_count
                          FROM risks r LEFT JOIN assets a ON a.id=r.asset_id WHERE r.status!='CLOSED' ORDER BY r.residual_score DESC""")
    for r in risks[:10]:
        r["controls"] = rows(conn, """SELECT c.control_code, c.title, c.implementation_status, f.name AS framework FROM risk_controls rc JOIN controls c ON c.id=rc.control_id
                                      JOIN frameworks f ON f.id=c.framework_id WHERE rc.risk_id=:r ORDER BY f.name""", r=r["id"])
    high = [r for r in risks if r["risk_level"] in ("HIGH", "CRITICAL")]
    gaps = rows(conn, """SELECT DISTINCT c.id, c.control_code, c.title, f.name AS framework, c.implementation_status,
                                (SELECT GROUP_CONCAT(DISTINCT r.risk_code) FROM risk_controls rc JOIN risks r ON r.id=rc.risk_id WHERE rc.control_id=c.id AND r.risk_level IN ('HIGH','CRITICAL') AND r.status!='CLOSED') AS drives_risks
                         FROM controls c JOIN frameworks f ON f.id=c.framework_id
                         WHERE c.implementation_status IN ('NOT_IMPLEMENTED','PARTIAL') AND f.name!='MITRE ATT&CK'
                           AND EXISTS (SELECT 1 FROM risk_controls rc JOIN risks r ON r.id=rc.risk_id WHERE rc.control_id=c.id AND r.risk_level IN ('HIGH','CRITICAL') AND r.status!='CLOSED')
                         ORDER BY c.implementation_status DESC, c.control_code LIMIT 25""")
    ctl = [c for c in controls_with_evidence(conn) if c["framework"] != "MITRE ATT&CK"]
    applicable = [c for c in ctl if c["implementation_status"] != "NOT_APPLICABLE"]
    ev_bad = [c for c in applicable if c["implementation_status"] == "IMPLEMENTED" and c["evidence_status"] != "PRESENT"]
    vulns = {"open": k["open_vulnerabilities"], "critical": k["critical_findings"], "kev": k["known_exploited_open"], "overdue": k["overdue_vulnerabilities"],
             "top": rows(conn, """SELECT v.cve_id, v.severity, v.cvss_score, v.known_exploited, v.due_date, v.risk_score, a.asset_tag, a.business_unit FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id
                                  WHERE v.status IN ('OPEN','IN_PROGRESS') ORDER BY v.risk_score DESC LIMIT 10""")}
    vendors = rows(conn, "SELECT vendor_name, criticality, residual_risk, assessment_status, next_review FROM vendors WHERE residual_risk>=7 ORDER BY residual_risk DESC LIMIT 8")
    pending = scalar(conn, "SELECT COUNT(*) FROM risks WHERE approval_status='PENDING'")
    recs = []
    unlinked = [r for r in high if r["control_count"] == 0]
    if unlinked:
        recs.append({"priority": "High", "title": "Link and assess controls for high-rated risks", "why": f"{len(unlinked)} of {len(high)} HIGH/CRITICAL risks have no linked control, so their residual score assumes zero mitigation.", "action": "Map each to the controls that mitigate it and record their real implementation status."})
    if gaps:
        recs.append({"priority": "High", "title": "Close control gaps that drive the highest risks", "why": f"{len(gaps)} partially or non-implemented controls are linked to HIGH/CRITICAL risks.", "action": "Start with: " + ", ".join(f"{g['framework']} {g['control_code']}" for g in gaps[:5]) + "."})
    if vulns["kev"]:
        recs.append({"priority": "High", "title": "Remediate known-exploited vulnerabilities first", "why": f"{vulns['kev']} open vulnerabilities are listed in CISA KEV (evidence of exploitation in the wild).", "action": "Patch or mitigate by the KEV due date; prioritise internet-exposed and critical assets."})
    if vulns["open"] and vulns["overdue"] / vulns["open"] > 0.2:
        recs.append({"priority": "Medium", "title": "Fix the remediation SLA process", "why": f"{vulns['overdue']} of {vulns['open']} open vulnerabilities ({round(100 * vulns['overdue'] / vulns['open'])}%) are past their due date.", "action": "Agree owners and SLAs per severity; report ageing weekly."})
    if applicable and len(ev_bad) / len(applicable) > 0.3 or ev_bad:
        recs.append({"priority": "Medium", "title": "Refresh missing or expired control evidence", "why": f"{len(ev_bad)} implemented controls lack valid evidence, so they do not count toward evidence coverage.", "action": "Collect current evidence and set expiry dates."})
    if vendors:
        recs.append({"priority": "Medium", "title": "Review high-risk vendors", "why": f"{len(vendors)} vendors have residual risk ≥ 7/10.", "action": "Complete overdue assessments and close open vendor findings."})
    if k["mfa_adoption"] is not None and k["mfa_adoption"] < 90:
        recs.append({"priority": "Medium", "title": "Raise MFA adoption", "why": f"MFA adoption is {k['mfa_adoption']}% of active accounts.", "action": "Enforce MFA for privileged and remote access first."})
    if pending:
        recs.append({"priority": "High", "title": "Decide pending risk acceptances", "why": f"{pending} HIGH/CRITICAL risk acceptance(s) await human approval.", "action": "Named executives should approve or reject with a documented rationale."})
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "workspace": ws, "kpis": k, "enterprise_score": round(enterprise_score(conn), 1),
        "risk_counts": {lvl: sum(1 for r in risks if r["risk_level"] == lvl) for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}, "open_risks": len(risks), "top_risks": risks[:10],
        "control_gaps": gaps, "evidence_issues": len(ev_bad), "compliance": compliance_summary(conn), "vulnerabilities": vulns, "vendors": vendors,
        "incidents_open": k["open_incidents"], "recommendations": recs,
        "sources": rows(conn, "SELECT source_name, source_type, status, retrieval_timestamp, dataset_version, record_count, from_cache FROM source_registry ORDER BY source_type DESC, source_name"),
        "method": ["Inherent risk = likelihood × impact; residual = inherent × (1 − mean effectiveness of linked applicable controls); levels LOW <5, MEDIUM <10, HIGH <17, CRITICAL.",
                   "Vulnerability priority combines CVSS (NVD), asset criticality, exploitability, internet exposure and CISA KEV membership with configurable weights.",
                   "Control and evidence coverage are internal readiness metrics: implemented ÷ applicable and valid-evidence ÷ applicable."],
        "limitations": ["This is a readiness assessment based on the data in this workspace. It is not a certification, attestation or audit opinion.",
                        "Control status, evidence, assets and risks are only as accurate as the data imported or entered by the assessor.",
                        "AI, where used, only explains calculated results and never determines scores or compliance."],
    }


CSS = """body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1d1d1b;background:#fff;max-width:960px;margin:32px auto;padding:0 20px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid #e3e1da;padding-bottom:4px}table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
th,td{border-bottom:1px solid #e3e1da;padding:6px 8px;text-align:left;vertical-align:top}th{background:#faf9f6;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;color:#62625d}
.muted{color:#62625d}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.kpi{border:1px solid #e3e1da;padding:10px;border-radius:4px}.kpi b{font-size:22px;display:block}
.b{display:inline-block;padding:0 6px;border-radius:3px;font-size:11.5px;font-weight:600;background:#eeede8}.CRITICAL{background:#f5e1df;color:#9a2e2e}.HIGH{background:#f6e6d9;color:#a85226}.MEDIUM{background:#f3ecd0;color:#8a6d12}.LOW{background:#e1eee4;color:#3b7248}
.note{border-left:3px solid #3a5a78;background:#f6f5f1;padding:8px 12px;margin:10px 0}@media print{body{margin:0}}"""


def esc(x) -> str:
    return html.escape("" if x is None else str(x))


def badge(level: str | None) -> str:
    return f'<span class="b {esc(level)}">{esc(level)}</span>' if level else "—"


def table(headers: list[str], body: list[list[str]]) -> str:
    if not body:
        return '<p class="muted">None.</p>'
    return "<table><thead><tr>" + "".join(f"<th>{esc(h)}</th>" for h in headers) + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in body) + "</tbody></table>"


def page(title: str, subtitle: str, body: str) -> str:
    return f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title><style>{CSS}</style></head><body><h1>{esc(title)}</h1><p class="muted">{esc(subtitle)}</p>{body}</body></html>'


def render_assessment(d: dict) -> str:
    k = d["kpis"]
    kp = "".join(f'<div class="kpi"><b>{esc(v)}</b><span class="muted">{esc(l)}</span></div>' for l, v in [("Enterprise risk score /100", d["enterprise_score"]), ("Open risks", d["open_risks"]),
          ("Control coverage %", k["control_coverage"]), ("Open vulnerabilities", k["open_vulnerabilities"])])
    parts = [f'<div class="kpis">{kp}</div>', f'<p>Risk levels: ' + " ".join(f'{badge(l)} {n}' for l, n in d["risk_counts"].items()) + "</p>"]
    parts.append("<h2>Recommendations</h2>" + (table(["Priority", "Recommendation", "Why (evidence)", "Action"], [[esc(r["priority"]), f"<b>{esc(r['title'])}</b>", esc(r["why"]), esc(r["action"])] for r in d["recommendations"]]) if d["recommendations"] else '<p class="muted">No rule-based recommendations triggered by the current data.</p>'))
    parts.append("<h2>Top risks</h2>" + table(["ID", "Risk", "Asset", "Inherent", "Residual", "Level", "Treatment", "Owner", "Controls"],
                 [[esc(r["risk_code"]), esc(r["title"]), esc(r["asset_tag"]), esc(round(r["inherent_score"], 1)), esc(round(r["residual_score"], 1)), badge(r["risk_level"]), esc(r["treatment"]), esc(r["owner"]),
                   esc("; ".join(f"{c['framework']} {c['control_code']} ({c['implementation_status'].lower().replace('_', ' ')})" for c in r.get("controls", [])) or "none linked")] for r in d["top_risks"]]))
    parts.append("<h2>Control gaps linked to HIGH/CRITICAL risks</h2>" + table(["Framework", "Control", "Status", "Drives risks"], [[esc(g["framework"]), esc(f"{g['control_code']} {g['title']}"), esc(g["implementation_status"].lower().replace("_", " ")), esc(g["drives_risks"])] for g in d["control_gaps"]]))
    parts.append("<h2>Compliance readiness (internal metric, not certification)</h2>" + table(["Framework", "Control coverage", "Evidence coverage", "Applicable controls"],
                 [[esc(f"{c['name']} {c['version']}"), esc(f"{c['control_coverage']}%"), esc(f"{c['evidence_coverage']}%"), esc(c["applicable_controls"])] for c in d["compliance"]]))
    v = d["vulnerabilities"]
    parts.append(f"<h2>Vulnerability exposure</h2><p>{v['open']} open · {v['critical']} critical · {v['kev']} in CISA KEV · {v['overdue']} overdue.</p>" + table(["CVE", "Asset", "Severity", "CVSS", "KEV", "Priority"],
                 [[esc(x["cve_id"]), esc(x["asset_tag"]), badge(x["severity"]), esc(x["cvss_score"]), "yes" if x["known_exploited"] else "", esc(round(x["risk_score"] or 0))] for x in v["top"]]))
    if d["vendors"]:
        parts.append("<h2>High-risk vendors</h2>" + table(["Vendor", "Criticality", "Residual risk", "Assessment"], [[esc(x["vendor_name"]), badge(x["criticality"]), esc(x["residual_risk"]), esc(x["assessment_status"])] for x in d["vendors"]]))
    parts.append("<h2>Data provenance</h2>" + table(["Source", "Type", "Status", "Retrieved", "Version", "Records"], [[esc(s["source_name"]), esc(s["source_type"].lower()), esc(s["status"] + (" (cached)" if s["from_cache"] else "")), esc(s["retrieval_timestamp"] or ""), esc(s["dataset_version"] or ""), esc(s["record_count"])] for s in d["sources"]]))
    parts.append('<h2>Method</h2><ul>' + "".join(f"<li>{esc(m)}</li>" for m in d["method"]) + "</ul>")
    parts.append('<div class="note"><b>Limitations.</b><ul>' + "".join(f"<li>{esc(m)}</li>" for m in d["limitations"]) + "</ul></div>")
    return page(f"Risk assessment: {d['workspace']['name']}", f"Generated {d['generated_at']} by CyberRisk", "".join(parts))


def render_analysis(a: dict) -> str:
    parts = [f'<p>Severity {badge(a["severity"])} · score {esc(a["score"])}/100 · {esc(a["meta"].get("events"))} events · {len(a["findings"])} findings</p>']
    if a.get("severity_rationale"):
        parts.append("<h2>Severity rationale</h2><ul>" + "".join(f"<li>{esc(x)}</li>" for x in a["severity_rationale"]) + "</ul>")
    parts.append("<h2>Findings</h2>" + table(["ID", "Finding", "Severity", "ATT&CK", "Detail", "Recommendation"], [[esc(f["id"]), f"<b>{esc(f['title'])}</b>", badge(f["severity"]), esc(", ".join(f["techniques"])), esc(f["description"]), esc(f["recommendation"])] for f in a["findings"]]))
    parts.append("<h2>ATT&CK techniques</h2>" + table(["ID", "Name", "Tactics"], [[esc(t["id"]), esc(t["name"] or "not in loaded dataset"), esc(", ".join(t["tactics"]))] for t in a["techniques"]]))
    if a["cves"]:
        parts.append("<h2>Referenced CVEs</h2>" + table(["CVE", "CVSS", "KEV", "Description"], [[esc(c["id"]), esc(c["cvss"]), "yes" if c["in_kev"] else "no", esc(c["description"])] for c in a["cves"]]))
    parts.append("<h2>Indicators</h2>" + table(["Type", "Value", "Notes"], [["ip", esc(i["value"]), esc(i["scope"] + (", flagged" if i.get("flagged") else ""))] for i in a["iocs"]["ips"][:25]] + [["domain", esc(d["value"]), ""] for d in a["iocs"]["domains"][:15]] + [[esc(h["type"]), esc(h["value"]), ""] for h in a["iocs"]["hashes"][:10]]))
    parts.append("<h2>Recommended next steps</h2><ol>" + "".join(f"<li>{esc(s)}</li>" for s in a["next_steps"]) + "</ol>")
    parts.append('<div class="note"><b>Limitations.</b><ul>' + "".join(f"<li>{esc(m)}</li>" for m in a["limitations"]) + "</ul></div>")
    return page(f"Analysis: {a['name']}", f"{a['kind']} analysis · {a.get('created_at', '')} · CyberRisk", "".join(parts))
