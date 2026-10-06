"""Deterministic synthetic organisational data (seed 42). Real public CVE/KEV/ATT&CK data is acquired separately.

Includes deliberate defects for ETL demonstration: duplicates, inconsistent casing, malformed CVSS,
missing owners, orphan references, expired evidence.
"""
from __future__ import annotations

import csv
import json
import random
from datetime import date, timedelta
from pathlib import Path

from sqlalchemy.engine import Engine

from app.config import get_settings
from app.db.session import connect, rows

SEED = 42
BUSINESS_UNITS = ["Engineering", "Finance", "Human Resources", "Sales", "Operations", "IT Infrastructure", "Customer Support", "Legal"]
ASSET_TYPES = ["Server", "Workstation", "Database", "Network Device", "Cloud Service", "Web Application"]
OWNER_ROLES = ["IT Operations Lead", "Security Engineer", "Platform Owner", "Application Owner", "Network Lead", "Data Steward"]
CLASSIFICATIONS = ["Public", "Internal", "Confidential", "Restricted"]
ENVIRONMENTS = ["Production", "Staging", "Development"]
FRAMEWORK_SLUG = {"NIST CSF": "NIST-CSF", "ISO/IEC 27001": "ISO-27001", "SOC 2": "SOC2"}
TECHNIQUES = ["T1566", "T1078", "T1190", "T1059", "T1486", "T1110", "T1021", "T1041", "T1003", "T1133", "T1204", "T1562"]
CATEGORIES = ["Phishing", "Malware", "Unauthorized Access", "Data Exposure", "Ransomware", "Denial of Service", "Insider Misuse"]
FALLBACK_CVES = [  # real, well-known CVEs used only if the NVD catalog has not been acquired
    ("CVE-2021-44228", 10.0), ("CVE-2023-4863", 8.8), ("CVE-2022-22965", 9.8), ("CVE-2023-34362", 9.8),
    ("CVE-2021-34527", 8.8), ("CVE-2020-1472", 10.0), ("CVE-2022-1388", 9.8), ("CVE-2023-23397", 9.8),
]


def _d(d: date) -> str:
    return d.isoformat()


def _write(path: Path, header: list[str], data: list[list]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(data)


def _cve_pool(engine: Engine | None) -> list[tuple[str, float | None, bool]]:
    if engine is not None:
        with connect(engine) as conn:
            pool = rows(conn, "SELECT cve_id, cvss_score, in_kev FROM cve_catalog ORDER BY cve_id")
        if pool:
            return [(r["cve_id"], r["cvss_score"], bool(r["in_kev"])) for r in pool]
    return [(c, s, False) for c, s in FALLBACK_CVES]


def generate(out_dir: Path | None = None, engine: Engine | None = None, today: date | None = None, seed: int = SEED) -> dict[str, int]:
    rnd = random.Random(seed)
    today = today or date.today()
    out = out_dir or (get_settings().data_dir / "synthetic")
    out.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}

    # ---- assets -----------------------------------------------------------
    assets, tags = [], []
    for i in range(1, 211):
        bu = rnd.choice(BUSINESS_UNITS)
        typ = rnd.choice(ASSET_TYPES)
        exposed = typ in ("Web Application", "Cloud Service") and rnd.random() < 0.6 or rnd.random() < 0.06
        crit = rnd.choices(["Low", "Medium", "High", "Critical"], [20, 35, 30, 15])[0]
        if bu in ("Finance", "Engineering") and rnd.random() < 0.3:
            crit = "Critical"
        tag = f"{typ[:3].upper()}-{i:04d}"
        tags.append(tag)
        owner = rnd.choice(OWNER_ROLES) if rnd.random() > 0.03 else ""  # ~3% missing owner
        cls = rnd.choice(CLASSIFICATIONS[2:] if bu in ("Finance", "Legal", "Human Resources") else CLASSIFICATIONS)
        assets.append([f"A{i:04d}", tag.lower() if rnd.random() < 0.08 else tag, f"{typ.lower().replace(' ', '-')}-{i:03d}",
                       typ, bu, owner, crit.upper() if rnd.random() < 0.5 else crit, "yes" if exposed else "no", cls,
                       rnd.choice(ENVIRONMENTS), rnd.choice(["Active"] * 9 + ["Decommissioned"])])
    for dup in rnd.sample(assets, 6):  # duplicate asset records
        assets.append(list(dup))
    _write(out / "assets.csv", ["asset_id", "asset_tag", "hostname", "asset_type", "business_unit", "owner_role", "criticality",
                                "internet_exposed", "data_classification", "environment", "status"], assets)
    counts["assets"] = len(assets)

    # ---- employees --------------------------------------------------------
    emps = []
    for i in range(1, 421):
        dept = rnd.choice(BUSINESS_UNITS)
        priv = rnd.choices(["Standard", "Elevated", "Admin"], [85, 11, 4])[0]
        p_mfa = {"Admin": 0.9, "Elevated": 0.85, "Standard": 0.74}[priv] - (0.1 if dept == "Sales" else 0)
        mfa = rnd.random() < p_mfa
        emps.append([f"E{i:04d}", dept, rnd.choice(["Analyst", "Engineer", "Manager", "Specialist", "Director"]), priv,
                     rnd.choice(["Y", "true", "TRUE"] if mfa else ["N", "false", "No"]), rnd.choices(["Active", "Disabled"], [95, 5])[0],
                     rnd.randint(0, 120), rnd.choices(["Completed", "Overdue", "In Progress"], [75, 15, 10])[0]])
    emps.append(list(emps[3]))
    emps.append(["E9999", "Sales", "Analyst", "Standard", "maybe", "Active", 3, "Completed"])  # invalid MFA flag
    _write(out / "employees.csv", ["employee_id", "department", "role", "privilege_level", "mfa_enabled", "account_status",
                                   "last_login_days", "training_status"], emps)
    counts["employees"] = len(emps)

    # ---- vendors + findings ----------------------------------------------
    cats = ["Cloud Hosting", "Payroll", "CRM", "Email Security", "Analytics", "Managed SOC", "Legal Services", "Telephony", "Backup", "Identity Provider"]
    vendors, vfind = [], []
    for i in range(1, 46):
        crit = rnd.choice(["Low", "Medium", "High", "Critical"])
        access = rnd.choice(["None", "Limited", "Confidential Data", "Restricted Data"])
        inh = round(rnd.uniform(2, 9.5), 1)
        status = rnd.choices(["Completed", "In Progress", "Overdue", "Not Started"], [55, 15, 20, 10])[0]
        last = today - timedelta(days=rnd.randint(30, 700))
        nxt = last + timedelta(days=365)
        vendors.append([f"V{i:03d}", f"Vendor {i:03d} ({rnd.choice(cats)})", rnd.choice(cats), crit, access, inh, status, _d(last), _d(nxt)])
        for j in range(rnd.choice([0, 0, 1, 2, 3])):
            vfind.append([f"V{i:03d}", rnd.choice(["No MFA for admin portal", "Outdated SOC 2 report", "Unencrypted data transfer", "No breach notification clause", "Subprocessor not disclosed"]),
                          rnd.choice(["Low", "Medium", "High", "Critical"]), rnd.choice(["Open", "Open", "Remediated"]), _d(today + timedelta(days=rnd.randint(-60, 120)))])
    vendors.append(list(vendors[5]))
    vfind.append(["V999", "Orphan vendor reference", "Low", "Open", _d(today)])
    _write(out / "vendors.csv", ["vendor_id", "vendor_name", "service_category", "criticality", "data_access", "inherent_risk",
                                 "security_assessment_status", "last_assessed", "next_review"], vendors)
    _write(out / "vendor_findings.csv", ["vendor_id", "finding", "severity", "status", "due_date"], vfind)
    counts["vendors"], counts["vendor_findings"] = len(vendors), len(vfind)

    # ---- control status & evidence ---------------------------------------
    fw = json.loads((Path(__file__).resolve().parents[1] / "grc" / "data" / "frameworks.json").read_text(encoding="utf-8"))["frameworks"]
    refs, ctl = [], []
    for f in fw:
        slug = FRAMEWORK_SLUG[f["name"]]
        for code, *_ in f["controls"]:
            ref = f"{slug}/{code}"
            refs.append(ref)
            st = rnd.choices(["IMPLEMENTED", "PARTIAL", "NOT_IMPLEMENTED", "NOT_APPLICABLE"], [42, 30, 23, 5])[0]
            eff = {"IMPLEMENTED": rnd.uniform(0.55, 0.9), "PARTIAL": rnd.uniform(0.2, 0.5), "NOT_IMPLEMENTED": rnd.uniform(0, 0.1), "NOT_APPLICABLE": 0}[st]
            ctl.append([ref, st.lower() if rnd.random() < 0.1 else st, round(eff, 2), rnd.choice(OWNER_ROLES)])
    _write(out / "control_status.csv", ["control_ref", "implementation_status", "effectiveness", "owner_role"], ctl)
    counts["control_status"] = len(ctl)

    ev = []
    for i, ref in enumerate(rnd.sample(refs, 55) + rnd.sample(refs, 60) + rnd.sample(refs, 25), 1):
        collected = today - timedelta(days=rnd.randint(10, 500))
        expiry = collected + timedelta(days=rnd.choice([180, 365, 365, 730]))
        status = "EXPIRED" if expiry < today else rnd.choices(["PRESENT", "NEEDS_REVIEW", "MISSING"], [80, 12, 8])[0]
        ev.append([f"EV-{i:04d}", ref, rnd.choice(["Policy", "Configuration Screenshot", "Audit Report", "Access Review", "Log Extract"]),
                   status.title() if rnd.random() < 0.05 else status, _d(collected) if status != "MISSING" else "", _d(expiry) if status != "MISSING" else "", rnd.choice(OWNER_ROLES)])
    ev.append(["EV-9001", "NIST-CSF/ZZ.XX-99", "Policy", "PRESENT", _d(today), _d(today + timedelta(days=300)), "Security Engineer"])  # orphan control
    _write(out / "compliance_evidence.csv", ["evidence_id", "control_id", "evidence_type", "status", "collected_at", "expiry_date", "owner_role"], ev)
    counts["compliance_evidence"] = len(ev)

    # ---- vulnerability scan findings (CVE IDs come from the real NVD catalog when acquired) ----
    pool = _cve_pool(engine)
    kev_pool = [p for p in pool if p[2]]
    scan = []
    for _ in range(720):
        cve, score, _k = rnd.choice(kev_pool if kev_pool and rnd.random() < 0.12 else pool)
        tag = rnd.choice(tags)
        disc = today - timedelta(days=rnd.randint(1, 150))
        sev_days = 45 if (score or 5) >= 9 else 75 if (score or 5) >= 7 else 120
        due = disc + timedelta(days=sev_days)
        status = rnd.choices(["OPEN", "IN_PROGRESS", "RESOLVED", "ACCEPTED"], [50, 15, 32, 3])[0]
        resolved = _d(disc + timedelta(days=rnd.randint(2, sev_days + 30))) if status == "RESOLVED" else ""
        if resolved and resolved > _d(today):
            resolved = _d(today)
        reported = f"{(score if score is not None else rnd.uniform(3, 9)):.1f}"
        scan.append([cve, tag.lower() if rnd.random() < 0.05 else tag, reported, rnd.choice(["None", "Low", "Medium", "High", "Active"]),
                     status.title() if rnd.random() < 0.15 else status, _d(disc), _d(due), resolved])
    for k in rnd.sample(range(len(scan)), 10):
        scan[k][2] = rnd.choice(["N/A", "11.7", "-2", "abc", ""])  # malformed CVSS
    for k in rnd.sample(range(len(scan)), 4):
        scan[k][1] = "ghost-asset-" + str(k)  # orphan asset
    scan += [list(r) for r in rnd.sample(scan, 25)]  # duplicates
    _write(out / "vulnerability_scan.csv", ["cve_id", "asset_tag", "scanner_cvss", "exploitability", "status", "discovered_at", "due_date", "resolved_at"], scan)
    counts["vulnerability_scan"] = len(scan)

    # ---- incidents ---------------------------------------------------------
    inc = []
    for i in range(1, 76):
        cat = rnd.choice(CATEGORIES)
        det = today - timedelta(days=rnd.randint(1, 365))
        sev = rnd.choices(["Low", "Medium", "High", "Critical"], [25, 35, 28, 12])[0]
        status = rnd.choices(["Closed", "Open", "Investigating", "Contained"], [60, 15, 15, 10])[0]
        res = _d(det + timedelta(days=rnd.randint(1, 30))) if status == "Closed" else ""
        t = ";".join(rnd.sample(TECHNIQUES, rnd.randint(1, 3)))
        inc.append([f"INC-{i:04d}", f"{cat} incident", cat, sev.upper() if rnd.random() < 0.3 else sev, status, rnd.choice(tags),
                    _d(det), res, f"Synthetic {cat.lower()} event affecting a monitored asset.", t])
    inc[7][5] = "ghost-asset-inc"
    inc.append(list(inc[2]))
    _write(out / "incidents.csv", ["incident_id", "title", "category", "severity", "status", "affected_asset_id", "detected_at",
                                   "resolved_at", "description", "mitre_technique_ids"], inc)
    counts["incidents"] = len(inc)

    # ---- audit findings ----------------------------------------------------
    af = []
    for i in range(1, 71):
        af.append([f"AF-{i:04d}", rnd.choice(["Quarterly access review lacks sign-off", "Backup restore test not evidenced", "Vendor assessment overdue",
                                              "Patch SLA exceeded for critical assets", "Incident runbook outdated", "Privileged account without MFA"]),
                   rnd.choice(["Internal Audit", "External Audit", "SOC 2 Readiness", "Pen Test"]), rnd.choice(["Low", "Medium", "High", "Critical"]),
                   rnd.choice(["Open", "Open", "In Progress", "Closed"]), rnd.choice(OWNER_ROLES), _d(today + timedelta(days=rnd.randint(-90, 150)))])
    af.append(list(af[4]))
    _write(out / "audit_findings.csv", ["finding_id", "title", "source", "severity", "status", "owner_role", "due_date"], af)
    counts["audit_findings"] = len(af)

    # ---- risk register & remediation --------------------------------------
    templates = [
        ("Unpatched internet-facing systems exploited", "Vulnerability Management", ["NIST-CSF/PR.PS-02", "NIST-CSF/ID.RA-01", "ISO-27001/A.8.8", "SOC2/CC7.1"], ["T1190"]),
        ("Compromised credentials without MFA", "Identity & Access", ["NIST-CSF/PR.AA-03", "ISO-27001/A.8.5", "SOC2/CC6.1"], ["T1078", "T1110"]),
        ("Ransomware disrupts critical services", "Resilience", ["NIST-CSF/RC.RP-01", "ISO-27001/A.8.13", "SOC2/A1.2"], ["T1486"]),
        ("Phishing leads to account takeover", "Awareness", ["NIST-CSF/PR.AT-01", "ISO-27001/A.6.3", "SOC2/CC1.1"], ["T1566"]),
        ("Critical vendor breach exposes customer data", "Third Party", ["NIST-CSF/GV.SC-03", "ISO-27001/A.5.19", "SOC2/CC9.2"], ["T1133"]),
        ("Sensitive data transmitted unencrypted", "Data Protection", ["NIST-CSF/PR.DS-02", "ISO-27001/A.8.24", "SOC2/CC6.7"], ["T1041"]),
        ("Insufficient logging delays breach detection", "Detection", ["NIST-CSF/PR.PS-04", "NIST-CSF/DE.CM-01", "ISO-27001/A.8.15", "SOC2/CC7.2"], ["T1562"]),
        ("Excess privileged access", "Identity & Access", ["NIST-CSF/PR.AA-05", "ISO-27001/A.8.2", "SOC2/CC6.3"], ["T1078", "T1003"]),
        ("Incident response plan not exercised", "Response", ["NIST-CSF/RS.MA-01", "ISO-27001/A.5.24", "SOC2/CC7.4"], ["T1059"]),
        ("Unmanaged changes cause outage or exposure", "Change Management", ["ISO-27001/A.8.32", "SOC2/CC8.1"], ["T1204"]),
    ]
    reg, rem = [], []
    for i in range(1, 41):
        title, cat, crefs, techs = templates[(i - 1) % len(templates)]
        tag = rnd.choice(tags)
        likelihood, impact = rnd.choices([1, 2, 3, 4, 5], [5, 15, 30, 30, 20])[0], rnd.choices([2, 3, 4, 5], [10, 25, 35, 30])[0]
        status = rnd.choices(["IDENTIFIED", "ASSESSMENT", "TREATMENT", "MITIGATION", "VALIDATION", "ACCEPTED", "CLOSED"], [15, 15, 20, 25, 8, 9, 8])[0]
        treat = rnd.choice(["MITIGATE", "MITIGATE", "MITIGATE", "TRANSFER", "AVOID", "ACCEPT"])
        code = f"R-{i:03d}"
        reg.append([code, title if i <= 10 else f"{title} ({rnd.choice(BUSINESS_UNITS)})", cat, tag, likelihood, impact, rnd.choice(OWNER_ROLES), status, treat,
                    _d(today + timedelta(days=rnd.randint(-45, 180))), ";".join(crefs), ";".join(techs)])
        for a in rnd.sample(["Enforce MFA on all privileged accounts", "Patch critical vulnerabilities within SLA", "Deploy EDR to remaining endpoints",
                             "Complete vendor security assessment", "Run tabletop incident exercise", "Enable centralized log forwarding",
                             "Implement network segmentation", "Rotate and vault service credentials"], rnd.randint(1, 3)):
            done = rnd.random() < 0.25
            rem.append([code, a, rnd.choice(OWNER_ROLES), rnd.choice(["Low", "Medium", "High", "Critical"]), _d(today + timedelta(days=rnd.randint(-30, 120))),
                        "COMPLETED" if done else rnd.choice(["OPEN", "IN_PROGRESS"]), round(rnd.uniform(0.08, 0.3), 2)])
    _write(out / "risk_register.csv", ["risk_code", "title", "category", "asset_tag", "likelihood", "impact", "owner_role", "status", "treatment",
                                       "due_date", "control_refs", "technique_ids"], reg)
    _write(out / "remediation_actions.csv", ["risk_code", "action", "owner_role", "priority", "due_date", "status", "effectiveness_gain"], rem)
    counts["risk_register"], counts["remediation_actions"] = len(reg), len(rem)
    return counts


if __name__ == "__main__":
    from app.db.session import get_engine
    print(generate(engine=get_engine()))
