"""Bring-your-own-dataset support: profile a file, suggest a column mapping to a target dataset, apply it, run the normal ETL.

Mapping only renames/fills columns; all validation, normalisation, de-duplication and rejection logging still happen in the pipeline.
"""
from __future__ import annotations

import io
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import pandas as pd

from app.etl.pipeline import DATASET_BY_NAME, read_table


@dataclass(frozen=True)
class Field:
    name: str
    required: bool = False
    default: str = ""            # applied when the field is not mapped; "TODAY" = today's ISO date
    synonyms: tuple[str, ...] = ()
    kind: str = "text"           # text | date | enum | number | bool
    example: str = ""


def F(name, required=False, default="", syn=(), kind="text", example=""):
    return Field(name, required, default, tuple(syn), kind, example)


SPECS: dict[str, list[Field]] = {
    "assets": [F("asset_id", syn=("id",), example="A0001"), F("asset_tag", True, syn=("tag", "asset", "asset_id", "id", "hostname", "host", "device", "device_name", "asset_name", "name"), example="SRV-0001"),
               F("hostname", True, syn=("host", "name", "fqdn", "device_name", "asset_name", "asset_tag"), example="web-01"), F("asset_type", syn=("type", "category", "class", "device_type"), example="Server"),
               F("business_unit", True, "Unassigned", ("bu", "department", "dept", "division", "team", "unit", "line_of_business"), example="Finance"),
               F("owner_role", True, "Unassigned", ("owner", "assigned_to", "custodian", "owner_name", "responsible", "asset_owner"), example="IT Operations Lead"),
               F("criticality", True, "MEDIUM", ("priority", "tier", "importance", "business_criticality", "criticality_rating", "impact"), "enum", "High"),
               F("internet_exposed", False, "no", ("public", "exposed", "external", "internet_facing", "internet", "public_facing"), "bool", "yes"),
               F("data_classification", syn=("classification", "data_class", "sensitivity", "data_sensitivity"), example="Confidential"), F("environment", syn=("env", "stage"), example="Production"),
               F("status", False, "Active", ("state", "lifecycle", "asset_status"), "enum", "Active")],
    "vulnerability_scan": [F("cve_id", True, syn=("cve", "vulnerability_id", "cve_number", "plugin_cve", "vuln_id", "id"), example="CVE-2021-44228"),
                           F("asset_tag", True, syn=("asset", "host", "hostname", "asset_id", "device", "target", "server", "ip"), example="SRV-0001"),
                           F("scanner_cvss", False, "", ("cvss", "cvss_score", "cvss_base_score", "base_score", "score"), "number", "9.8"),
                           F("exploitability", False, "NONE", ("exploit", "exploit_available", "exploitability_rating"), example="High"),
                           F("status", True, "OPEN", ("state", "vuln_status", "finding_status"), "enum", "Open"), F("discovered_at", True, "TODAY", ("first_seen", "found", "detected", "first_detected", "date_found", "scan_date", "discovered", "first_found"), "date", "2026-09-01"),
                           F("due_date", False, "", ("due", "sla_date", "remediation_due", "target_date"), "date", "2026-10-01"), F("resolved_at", False, "", ("resolved", "fixed_at", "closed_at", "date_fixed", "remediated_at"), "date")],
    "incidents": [F("incident_id", True, syn=("id", "ticket", "ticket_id", "case_id", "number", "incident_number", "incident"), example="INC-0001"), F("title", syn=("summary", "name", "short_description", "subject"), example="Phishing campaign"),
                  F("category", syn=("type", "incident_type", "classification", "kind"), example="Phishing"), F("severity", True, "MEDIUM", ("priority", "impact", "sev", "criticality"), "enum", "High"),
                  F("status", True, "OPEN", ("state", "incident_status", "stage"), "enum", "Closed"), F("affected_asset_id", False, "", ("asset", "asset_tag", "host", "hostname", "affected_asset", "affected_host", "system", "ci"), example="SRV-0001"),
                  F("detected_at", True, "TODAY", ("detected", "opened", "opened_at", "created", "created_at", "date", "reported", "start_time", "timestamp"), "date", "2026-09-10"),
                  F("resolved_at", False, "", ("resolved", "closed", "closed_at", "end_time", "date_resolved"), "date"), F("description", syn=("details", "notes", "long_description", "narrative"), example="User reported suspicious email"),
                  F("mitre_technique_ids", False, "", ("techniques", "mitre", "attack_ids", "technique_ids", "mitre_techniques", "ttp"), example="T1566;T1078")],
    "employees": [F("employee_id", True, syn=("id", "user_id", "username", "user", "employee", "emp_id", "account"), example="E0001"), F("department", True, "Unassigned", ("dept", "business_unit", "team", "division"), example="Finance"),
                  F("role", False, "Unknown", ("job_title", "title", "position")), F("privilege_level", False, "Standard", ("privilege", "access_level", "account_type", "admin"), example="Admin"),
                  F("mfa_enabled", True, "", ("mfa", "two_factor", "2fa", "multi_factor", "mfa_status", "mfa_registered"), "bool", "yes"), F("account_status", False, "Active", ("status", "state", "account_state")),
                  F("last_login_days", False, "0", ("last_login", "days_since_login", "inactive_days"), "number", "5"), F("training_status", False, "Unknown", ("training", "security_training", "awareness_training"))],
    "vendors": [F("vendor_id", True, syn=("id", "vendor_code", "supplier_id"), example="V001"), F("vendor_name", True, syn=("name", "vendor", "supplier", "supplier_name", "company"), example="Acme Cloud"),
                F("service_category", syn=("category", "service", "type"), example="Cloud Hosting"), F("criticality", True, "MEDIUM", ("tier", "importance", "business_criticality", "risk_tier"), "enum", "High"),
                F("data_access", syn=("data", "data_type", "access", "data_classification"), example="Confidential Data"), F("inherent_risk", True, "5", ("risk", "risk_score", "inherent", "score"), "number", "6.5"),
                F("security_assessment_status", False, "NOT_STARTED", ("assessment_status", "assessment", "review_status", "due_diligence"), "enum", "Completed"),
                F("last_assessed", syn=("last_review", "last_assessment", "assessed_on"), kind="date"), F("next_review", syn=("next_assessment", "review_due", "renewal"), kind="date")],
    "vendor_findings": [F("vendor_id", True, syn=("vendor", "id", "supplier_id")), F("finding", True, syn=("issue", "description", "gap", "observation", "title")), F("severity", True, "MEDIUM", ("risk", "rating", "priority"), "enum"),
                        F("status", False, "OPEN", ("state",), "enum"), F("due_date", syn=("due", "target_date"), kind="date")],
    "control_status": [F("control_ref", True, syn=("control", "control_id", "ref", "id"), example="NIST-CSF/PR.AA-03"), F("implementation_status", True, "NOT_IMPLEMENTED", ("status", "state", "maturity", "implemented"), "enum", "IMPLEMENTED"),
                       F("effectiveness", False, "0", ("effectiveness_score", "score", "strength"), "number", "0.7"), F("owner_role", syn=("owner", "responsible"))],
    "compliance_evidence": [F("evidence_id", True, syn=("id", "evidence", "ref"), example="EV-0001"), F("control_id", True, syn=("control", "control_ref", "control_code"), example="NIST-CSF/PR.AA-03"),
                            F("evidence_type", syn=("type", "kind", "category")), F("status", True, "PRESENT", ("state", "evidence_status"), "enum"), F("collected_at", syn=("collected", "date", "created"), kind="date"),
                            F("expiry_date", syn=("expiry", "expires", "valid_until", "expires_at"), kind="date"), F("owner_role", syn=("owner",))],
    "audit_findings": [F("finding_id", True, syn=("id", "ref", "finding"), example="AF-0001"), F("title", True, syn=("finding", "summary", "name", "issue", "description")), F("source", syn=("audit", "origin", "auditor")),
                       F("severity", True, "MEDIUM", ("rating", "risk", "priority"), "enum"), F("status", False, "OPEN", ("state",), "enum"), F("owner_role", syn=("owner", "assigned_to")), F("due_date", syn=("due", "target_date"), kind="date")],
    "risk_register": [F("risk_code", True, syn=("id", "risk_id", "ref", "code"), example="R-001"), F("title", True, syn=("risk", "name", "risk_title", "description", "summary")), F("category", syn=("type", "risk_category", "domain")),
                      F("asset_tag", syn=("asset", "affected_asset", "system")), F("likelihood", True, "3", ("probability", "likelihood_score", "l"), "number", "4"), F("impact", True, "3", ("consequence", "impact_score", "severity", "i"), "number", "5"),
                      F("owner_role", syn=("owner", "risk_owner")), F("status", False, "IDENTIFIED", ("state", "risk_status"), "enum"), F("treatment", False, "MITIGATE", ("response", "risk_response", "treatment_plan"), "enum"),
                      F("due_date", syn=("due", "target_date", "review_date"), kind="date"), F("control_refs", syn=("controls", "mitigating_controls")), F("technique_ids", syn=("techniques", "mitre"))],
    "remediation_actions": [F("risk_code", True, syn=("risk", "risk_id", "id")), F("action", True, syn=("task", "remediation", "description", "title")), F("owner_role", syn=("owner", "assigned_to")),
                            F("priority", False, "MEDIUM", ("severity", "importance"), "enum"), F("due_date", syn=("due", "target_date"), kind="date"), F("status", False, "OPEN", ("state",), "enum"),
                            F("effectiveness_gain", False, "0.1", ("gain", "risk_reduction", "effect"), "number")],
}
assert set(SPECS) == set(DATASET_BY_NAME), "mapping spec must cover every dataset"


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(s).strip().lower()).strip("_")


def _tokens(s: str) -> set[str]:
    return {t for t in norm(s).split("_") if t}


def score(source: str, f: Field) -> float:
    n = norm(source)
    if n == f.name:
        return 1.0
    syns = [norm(x) for x in f.synonyms]
    if n in syns:
        return 0.9 - 0.02 * min(syns.index(n), 10)
    for x in [f.name, *syns]:
        if len(x) > 2 and (x in n or n in x) and len(n) > 2:
            return 0.6
    a, b = _tokens(source), _tokens(f.name) | {t for x in f.synonyms for t in _tokens(x)}
    j = len(a & b) / len(a | b) if a | b else 0
    return 0.5 if j >= 0.5 else 0.0


def suggest(columns: list[str], dataset: str) -> dict:
    fields = SPECS[dataset]
    out = []
    for f in fields:
        ranked = sorted(((score(c, f), c) for c in columns), reverse=True)
        good = [(s, c) for s, c in ranked if s >= 0.5]
        best = good[0] if good else None
        out.append({"field": f.name, "required": f.required, "kind": f.kind, "default": f.default, "example": f.example,
                    "mapped_from": best[1] if best else None, "confidence": round(best[0], 2) if best else 0.0,
                    "alternatives": [c for _, c in good[1:4]]})
    missing = [o["field"] for o in out if o["required"] and not o["mapped_from"] and not next(f for f in fields if f.name == o["field"]).default]
    return {"dataset": dataset, "fields": out, "missing_required": missing}


def detect_dataset(columns: list[str]) -> list[dict]:
    """Rank datasets by how well the file's columns cover each dataset's required fields."""
    ranks = []
    for ds, fields in SPECS.items():
        req = [f for f in fields if f.required]
        got = [max((score(c, f) for c in columns), default=0) for f in req]
        ranks.append({"dataset": ds, "score": round(sum(1 for g in got if g >= 0.5) / len(req) * 0.7 + (sum(got) / len(got)) * 0.3, 3), "matched_required": sum(1 for g in got if g >= 0.5), "required": len(req)})
    return sorted(ranks, key=lambda r: -r["score"])


def profile(df: pd.DataFrame) -> list[dict]:
    cols = []
    for c in df.columns:
        s = df[c].astype(str).str.strip()
        nonblank = s[s != ""]
        nums = pd.to_numeric(nonblank, errors="coerce")
        dates = pd.to_datetime(nonblank, errors="coerce", format="mixed") if len(nonblank) else nonblank
        if len(nonblank) and nums.notna().mean() > 0.9:
            kind = "number"
        elif len(nonblank) and dates.notna().mean() > 0.9 and not nums.notna().mean() > 0.5:
            kind = "date"
        elif len(nonblank) and set(x.lower() for x in nonblank.unique()) <= {"yes", "no", "y", "n", "true", "false", "1", "0"}:
            kind = "boolean"
        else:
            kind = "text"
        cols.append({"name": str(c), "type": kind, "null_pct": round(100 * (1 - len(nonblank) / max(len(s), 1)), 1), "unique": int(nonblank.nunique()), "sample": [str(x)[:60] for x in nonblank.unique()[:5]]})
    return cols


def apply_mapping(df: pd.DataFrame, dataset: str, mapping: dict[str, str | None]) -> pd.DataFrame:
    """Build the canonical frame the pipeline expects. Unmapped optional fields get their default; dates are normalised to ISO."""
    fields = SPECS[dataset]
    cols = set(df.columns)
    bad = [v for v in mapping.values() if v and v not in cols]
    if bad:
        raise ValueError(f"Unknown source columns in mapping: {bad}")
    out = pd.DataFrame(index=df.index)
    today = date.today().isoformat()
    for f in fields:
        src = mapping.get(f.name)
        if src:
            col = df[src].astype(str).str.strip()
            if f.kind == "date":
                parsed = pd.to_datetime(col.where(col != ""), errors="coerce", format="mixed", utc=True)
                col = parsed.dt.strftime("%Y-%m-%d").where(parsed.notna(), col)  # unparseable values stay as-is and are rejected by validation
            out[f.name] = col
        else:
            out[f.name] = today if f.default == "TODAY" else f.default
    return out


def template_csv(dataset: str) -> str:
    fields = SPECS[dataset]
    buf = io.StringIO()
    buf.write(",".join(f.name for f in fields) + "\n")
    buf.write(",".join(f'"{f.example}"' if "," in f.example else f.example for f in fields) + "\n")
    return buf.getvalue()


def load_upload(path: Path) -> pd.DataFrame:
    return read_table(path)
