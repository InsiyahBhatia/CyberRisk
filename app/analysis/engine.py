"""Analysis orchestration: parse -> detect -> extract IOCs -> enrich (ATT&CK, NVD, CISA KEV) -> score -> persist.
Everything here is deterministic and works with no organisation data and no AI."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from sqlalchemy import Connection

from app.analysis import detections, iocs, parsers
from app.db.session import execute, one, rows
from app.risk.engine import cvss_severity

SEV_WEIGHT = {"CRITICAL": 0.60, "HIGH": 0.35, "MEDIUM": 0.15, "LOW": 0.05}
LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
LIMITATIONS = ["Rule-based detections: they find known patterns, not novel attacks, and can produce false positives.",
               "Severity is a triage aid computed from detected patterns; it is not an organisational risk rating until linked to assets and controls.",
               "Timestamps without a timezone are treated as UTC."]

CATEGORY_KEYWORDS = {
    "Ransomware": ["ransom", "encrypted files", ".locked", "decrypt", "bitcoin", "shadow cop", "vssadmin", "your files have been"],
    "Phishing": ["phish", "spoof", "malicious email", "credential harvest", "suspicious email", "malicious link", "fake login", "business email compromise", "bec "],
    "Malware": ["malware", "trojan", "backdoor", "command and control", "c2 ", "beacon", "payload", "virus", "botnet", "rat ", "infostealer", "dropper"],
    "Unauthorized Access": ["unauthorized", "brute force", "brute-force", "compromised account", "stolen credential", "lateral movement", "privilege escalation", "mfa fatigue", "password spray", "account takeover"],
    "Data Exposure": ["exfiltrat", "data leak", "exposed bucket", "data breach", "pii", "sensitive data", "public s3", "customer data", "misconfigured"],
    "Denial of Service": ["ddos", "denial of service", "traffic flood", "syn flood", "service unavailable"],
    "Insider Misuse": ["insider", "former employee", "policy violation", "employee misuse", "disgruntled"],
}
CATEGORY_BASE = {"Ransomware": "CRITICAL", "Data Exposure": "HIGH", "Malware": "HIGH", "Unauthorized Access": "HIGH", "Phishing": "MEDIUM", "Denial of Service": "MEDIUM", "Insider Misuse": "MEDIUM"}
ESCALATORS = ["domain admin", "production", "customer data", "confirmed exfiltration", "multiple systems", "multiple hosts", "executive", "regulated", "pci", "active attacker", "spread"]
MITIGATORS = ["false positive", "no evidence of compromise", "was blocked", "successfully blocked", "no data was", "contained quickly", "test environment", "authorised test", "authorized test"]
KEYWORD_TECHNIQUES = [("phish", "T1566"), ("malicious link", "T1204"), ("macro", "T1204.002"), ("powershell", "T1059.001"), ("brute force", "T1110"), ("brute-force", "T1110"), ("password spray", "T1110.003"),
                      ("valid account", "T1078"), ("stolen credential", "T1078"), ("ransom", "T1486"), ("encrypted files", "T1486"), ("exfiltrat", "T1041"), ("command and control", "T1071"), ("c2 ", "T1071"),
                      ("lateral movement", "T1021"), ("remote desktop", "T1021.001"), ("rdp", "T1021.001"), ("scheduled task", "T1053"), ("exposed", "T1190"), ("vulnerability", "T1190"), ("mimikatz", "T1003"),
                      ("keylogger", "T1056"), ("ddos", "T1498"), ("shadow cop", "T1490")]
PLAYBOOK = {
    "Ransomware": ["Isolate affected hosts from the network now (do not power off; preserve memory).", "Identify patient zero and the initial access vector (phishing, exposed RDP, vulnerable edge device).", "Verify offline/immutable backups and test restore on a clean network segment.", "Engage legal/insurance and decide on regulatory notification clocks.", "Reset credentials for accounts seen on affected hosts; hunt for persistence before restoring."],
    "Phishing": ["Pull the message from all mailboxes and block the sender/URL/attachment hash.", "Identify who clicked or entered credentials; reset passwords and revoke sessions for them.", "Check for mailbox rules, OAuth grants and MFA changes on affected accounts.", "Send a short awareness note; record the technique for training."],
    "Malware": ["Isolate the host and capture memory/disk before remediation.", "Block hashes, domains and IPs at endpoint, DNS and firewall.", "Hunt for the same indicators across the estate.", "Rebuild from a known-good image if persistence cannot be proven absent."],
    "Unauthorized Access": ["Disable or reset the affected accounts and revoke active sessions/tokens.", "Review authentication logs for the source IPs and any lateral movement afterwards.", "Enforce MFA and conditional access on the targeted service.", "Review privileged group membership and recent changes."],
    "Data Exposure": ["Stop the exposure (revoke public access/keys) and preserve access logs.", "Determine what data, how many records and whether it was accessed by third parties.", "Assess notification obligations with legal/privacy.", "Add a preventive control (guardrail, scanning) and track it as a remediation action."],
    "Denial of Service": ["Engage the upstream provider/CDN and enable rate limiting or scrubbing.", "Identify the targeted service and its dependencies.", "Capture attack traffic characteristics for blocking rules.", "Review capacity and resilience plans."],
    "Insider Misuse": ["Preserve evidence under HR/legal guidance before any confrontation.", "Restrict the account's access proportionately.", "Review data access and transfer logs over the relevant period.", "Document decisions and approvals."],
    "General": ["Validate the alert and scope affected assets and accounts.", "Contain proportionately to the confirmed impact.", "Preserve logs and evidence.", "Record the incident, map techniques to ATT&CK, and agree follow-up actions."],
}


def _level_up(level: str, steps: int) -> str:
    return LEVELS[max(0, min(3, LEVELS.index(level) + steps))]


def score_findings(findings: list[dict]) -> tuple[float, str]:
    """score = 100 x (1 - prod(1 - w_i)): diminishing returns so many low findings never outweigh one critical one."""
    p = 1.0
    for f in findings:
        p *= 1 - SEV_WEIGHT[f["severity"]]
    score = round(100 * (1 - p), 1)
    level = "CRITICAL" if score >= 70 else "HIGH" if score >= 45 else "MEDIUM" if score >= 20 else "LOW"
    return score, level


def enrich(conn: Connection, tech_ids: list[str], cve_ids: list[str]) -> tuple[list[dict], list[dict]]:
    techs = []
    for t in tech_ids:
        r = one(conn, "SELECT technique_id, name, tactics, description FROM attack_techniques WHERE technique_id=:t", t=t)
        techs.append({"id": t, "name": r["name"] if r else None, "tactics": (r["tactics"] if r else "").split(",") if r and r["tactics"] else [], "known": bool(r),
                      "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"})
    cves = []
    for c in cve_ids:
        r = one(conn, """SELECT c.cve_id, c.cvss_score, c.severity, c.description, c.in_kev, k.vulnerability_name, k.due_date, k.known_ransomware_use, k.required_action
                         FROM cve_catalog c LEFT JOIN kev_entries k ON k.cve_id=c.cve_id WHERE c.cve_id=:c""", c=c)
        kev = one(conn, "SELECT cve_id, vulnerability_name, due_date, known_ransomware_use, required_action FROM kev_entries WHERE cve_id=:c", c=c)
        if r:
            cves.append({"id": c, "known": True, "cvss": r["cvss_score"], "severity": r["severity"], "in_kev": bool(r["in_kev"] or kev), "description": (r["description"] or "")[:300],
                         "kev": {k: kev[k] for k in ("vulnerability_name", "due_date", "known_ransomware_use", "required_action")} if kev else None})
        else:
            cves.append({"id": c, "known": False, "cvss": None, "severity": None, "in_kev": bool(kev), "description": "Not in the loaded NVD window.",
                         "kev": {k: kev[k] for k in ("vulnerability_name", "due_date", "known_ransomware_use", "required_action")} if kev else None})
    return techs, cves


def _kev_findings(cves: list[dict], start_index: int) -> list[dict]:
    out = []
    for c in cves:
        if c["in_kev"]:
            out.append({"id": "", "rule": "kev_cve_referenced", "title": f"{c['id']} is in CISA's Known Exploited Vulnerabilities catalog", "severity": "HIGH", "techniques": ["T1190"],
                        "description": f"{c['id']} ({(c['kev'] or {}).get('vulnerability_name') or 'KEV entry'}) has evidence of exploitation in the wild" + (f"; known ransomware use: {c['kev']['known_ransomware_use']}" if c["kev"] and c["kev"]["known_ransomware_use"] == "Known" else "") + ".",
                        "count": 1, "evidence_lines": [], "sample": [], "recommendation": (c["kev"] or {}).get("required_action") or "Patch or mitigate per vendor guidance; check exposure on internet-facing systems.", "entities": {}})
    return out


def _finish(conn: Connection, *, kind: str, name: str, source_name: str | None, events: list[dict], meta: dict, findings: list[dict], ioc: dict, extra: dict) -> dict:
    cves_raw = ioc["cves"]
    tech_ids = sorted(set(ioc["technique_ids"]) | {t for f in findings for t in f["techniques"]})
    techs, cves = enrich(conn, tech_ids, cves_raw)
    findings = findings + _kev_findings(cves, len(findings))
    findings.sort(key=lambda f: (-detections.SEVERITY_ORDER[f["severity"]], -f["count"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F{i}"
    tech_ids = sorted(set(tech_ids) | {t for f in findings for t in f["techniques"]})
    techs, _ = enrich(conn, tech_ids, [])
    for t in techs:
        t["findings"] = [f["id"] for f in findings if t["id"] in f["techniques"]]
    score, level = score_findings(findings)
    if extra.get("severity_override"):
        level = extra.pop("severity_override")
        score = max(score, {"LOW": 10.0, "MEDIUM": 30.0, "HIGH": 55.0, "CRITICAL": 80.0}[level])  # incident severity is category-driven; keep score consistent with it
    bad_ips = {ip for f in findings for ip in (f.get("entities") or {}).get("ips", [])}
    for ip in ioc["ips"]:
        ip["flagged"] = ip["value"] in bad_ips
    ioc["ips"].sort(key=lambda i: (not i["flagged"], i["scope"] != "public", -i["count"]))
    timeline = extra.pop("timeline", None) or _log_timeline(events, findings)
    result = {"kind": kind, "name": name, "source_name": source_name, "meta": meta, "severity": level, "score": score, "findings": findings, "iocs": ioc, "techniques": techs, "cves": cves,
              "tactics": sorted({t for x in techs for t in x["tactics"]}), "timeline": timeline, "limitations": LIMITATIONS,
              "scoring": "score = 100 x (1 - product(1 - weight)) with weights CRITICAL .60, HIGH .35, MEDIUM .15, LOW .05; level: >=70 CRITICAL, >=45 HIGH, >=20 MEDIUM", **extra}
    result["id"] = execute(conn, """INSERT INTO analyses (name, kind, source_name, created_at, event_count, finding_count, severity, score, result_json)
                                    VALUES (:n,:k,:s,:c,:e,:f,:sev,:sc,:r)""", n=name[:120], k=kind, s=source_name, c=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                           e=meta.get("events", 0), f=len(findings), sev=level, sc=score, r="{}").lastrowid
    execute(conn, "UPDATE analyses SET result_json=:r WHERE id=:i", r=json.dumps(result, default=str), i=result["id"])
    return result


def _log_timeline(events: list[dict], findings: list[dict]) -> list[dict]:
    by_line = {e["line"]: e for e in events}
    items = []
    for f in findings:
        for ln in f["evidence_lines"][:2]:
            e = by_line.get(ln)
            if e:
                items.append({"ts": e["ts"], "line": ln, "finding": f["id"], "severity": f["severity"], "event": e["raw"][:160]})
    items.sort(key=lambda x: (x["ts"] is None, x["ts"] or "", x["line"]))
    return items[:40]


def analyze_logs(conn: Connection, data: bytes, filename: str, name: str | None = None) -> dict:
    events, meta = parsers.parse(data, filename)
    if not events:
        raise ValueError("No events could be parsed from this file")
    findings = detections.detect(events)
    blob = "\n".join(e["raw"] for e in events[:50000])
    ioc = iocs.extract(blob)
    top_actions: dict[str, int] = {}
    for e in events:
        top_actions[e["action"]] = top_actions.get(e["action"], 0) + 1
    meta["action_counts"] = top_actions
    steps = list(dict.fromkeys(f["recommendation"] for f in findings))[:6] or ["No known attack patterns were detected. Consider supplying more context (authentication, web, endpoint logs)."]
    return _finish(conn, kind="logs", name=name or filename or "log analysis", source_name=filename, events=events, meta=meta, findings=findings, ioc=ioc, extra={"next_steps": steps})


def analyze_incident(conn: Connection, text: str, name: str | None = None) -> dict:
    text = text.strip()
    if len(text) < 20:
        raise ValueError("Provide at least a sentence or two describing the incident")
    low = text.lower()
    scores = {cat: sum(low.count(k) for k in kws) for cat, kws in CATEGORY_KEYWORDS.items()}
    ranked = sorted(((n, c) for c, n in scores.items() if n > 0), reverse=True)
    category = ranked[0][1] if ranked else "General"
    secondary = [c for n, c in ranked[1:3]]
    rationale = [f"Category '{category}' from keyword evidence ({ranked[0][0]} matching phrase(s))." if ranked else "No category keywords found; treated as a general incident."]
    level = CATEGORY_BASE.get(category, "MEDIUM")
    up = [k for k in ESCALATORS if k in low]
    down = [k for k in MITIGATORS if k in low]
    if up:
        level = _level_up(level, 1)
        rationale.append("Escalated one level by: " + ", ".join(up[:4]) + ".")
    if down:
        level = _level_up(level, -1)
        rationale.append("Reduced one level by: " + ", ".join(down[:3]) + ".")
    # treat each line as an event so command-level detections work on pasted evidence
    lines = [ln for ln in text.splitlines() if ln.strip()]
    events = [parsers._parse_text_line(i, ln) for i, ln in enumerate(lines, 1)]
    events = [e for e in events if e]
    findings = detections.detect(events)
    ioc = iocs.extract(text)
    kw_tech = sorted({t for k, t in KEYWORD_TECHNIQUES if k in low})
    ioc["technique_ids"] = sorted(set(ioc["technique_ids"]) | set(kw_tech))
    timeline = []
    for e in events:
        if e["ts"]:
            timeline.append({"ts": e["ts"], "line": e["line"], "finding": None, "severity": None, "event": e["raw"][:200]})
    timeline.sort(key=lambda x: x["ts"])
    meta = {"format": "incident text", "events": len(events), "characters": len(text), "with_timestamp": len(timeline)}
    steps = list(PLAYBOOK.get(category, PLAYBOOK["General"]))
    steps += [f["recommendation"] for f in findings if f["recommendation"] not in steps][:3]
    return _finish(conn, kind="incident", name=name or f"{category} incident", source_name=None, events=events, meta=meta, findings=findings, ioc=ioc,
                   extra={"category": category, "secondary_categories": secondary, "severity_override": level, "severity_rationale": rationale, "next_steps": steps, "timeline": timeline[:60],
                          "technique_basis": {"explicit_ids": sorted(set(iocs.TECH.findall(text))), "from_keywords": kw_tech}})


def get_analysis(conn: Connection, aid: int) -> dict | None:
    r = one(conn, "SELECT * FROM analyses WHERE id=:i", i=aid)
    if not r:
        return None
    return {**json.loads(r["result_json"]), "id": r["id"], "created_at": r["created_at"]}


def list_analyses(conn: Connection, limit: int = 50) -> list[dict]:
    return rows(conn, "SELECT id, name, kind, source_name, created_at, event_count, finding_count, severity, score FROM analyses ORDER BY id DESC LIMIT :l", l=limit)
