"""Deterministic detection rules over normalised events, each mapped to MITRE ATT&CK. No LLM involved."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from urllib.parse import unquote, unquote_plus

THRESHOLDS = {"brute_force_failures": 5, "brute_force_high": 20, "spray_users": 5, "scan_paths": 15, "exfil_bytes": 50 * 1024 * 1024}
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# (rule_id, title, severity, techniques, regex, recommendation)
PATTERN_RULES = [
    ("sqli", "SQL injection attempt", "HIGH", ["T1190"], r"union\s+(all\s+)?select|'\s*or\s*'?1'?\s*=\s*'?1|or\s+1\s*=\s*1|sleep\s*\(\s*\d|information_schema|xp_cmdshell|;\s*drop\s+table|benchmark\s*\(", "Review the targeted endpoint for parameterised queries; check the WAF; look for successful 200 responses after the attempts."),
    ("path_traversal", "Path traversal / local file inclusion attempt", "HIGH", ["T1190"], r"\.\./\.\./|\.\.%2f|%2e%2e[%/\\]|/etc/passwd|/etc/shadow|boot\.ini|win\.ini", "Confirm the application normalises paths; check whether any request returned file contents."),
    ("xss", "Cross-site scripting attempt", "MEDIUM", ["T1190"], r"<script\b|javascript:|onerror\s*=|onload\s*=|<img[^>]+src\s*=\s*x", "Validate output encoding on the affected parameter."),
    ("scanner_ua", "Known scanner / attack tool user agent", "MEDIUM", ["T1595"], r"sqlmap|nikto|nmap|masscan|wpscan|dirbuster|gobuster|acunetix|nessus|zgrab|hydra", "Block or rate-limit the source; confirm it is not an authorised assessment."),
    ("encoded_powershell", "Encoded or obfuscated PowerShell execution", "HIGH", ["T1059.001"], r"powershell[^\n]{0,80}(-enc\b|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,})|frombase64string|iex\s*\(|invoke-expression|downloadstring", "Decode and inspect the command; isolate the host if the parent process is unexpected."),
    ("shadow_copy_deletion", "Backup / shadow-copy destruction (ransomware indicator)", "CRITICAL", ["T1490"], r"vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete\s+(catalog|backup)|bcdedit[^\n]{0,40}recoveryenabled\s+no|wmic\s+shadowcopy\s+delete|cipher\s+/w", "Treat as active ransomware: isolate affected hosts immediately, preserve volatile evidence, verify offline backups."),
    ("credential_dumping", "Credential dumping tooling", "CRITICAL", ["T1003"], r"mimikatz|sekurlsa|lsass(\.exe)?[^\n]{0,60}(dump|minidump|procdump)|procdump[^\n]{0,40}lsass|comsvcs\.dll[^\n]{0,30}minidump|ntds\.dit", "Assume credentials on the host are compromised; reset affected accounts and hunt for lateral movement."),
    ("account_creation", "New account or privileged group membership change", "MEDIUM", ["T1136", "T1098"], r"net\s+user\s+\S+\s+\S*\s*/add|net\s+localgroup\s+administrators\s+\S+\s+/add|useradd\b|usermod\s+-a?G\s+(sudo|wheel|admin)|added\s+to\s+(the\s+)?(administrators|domain admins)|a member was added to a security-enabled", "Verify the change was authorised and ticketed; disable the account if not."),
    ("download_execute", "Download-and-execute / living-off-the-land transfer", "HIGH", ["T1105"], r"certutil[^\n]{0,30}-urlcache|bitsadmin[^\n]{0,20}/transfer|(curl|wget)[^\n|]{0,150}\|\s*(ba)?sh\b|mshta\s+http|regsvr32[^\n]{0,20}/i:http", "Inspect the retrieved payload and its destination; block the domain and scope other hosts that contacted it."),
    ("log_clearing", "Security log cleared (defence evasion)", "HIGH", ["T1070.001"], r"wevtutil\s+cl\b|clear-eventlog|event\s*id\s*1102|audit log was cleared|history\s+-c|unset\s+histfile|rm\s+-rf?\s+/var/log", "Preserve remaining logs from forwarders; investigate what happened just before the clearing."),
    ("persistence_task", "Persistence via scheduled task / service / run key", "MEDIUM", ["T1053", "T1547"], r"schtasks[^\n]{0,20}/create|sc\s+create\s+\S+|currentversion\\run\b|crontab\s+-[le]|new-scheduledtask", "Review the task/service binary and its creator; remove if unauthorised."),
    ("lateral_movement_tools", "Remote execution / lateral movement tooling", "HIGH", ["T1021", "T1569"], r"psexec|wmic[^\n]{0,30}/node|winrs\b|smbexec|enter-pssession|invoke-command[^\n]{0,30}-computername", "Confirm administrative intent; review authentication events on the target host."),
]


def _ev(f_id, rule, title, sev, techniques, desc, lines, events, rec, **extra):
    sample = [e["raw"][:200] for e in events[:3]]
    return {"id": f_id, "rule": rule, "title": title, "severity": sev, "techniques": techniques, "description": desc, "count": len(lines), "evidence_lines": sorted(lines)[:25],
            "sample": sample, "recommendation": rec, **extra}


def detect(events: list[dict]) -> list[dict]:
    findings: list[dict] = []
    T = THRESHOLDS

    def add(**kw):
        findings.append({**kw, "id": f"F{len(findings) + 1}"})

    # --- authentication: brute force / spraying / success after failures
    fails = defaultdict(list)
    users = defaultdict(set)
    for e in events:
        if e["action"] == "login_failed" and e["src_ip"]:
            fails[e["src_ip"]].append(e)
            if e["user"]:
                users[e["src_ip"]].add(e["user"])
    for ip, evs in sorted(fails.items(), key=lambda kv: -len(kv[1])):
        n = len(evs)
        if n < T["brute_force_failures"]:
            continue
        sev = "HIGH" if n >= T["brute_force_high"] else "MEDIUM"
        span = _span(evs)
        if len(users[ip]) >= T["spray_users"] and n / max(len(users[ip]), 1) <= 6:
            add(**_ev("", "password_spraying", "Password spraying", "HIGH", ["T1110.003"], f"{n} failed logins from {ip} across {len(users[ip])} distinct accounts{span}.",
                      [e["line"] for e in evs], evs, "Block the source, enforce MFA and lockout, and check whether any targeted account later logged in successfully.", entities={"ips": [ip], "users": sorted(users[ip])[:10]}))
        else:
            add(**_ev("", "brute_force", "Brute-force authentication attempts", sev, ["T1110"], f"{n} failed logins from {ip}{span}" + (f" targeting {', '.join(sorted(users[ip])[:5])}" if users[ip] else "") + ".",
                      [e["line"] for e in evs], evs, "Block or rate-limit the source; enforce MFA and account lockout on the targeted service.", entities={"ips": [ip], "users": sorted(users[ip])[:10]}))
        later = [e for e in events if e["action"] == "login_success" and e["src_ip"] == ip and e["line"] > evs[0]["line"]]
        if later:
            add(**_ev("", "success_after_failures", "Successful login from an IP that was brute-forcing", "CRITICAL", ["T1078"], f"{ip} authenticated successfully after {n} failures (user {later[0]['user'] or 'unknown'}). Likely account compromise.",
                      [e["line"] for e in later], later, "Treat the account as compromised: reset credentials, revoke sessions, review actions taken after the login.", entities={"ips": [ip], "users": sorted({e['user'] for e in later if e['user']})}))

    # --- web: scanning (many distinct 4xx paths from one IP)
    paths = defaultdict(set)
    path_events = defaultdict(list)
    for e in events:
        if e["action"] == "request" and e["src_ip"] and str(e.get("status", "")).startswith(("403", "404")) and e["url"]:
            paths[e["src_ip"]].add(e["url"].split("?")[0])
            path_events[e["src_ip"]].append(e)
    for ip, ps in paths.items():
        if len(ps) >= T["scan_paths"]:
            evs = path_events[ip]
            add(**_ev("", "web_scanning", "Web reconnaissance / content scanning", "MEDIUM", ["T1595"], f"{ip} requested {len(ps)} distinct missing/forbidden paths ({len(evs)} requests).",
                      [e["line"] for e in evs], evs, "Rate-limit or block the source; ensure no sensitive paths exist.", entities={"ips": [ip]}))

    # --- exfiltration by volume
    out_by_ip = defaultdict(int)
    out_events = defaultdict(list)
    for e in events:
        if e["bytes"] and e["src_ip"]:
            out_by_ip[e["src_ip"]] += e["bytes"]
            out_events[e["src_ip"]].append(e)
    for ip, total in out_by_ip.items():
        if total >= T["exfil_bytes"] and len(out_events[ip]) >= 1:
            evs = out_events[ip]
            add(**_ev("", "large_transfer", "Unusually large data transfer", "MEDIUM", ["T1041"], f"{ip} transferred {total / 1048576:.0f} MB across {len(evs)} events (threshold {T['exfil_bytes'] // 1048576} MB).",
                      [e["line"] for e in evs[:200]], evs, "Confirm the transfer is business-justified; if not, identify the data involved and the destination.", entities={"ips": [ip]}))

    # --- pattern rules over raw text
    for rule_id, title, sev, techs, rx, rec in PATTERN_RULES:
        pat = re.compile(rx, re.I)
        hits = [e for e in events if pat.search(_haystack(e))]
        if hits:
            ips = sorted({e["src_ip"] for e in hits if e["src_ip"]})[:10]
            add(**_ev("", rule_id, title, sev, techs, f"{len(hits)} event(s) match this pattern" + (f" (sources: {', '.join(ips[:5])})" if ips else "") + ".",
                      [e["line"] for e in hits], hits, rec, entities={"ips": ips, "users": sorted({e['user'] for e in hits if e['user']})[:10]}))

    # --- off-hours successful logins
    odd = [e for e in events if e["action"] == "login_success" and e["ts"] and _hour(e["ts"]) in range(0, 5)]
    if odd:
        add(**_ev("", "off_hours_login", "Successful logins at unusual hours (00:00–05:00 UTC)", "LOW", ["T1078"], f"{len(odd)} successful login(s) between 00:00 and 05:00 UTC.",
                  [e["line"] for e in odd], odd, "Verify with the account owners; correlate with the source IPs.", entities={"ips": sorted({e['src_ip'] for e in odd if e['src_ip']})[:10], "users": sorted({e['user'] for e in odd if e['user']})[:10]}))

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], -f["count"]))
    for i, f in enumerate(findings, 1):
        f["id"] = f"F{i}"
    return findings


def _hour(ts: str) -> int:
    return datetime.fromisoformat(ts).hour


def _span(evs: list[dict]) -> str:
    ts = sorted(e["ts"] for e in evs if e["ts"])
    if len(ts) < 2:
        return ""
    secs = int((datetime.fromisoformat(ts[-1]) - datetime.fromisoformat(ts[0])).total_seconds())
    return f" over {secs // 60} min {secs % 60} s" if secs >= 60 else f" over {secs} s"


def _haystack(e: dict) -> str:
    """Raw text plus its URL-decoded form (attackers percent-encode payloads) plus any command line."""
    raw = e["raw"]
    decoded = unquote_plus(unquote(raw)) if "%" in raw else ""
    return f"{raw} {decoded} {e.get('command') or ''}"
