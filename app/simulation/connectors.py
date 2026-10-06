"""Connectors: map each integration's native payload to one common Signal. Invalid payloads are rejected with a reason
(logged like any other ETL rejection), never silently dropped."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class Reject(Exception):
    pass


@dataclass
class Signal:
    source: str
    kind: str
    ts: str
    severity: str
    title: str
    host: str = ""
    user: str = ""
    src_ip: str = ""
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    cve: str = ""
    raw: str = ""
    extra: dict = field(default_factory=dict)


def _ts(v, fmt: str | None = None) -> str:
    if not v:
        raise Reject("missing timestamp")
    try:
        if fmt:
            return datetime.strptime(str(v), fmt).replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Reject(f"unparseable timestamp {str(v)[:30]!r}")


def _sev(word: str, table: dict[str, str]) -> str:
    s = table.get(str(word).strip().lower())
    if not s:
        raise Reject(f"unknown severity {str(word)[:20]!r}")
    return s


def _techs(*vals) -> list[str]:
    out = []
    for v in vals:
        for t in re.split(r"[;, ]+", str(v or "")):
            if t:
                if not TECH_RE.match(t):
                    raise Reject(f"malformed ATT&CK id {t[:12]!r}")
                if t not in out:
                    out.append(t)
    return out


def _line(ts: str, host: str, msg: str) -> str:
    d = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    return f"{d.strftime('%b')} {d.day:>2} {d.strftime('%H:%M:%S')} {host or '-'} {msg}"


def siem(p: dict) -> Signal:
    ts = _ts(p.get("_time"))
    if not p.get("search_name"):
        raise Reject("SIEM alert without rule name")
    sev = _sev(p.get("urgency"), {"informational": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"})
    t = _techs(p.get("mitre_technique_id"))
    return Signal("SIEM", "alert", ts, sev, p["search_name"], host=p.get("dest", ""), user=p.get("user") or "", src_ip=p.get("src") or "", techniques=t,
                  description=f"{p['search_name']} (src {p.get('src') or '-'} → {p.get('dest') or '-'})", raw=p.get("_raw") or _line(ts, p.get("dest", ""), p["search_name"]))


def edr(p: dict) -> Signal:
    ts = _ts(p.get("created_timestamp"))
    beh = (p.get("behaviors") or [None])[0]
    host = (p.get("device") or {}).get("hostname")
    if not beh or not host:
        raise Reject("EDR detection without behavior or device")
    sev = _sev(p.get("max_severity_displayname"), {"informational": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"})
    cmd = beh.get("cmdline") or beh.get("filename") or ""
    return Signal("EDR", "detection", ts, sev, f"{beh.get('tactic', 'Detection')}: {beh.get('filename', 'process')}", host=host, user=p.get("username") or "", src_ip=(p.get("device") or {}).get("local_ip", ""),
                  techniques=_techs(beh.get("technique_id")), description=cmd[:300], raw=_line(ts, host, f"edr: {beh.get('filename', '')} {cmd}"))


def itsm(p: dict) -> Signal:
    ts = _ts(p.get("opened_at"), "%Y-%m-%d %H:%M:%S")
    if not p.get("number") or not p.get("short_description"):
        raise Reject("ticket without number or description")
    m = re.match(r"^\s*([1-5])\b", str(p.get("priority", "")))
    if not m:
        raise Reject(f"unrecognised priority {str(p.get('priority'))[:15]!r}")
    sev = {"1": "CRITICAL", "2": "HIGH", "3": "MEDIUM", "4": "LOW", "5": "INFO"}[m.group(1)]
    cls = p.get("sys_class_name", "incident")
    return Signal("ITSM", "ticket", ts, sev, f"{p['number']}: {p['short_description']}", host=p.get("cmdb_ci") or "", user=p.get("caller_id") or "", description=p.get("description", ""),
                  raw=_line(ts, p.get("cmdb_ci") or "itsm", f"ticket {p['number']} {p['short_description']} {p.get('description', '')}"),
                  extra={"number": p["number"], "class": cls, "category": p.get("category", ""), "is_incident": cls == "incident" and p.get("category") == "Security"})


def scanner(p: dict) -> Signal:
    ts = _ts(p.get("first_found"))
    host = (p.get("asset") or {}).get("hostname")
    if not host:
        raise Reject("scanner finding without asset")
    cves = p.get("cve") or []
    for c in cves:
        if not CVE_RE.match(str(c)):
            raise Reject(f"malformed CVE {str(c)[:20]!r}")
    try:
        cvss = float(p.get("cvss_base_score"))
    except (TypeError, ValueError):
        if cves:
            raise Reject(f"non-numeric CVSS {str(p.get('cvss_base_score'))[:10]!r}")
        cvss = 0.0
    if not 0 <= cvss <= 10:
        raise Reject(f"CVSS {cvss} outside 0-10")
    sev = _sev(p.get("severity"), {"info": "INFO", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"})
    return Signal("Scanner", "finding", ts, sev, p.get("plugin_name") or "Scan finding", host=host, src_ip=(p.get("asset") or {}).get("ipv4", ""), cve=cves[0] if cves else "",
                  description=f"{p.get('plugin_name', '')} CVSS {cvss}", raw=_line(ts, host, f"scanner: {p.get('plugin_name', '')} {' '.join(cves)}"), extra={"cvss": cvss, "cve_list": cves})


IAM_RULES = {
    "user.session.start": None, "user.mfa.factor.deactivate": ("HIGH", "T1556"), "user.account.privilege.grant": ("HIGH", "T1098"), "user.account.lock": ("MEDIUM", ""),
}


def iam(p: dict) -> Signal:
    ts = _ts(p.get("published"))
    ev = p.get("eventType") or ""
    if ev not in IAM_RULES:
        raise Reject(f"unsupported event type {ev[:30]!r}")
    result = str((p.get("outcome") or {}).get("result", "")).upper()
    if result not in ("SUCCESS", "FAILURE"):
        raise Reject("missing outcome")
    user = str((p.get("actor") or {}).get("alternateId", "")).split("@")[0]
    ip = (p.get("client") or {}).get("ipAddress", "")
    country = ((p.get("client") or {}).get("geographicalContext") or {}).get("country", "US")
    if ev == "user.session.start":
        if result == "FAILURE":
            sev, title, tech, line = "LOW", f"Failed sign-in for {user}", ["T1110"], f"Failed password for {user} from {ip} port 443 ssh2 (idp)"
        elif country not in ("US", ""):
            sev, title, tech, line = "MEDIUM", f"Sign-in for {user} from {country}", ["T1078"], f"Accepted password for {user} from {ip} port 443 ssh2 (idp, country {country})"
        else:
            sev, title, tech, line = "INFO", f"Sign-in for {user}", [], f"Accepted password for {user} from {ip} port 443 ssh2 (idp)"
    else:
        sev, tx = IAM_RULES[ev]
        title, tech, line = f"{ev.split('.')[-1].replace('_', ' ').title()} for {user}", _techs(tx), f"idp: {ev} user={user} from {ip}"
    return Signal("IAM", "auth", ts, sev, title, user=user, src_ip=ip, techniques=tech, description=f"{ev} {result}", raw=_line(ts, "idp", line))


CLOUD_RULES = {"PutBucketAcl": ("INFO", ""), "GetObject": ("INFO", ""), "CreateAccessKey": ("MEDIUM", "T1098.001"), "StopLogging": ("CRITICAL", "T1562.008"),
               "DescribeInstances": ("INFO", ""), "ListBuckets": ("INFO", ""), "AssumeRole": ("INFO", "")}


def cloud(p: dict) -> Signal:
    ts = _ts(p.get("eventTime"))
    name = p.get("eventName")
    if name not in CLOUD_RULES:
        raise Reject(f"unsupported cloud event {str(name)[:30]!r}")
    sev, tech = CLOUD_RULES[name]
    params = p.get("requestParameters") or {}
    user = (p.get("userIdentity") or {}).get("userName", "")
    title = name
    if name == "PutBucketAcl" and "AllUsers" in str(params.get("AccessControlList", "")):
        sev, tech, title = "HIGH", "T1530", f"Bucket {params.get('bucketName', '?')} made public"
    if name == "GetObject" and user == "anonymous":
        sev, tech, title = "MEDIUM", "T1530", f"Anonymous download from {params.get('bucketName', '?')}"
    return Signal("Cloud", "cloud", ts, sev, title, user=user, src_ip=p.get("sourceIPAddress", ""), techniques=_techs(tech), description=f"{name} {params}"[:300],
                  raw=_line(ts, "cloudtrail", f"{name} user={user} from {p.get('sourceIPAddress', '')} {params}"))


def email(p: dict) -> Signal:
    ts = _ts(p.get("received"))
    verdict = str(p.get("verdict", "")).lower()
    sev = {"malicious": "HIGH", "suspicious": "MEDIUM", "clean": "INFO"}.get(verdict)
    if not sev:
        raise Reject(f"unknown verdict {verdict[:15]!r}")
    urls = " ".join(p.get("urls") or [])
    return Signal("Email", "phish", ts, sev, f"Reported email ({verdict}): {p.get('subject', '')[:80]}", user=p.get("reported_by") or "", techniques=_techs("T1566") if verdict != "clean" else [],
                  description=f"from {p.get('sender')} urls {urls} attachments {' '.join(p.get('attachments') or [])}"[:300], raw=_line(ts, "mail-gw", f"reported phish from {p.get('sender')} {urls} {' '.join(p.get('attachments') or [])}"))


CONNECTORS = {"SIEM": siem, "EDR": edr, "ITSM": itsm, "Scanner": scanner, "IAM": iam, "Cloud": cloud, "Email": email}
DISPLAY = {"SIEM": "Splunk-style SIEM", "EDR": "CrowdStrike-style EDR", "ITSM": "ServiceNow-style ITSM", "Scanner": "Tenable-style scanner", "IAM": "Okta-style IdP",
           "Cloud": "CloudTrail-style audit", "Email": "Email security reports"}
