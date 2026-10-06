"""Indicator extraction (IPs, domains, URLs, hashes, e-mails, CVEs, ATT&CK ids). Pure regex; defanged forms (hxxp, [.]) are normalised."""
from __future__ import annotations

import ipaddress
import re
from collections import Counter

IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|co|us|uk|de|fr|br|in|su|tk|ml|ga|cf|gq|cc|me|app|dev|cloud|online|site|tech|live|pw|ws)\b", re.I)
SHA256, SHA1, MD5 = (re.compile(rf"\b[a-fA-F0-9]{{{n}}}\b") for n in (64, 40, 32))
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
FILE_EXT = {"exe", "dll", "txt", "log", "php", "html", "js", "css", "png", "jpg", "gif", "json", "xml", "ini", "sys", "bat", "ps1", "sh", "py", "pdf", "doc", "docx", "zip"}


def refang(text: str) -> str:
    t = re.sub(r"hxxp", "http", text, flags=re.I)
    return t.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@")


def _ip_info(ip: str) -> dict:
    a = ipaddress.ip_address(ip)
    if a.is_global:
        scope = "public"
    elif a.is_loopback or a.is_link_local or any(a in n for n in RFC1918):
        scope = "private"
    else:
        scope = "reserved"  # documentation/test/CGNAT ranges: not routable on the internet
    return {"value": ip, "scope": scope}


def extract(text: str, limit: int = 40) -> dict:
    t = refang(text)
    ips = Counter(IPV4.findall(t))
    urls = Counter(URL.findall(t))
    emails = Counter(e.lower() for e in EMAIL.findall(t))
    email_domains = {e.split("@")[1] for e in emails}
    domains = Counter(d.lower() for d in DOMAIN.findall(t) if d.rsplit(".", 1)[-1].lower() not in FILE_EXT and d.lower() not in email_domains)
    sha256 = set(SHA256.findall(t))
    sha1 = {h for h in SHA1.findall(t) if not any(h in s for s in sha256)}
    md5 = {h for h in MD5.findall(t) if not any(h in s for s in sha256 | sha1)}
    return {
        "ips": [{**_ip_info(ip), "count": n} for ip, n in ips.most_common(limit)],
        "domains": [{"value": d, "count": n} for d, n in domains.most_common(limit)],
        "urls": [{"value": u[:200], "count": n} for u, n in urls.most_common(limit)],
        "emails": [{"value": e, "count": n} for e, n in emails.most_common(limit)],
        "hashes": [{"type": "sha256", "value": h} for h in sorted(sha256)[:limit]] + [{"type": "sha1", "value": h} for h in sorted(sha1)[:limit]] + [{"type": "md5", "value": h} for h in sorted(md5)[:limit]],
        "cves": sorted({c.upper() for c in CVE.findall(t)}),
        "technique_ids": sorted(set(TECH.findall(t))),
    }
