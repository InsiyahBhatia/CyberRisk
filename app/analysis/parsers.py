"""Parse uploaded logs/events (CSV, JSON, JSON-lines, plain text: syslog/auth.log/web access logs) into normalised events."""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone

MAX_EVENTS = 200_000
MAX_RAW = 600
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
ISO_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}(?::\d{2})?)(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
SYSLOG_RE = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
APACHE_RE = re.compile(r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)[^"]*" (?P<status>\d{3}) (?P<bytes>\d+|-)(?: "[^"]*" "(?P<ua>[^"]*)")?')
FAILED_PW = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)", re.I)
INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)", re.I)
ACCEPTED = re.compile(r"Accepted (?:password|publickey|keyboard-interactive\S*) for (?P<user>\S+) from (?P<ip>\S+)", re.I)
USER_KV = re.compile(r"\b(?:user(?:name)?|account(?:name)?|targetusername)\s*[=:]\s*['\"]?([\w.\\@-]+)", re.I)
FAIL_WORDS = re.compile(r"failed (?:login|logon|password|authentication)|authentication fail|login fail|logon failure|invalid (?:credentials|password)|access denied for user|bad password|an account failed to log on", re.I)
OK_WORDS = re.compile(r"login success|logged in|successful (?:login|logon|authentication)|authentication success|logon success|session opened for user|an account was successfully logged on|accepted (?:password|publickey)", re.I)
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

COLS = {
    "ts": ("timestamp", "time", "@timestamp", "date", "datetime", "_time", "eventtime", "event_time", "created", "timegenerated", "timecreated", "time_created", "systemtime", "logtime", "log_time", "occurred", "event_timestamp"),
    "src_ip": ("src_ip", "source_ip", "sourceip", "ip", "client_ip", "clientip", "remote_addr", "remote_ip", "src", "sourceaddress", "ipaddress", "source_address", "c-ip", "sourcenetworkaddress"),
    "user": ("user", "username", "user_name", "account", "accountname", "targetusername", "account_name", "userid", "user_id", "subjectusername"),
    "event": ("event", "action", "event_type", "eventid", "event_id", "activity", "operation", "category", "type", "eventname"),
    "status": ("status", "result", "outcome", "status_code", "response_code", "sc-status", "http_status"),
    "url": ("url", "uri", "request", "path", "request_uri", "cs-uri-stem", "requesturl"),
    "method": ("method", "http_method", "cs-method"),
    "bytes": ("bytes", "bytes_out", "sent_bytes", "out_bytes", "bytes_sent", "sc-bytes", "bytesout", "size"),
    "command": ("command", "commandline", "command_line", "process_command_line", "cmd", "processcommandline", "cmdline"),
    "message": ("message", "msg", "description", "details", "log", "text", "raw", "line"),
}
EVENT_ID_ACTIONS = {"4625": "login_failed", "4624": "login_success", "1102": "log_cleared", "104": "log_cleared", "4720": "account_created", "4728": "group_add", "4732": "group_add", "4688": "process"}


def parse_ts(value) -> datetime | None:
    """Best-effort timestamp parse; returns naive UTC."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        if re.fullmatch(r"\d{10}(\.\d+)?", s):
            return datetime.fromtimestamp(float(s), tz=timezone.utc).replace(tzinfo=None)
        if re.fullmatch(r"\d{13}", s):
            return datetime.fromtimestamp(int(s) / 1000, tz=timezone.utc).replace(tzinfo=None)
        m = ISO_RE.search(s)
        if m:
            dt = datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}" + ("" if m.group(2).count(":") == 2 else ":00"))
            tz = m.group(3)
            if tz and tz != "Z":
                sign = 1 if tz[0] == "+" else -1
                hh, mm = int(tz[1:3]), int(tz[-2:])
                from datetime import timedelta
                dt = dt - sign * timedelta(hours=hh, minutes=mm)
            return dt
        if re.match(r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}", s):
            return datetime.strptime(s.split(" ")[0], "%d/%b/%Y:%H:%M:%S")
        m = SYSLOG_RE.match(s)
        if m:
            h, mi, se = map(int, m.group(3).split(":"))
            return datetime(datetime.now().year, MONTHS[m.group(1)], int(m.group(2)), h, mi, se)
    except (ValueError, OverflowError, OSError):
        return None
    return None


def _classify(text: str, event_hint: str = "") -> str:
    m = re.search(r"\b(\d{3,4})\b", event_hint or "")
    if m and m.group(1) in EVENT_ID_ACTIONS:
        return EVENT_ID_ACTIONS[m.group(1)]
    if FAILED_PW.search(text) or INVALID_USER.search(text) or FAIL_WORDS.search(text):
        return "login_failed"
    if ACCEPTED.search(text) or OK_WORDS.search(text):
        return "login_success"
    if re.search(r"event\s*id\s*1102|audit log was cleared|log cleared", text, re.I):
        return "log_cleared"
    return "other"


def _event(line: int, raw: str, **kw) -> dict:
    ev = {"line": line, "raw": raw[:MAX_RAW], "ts": None, "src_ip": None, "user": None, "action": "other", "status": None, "method": None, "url": None, "bytes": None, "command": None}
    ev.update(kw)
    if isinstance(ev["ts"], datetime):
        ev["ts"] = ev["ts"].isoformat()
    return ev


def _parse_text_line(i: int, line: str) -> dict | None:
    line = line.rstrip("\r\n")
    if not line.strip():
        return None
    m = APACHE_RE.match(line)
    if m:
        d = m.groupdict()
        return _event(i, line, ts=parse_ts(d["ts"]), src_ip=d["ip"], user=None if d["user"] == "-" else d["user"], action="request", status=d["status"], method=d["method"], url=d["url"],
                      bytes=None if d["bytes"] == "-" else int(d["bytes"]))
    ip, user = None, None
    for rx in (FAILED_PW, INVALID_USER, ACCEPTED):
        mm = rx.search(line)
        if mm:
            ip, user = mm.group("ip"), mm.group("user")
            break
    if ip is None:
        mi = IP_RE.search(line)
        ip = mi.group(0) if mi else None
        mu = USER_KV.search(line)
        user = mu.group(1) if mu else None
    ts = None
    mt = ISO_RE.search(line)
    if mt:
        ts = parse_ts(mt.group(0))
    else:
        ms = SYSLOG_RE.match(line)
        if ms:
            ts = parse_ts(ms.group(0))
    return _event(i, line, ts=ts, src_ip=ip, user=user, action=_classify(line))


def _pick(row: dict, keys: tuple[str, ...]):
    low = {re.sub(r"[^a-z0-9@_.-]", "", str(k).lower()): v for k, v in row.items()}
    for k in keys:
        v = low.get(k)
        if v not in (None, "", "-"):
            return v
    return None


def _row_event(i: int, row: dict) -> dict:
    flat = {k: ("" if v is None else str(v)) for k, v in row.items() if not isinstance(v, (dict, list))}
    raw = " | ".join(f"{k}={v}" for k, v in flat.items() if v != "")
    message = _pick(row, COLS["message"]) or ""
    event_hint = str(_pick(row, COLS["event"]) or "")
    text = f"{event_hint} {message} {raw}"
    ip = _pick(row, COLS["src_ip"])
    ip = ip if ip and IP_RE.fullmatch(str(ip).strip()) else (IP_RE.search(raw).group(0) if IP_RE.search(raw) else None)
    status = _pick(row, COLS["status"])
    action = _classify(text, event_hint)
    if action == "other" and re.fullmatch(r"(?i)fail(ed|ure)?|denied", str(status or "")) and re.search(r"(?i)log(in|on)|auth", text):
        action = "login_failed"
    if action == "other" and re.fullmatch(r"(?i)success(ful)?|ok|allowed", str(status or "")) and re.search(r"(?i)log(in|on)|auth", text):
        action = "login_success"
    url = _pick(row, COLS["url"])
    if action == "other" and url:
        action = "request"
    b = _pick(row, COLS["bytes"])
    try:
        b = int(float(b)) if b is not None else None
    except ValueError:
        b = None
    return _event(i, raw or message, ts=parse_ts(_pick(row, COLS["ts"])), src_ip=str(ip).strip() if ip else None, user=str(_pick(row, COLS["user"]) or "") or None, action=action,
                  status=str(status) if status is not None else None, method=_pick(row, COLS["method"]), url=url, bytes=b, command=_pick(row, COLS["command"]))


def parse(data: bytes, filename: str = "") -> tuple[list[dict], dict]:
    text = data.decode("utf-8", errors="replace")
    name = filename.lower()
    events: list[dict] = []
    fmt = "text"
    stripped = text.lstrip()
    try:
        if name.endswith(".json") or (stripped[:1] in "[{" and not name.endswith((".log", ".txt"))):
            whole = stripped[:1] == "[" or (stripped[:1] == "{" and "\n{" not in stripped)
            payload = json.loads(text) if whole else [json.loads(l) for l in text.splitlines() if l.strip()]
            if isinstance(payload, dict):
                payload = next((v for v in payload.values() if isinstance(v, list)), [payload])
            events = [_row_event(i, r if isinstance(r, dict) else {"message": str(r)}) for i, r in enumerate(payload[:MAX_EVENTS], 1)]
            fmt = "json" if whole else "jsonl"
        elif name.endswith(".jsonl") or name.endswith(".ndjson"):
            events = [_row_event(i, json.loads(l)) for i, l in enumerate(text.splitlines()[:MAX_EVENTS], 1) if l.strip()]
            fmt = "jsonl"
        elif name.endswith(".csv") or (name.endswith(".txt") is False and text.splitlines()[:1] and text.splitlines()[0].count(",") >= 2 and not APACHE_RE.match(text.splitlines()[0])):
            rows = list(csv.DictReader(io.StringIO(text)))
            if rows and len(rows[0]) >= 2:
                events = [_row_event(i, r) for i, r in enumerate(rows[:MAX_EVENTS], 2)]
                fmt = "csv"
    except (json.JSONDecodeError, csv.Error, StopIteration):
        events = []
    if not events:
        fmt = "text"
        for i, line in enumerate(text.splitlines()[:MAX_EVENTS], 1):
            ev = _parse_text_line(i, line)
            if ev:
                events.append(ev)
    meta = {"format": fmt, "events": len(events), "with_timestamp": sum(1 for e in events if e["ts"]), "with_ip": sum(1 for e in events if e["src_ip"]), "truncated": len(events) >= MAX_EVENTS}
    tss = sorted(e["ts"] for e in events if e["ts"])
    meta["first_event"], meta["last_event"] = (tss[0], tss[-1]) if tss else (None, None)
    return events, meta
