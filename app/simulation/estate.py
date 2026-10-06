"""The simulated organisation's footprint: hosts, users and external actors that events refer to."""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from sqlalchemy import Connection

from app.db.session import rows

SURNAMES = ["Alvarez", "Bennett", "Chen", "Dasgupta", "Eriksen", "Fofana", "Grant", "Hughes", "Ito", "Jovanovic", "Kowalski", "Lindqvist", "Mbeki", "Novak", "Okafor", "Petrov",
            "Quinn", "Rossi", "Silva", "Tanaka", "Underwood", "Varga", "Whitlock", "Yilmaz", "Zhao"]
FIRSTS = "abcdefghijklmnoprstw"
ATTACKER_IPS = ["198.51.100.23", "198.51.100.77", "203.0.113.9", "203.0.113.45", "192.0.2.150", "192.0.2.201", "198.51.100.140"]  # documentation ranges: clearly not real
ATTACKER_COUNTRIES = ["RU", "CN", "KP", "IR", "NG", "BR"]
HOST_KINDS = [("web", "Web Application", True, "Engineering"), ("api", "Web Application", True, "Engineering"), ("db", "Database", False, "IT Infrastructure"), ("fs", "Server", False, "Operations"),
              ("vpn", "Network Device", True, "IT Infrastructure"), ("wks", "Workstation", False, "Sales"), ("fin", "Server", False, "Finance"), ("hr", "Server", False, "Human Resources")]


def ip_for(tag: str) -> str:
    h = hashlib.sha256(tag.encode()).digest()
    return f"10.{h[0] % 200 + 10}.{h[1] % 250 + 1}.{h[2] % 250 + 1}"


@dataclass
class Host:
    tag: str
    name: str
    ip: str
    criticality: str = "MEDIUM"
    exposed: bool = False
    business_unit: str = ""
    asset_id: int | None = None


@dataclass
class Estate:
    hosts: list[Host] = field(default_factory=list)
    users: list[str] = field(default_factory=list)

    def by_name(self) -> dict[str, Host]:
        m = {}
        for h in self.hosts:
            m[h.tag.lower()] = h
            m[h.name.lower()] = h
        return m

    def pick(self, rnd: random.Random, exposed: bool | None = None, crit: tuple[str, ...] | None = None) -> Host:
        pool = [h for h in self.hosts if (exposed is None or h.exposed == exposed) and (crit is None or h.criticality in crit)] or self.hosts
        return rnd.choice(pool)


def make_users(rnd: random.Random, n: int = 40) -> list[str]:
    seen, out = set(), []
    while len(out) < n:
        u = f"{rnd.choice(FIRSTS)}{rnd.choice(SURNAMES).lower()}"
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def generated_assets(rnd: random.Random, n: int = 24) -> list[dict]:
    """Rows in the `assets` import format, used to seed an empty workspace so events map to a real inventory."""
    out = []
    for i in range(1, n + 1):
        kind, typ, exposed, bu = HOST_KINDS[(i - 1) % len(HOST_KINDS)]
        tag = f"SIM-{kind.upper()}-{i:02d}"
        crit = rnd.choices(["LOW", "MEDIUM", "HIGH", "CRITICAL"], [10, 30, 35, 25] if kind in ("db", "fin", "fs", "web") else [30, 40, 25, 5])[0]
        out.append({"asset_id": f"S{i:03d}", "asset_tag": tag, "hostname": tag.lower(), "asset_type": typ, "business_unit": bu, "owner_role": "Platform Owner", "criticality": crit.title(),
                    "internet_exposed": "yes" if exposed else "no", "data_classification": "Confidential" if kind in ("db", "fin", "hr") else "Internal", "environment": "Production", "status": "Active"})
    return out


def load_estate(conn: Connection, rnd: random.Random, limit: int = 120) -> Estate:
    assets = rows(conn, "SELECT id, asset_tag, name, criticality, internet_exposed, business_unit FROM assets WHERE status='ACTIVE' ORDER BY (criticality='CRITICAL') DESC, id LIMIT :l", l=limit)
    hosts = [Host(a["asset_tag"], a["name"], ip_for(a["asset_tag"]), a["criticality"], bool(a["internet_exposed"]), a["business_unit"] or "", a["id"]) for a in assets]
    return Estate(hosts, make_users(rnd))
