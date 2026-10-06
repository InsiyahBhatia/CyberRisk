"""Document ingestion: parse -> clean -> chunk -> metadata -> SQLite; the vector index is rebuilt from stored chunks.

Ingestion guardrail: documents whose text trips the injection rules are QUARANTINED (stored, never retrievable).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import Connection

from app.db.session import execute, one, rows, scalar
from app.guardrails import rules
from app.rag import chunking

KB_DIR = Path(__file__).resolve().parents[2] / "knowledge_base"


def chunk_id(doc_id: int, idx: int) -> str:
    return f"KB:doc{doc_id}:c{idx}"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ingest_text(conn: Connection, raw: str, fallback_title: str, *, trusted: bool = True, force_source_type: str | None = None, scan: bool = True) -> dict:
    """Returns {document_id, status, chunks, flags}. Re-ingesting identical content is a no-op."""
    checksum = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    existing = one(conn, "SELECT id, status FROM documents WHERE checksum=:c", c=checksum)
    if existing:
        return {"document_id": existing["id"], "status": existing["status"], "chunks": scalar(conn, "SELECT COUNT(*) FROM document_chunks WHERE document_id=:d", d=existing["id"]), "flags": [], "duplicate": True}
    doc = chunking.parse_markdown(raw, fallback_title)
    flags = rules.find_injection(doc.text) if scan else []  # structured official data skips the doc-level scan; retrieval still sanitises chunks
    status = "QUARANTINED" if (flags or not trusted) else "ACTIVE"
    res = execute(conn, """INSERT INTO documents (title, source_type, framework, version, checksum, status, trusted, ingested_at)
                           VALUES (:t,:s,:f,:v,:c,:st,:tr,:at)""",
                  t=doc.title, s=force_source_type or doc.source_type, f=doc.framework, v=doc.version, c=checksum, st=status, tr=int(trusted and not flags), at=_now())
    doc_id = res.lastrowid
    chunks = chunking.chunk_sections(doc.text)
    for i, (section, content) in enumerate(chunks):
        meta = {"document_id": doc_id, "title": doc.title, "framework": doc.framework, "version": doc.version, "section": section,
                "source_type": force_source_type or doc.source_type, "checksum": checksum}
        execute(conn, "INSERT INTO document_chunks (document_id, chunk_index, section, content, metadata_json) VALUES (:d,:i,:s,:c,:m)",
                d=doc_id, i=i, s=section, c=content, m=json.dumps(meta))
    return {"document_id": doc_id, "status": status, "chunks": len(chunks), "flags": flags, "duplicate": False}


def ingest_knowledge_base(conn: Connection, directory: Path | None = None) -> list[dict]:
    out = []
    for p in sorted((directory or KB_DIR).glob("*.md")):
        r = ingest_text(conn, p.read_text(encoding="utf-8"), p.stem.replace("_", " ").title())
        out.append({"file": p.name, **r})
    return out


def ingest_reference_data(conn: Connection) -> list[dict]:
    """Authoritative structured reference content -> documents: curated framework controls and public ATT&CK technique descriptions."""
    out = []
    for fw in rows(conn, "SELECT id, name, version FROM frameworks WHERE name != 'MITRE ATT&CK'"):
        ctl = rows(conn, "SELECT control_code, title, category, description FROM controls WHERE framework_id=:f ORDER BY control_code", f=fw["id"])
        if not ctl:
            continue
        body = "\n\n".join(f"## {c['control_code']} {c['title']}\n{c['control_code']} ({c['category']}): {c['title']}. {c['description']}" for c in ctl)
        raw = f"# {fw['name']} {fw['version']} control reference (curated)\nFramework: {fw['name']}\nVersion: {fw['version']}\nSource type: curated framework reference\n\n{body}"
        out.append({"file": f"framework:{fw['name']}", **ingest_text(conn, raw, fw["name"], scan=False)})
    techs = rows(conn, "SELECT technique_id, name, tactics, description FROM attack_techniques WHERE technique_id NOT LIKE '%.%' ORDER BY technique_id")
    if techs:
        body = "\n\n".join(f"## {t['technique_id']} {t['name']}\n{t['technique_id']} {t['name']} (tactics: {t['tactics']}). {t['description'][:700]}" for t in techs)
        ver = scalar(conn, "SELECT version FROM attack_techniques LIMIT 1")
        raw = f"# MITRE ATT&CK Enterprise technique reference\nFramework: MITRE ATT&CK\nVersion: {ver}\nSource type: public threat knowledge base\n\n{body}"
        out.append({"file": "mitre:attack", **ingest_text(conn, raw, "MITRE ATT&CK", scan=False)})
    return out
