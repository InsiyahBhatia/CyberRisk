"""Retrieval over ACTIVE (trusted, non-quarantined) chunks with scores, citation metadata and low-confidence detection."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from sqlalchemy import Connection

from app.db.session import rows
from app.rag.store import TfidfVectorStore, VectorStore

MIN_CONFIDENT_SCORE = 0.12   # top hit below this => treat retrieval as insufficient
MAX_PER_DOC = 2              # diversity: at most this many chunks per document in a result


@dataclass
class Retrieval:
    chunks: list[dict]
    confident: bool
    top_score: float
    index_version: str

    @property
    def ids(self) -> list[str]:
        return [c["id"] for c in self.chunks]


class KnowledgeIndex:
    """Index over document_chunks. Rebuilt lazily when the stored chunk set changes (version = hash of chunk ids+checksums)."""

    def __init__(self, store: VectorStore | None = None):
        self.store = store or TfidfVectorStore()
        self._version: str | None = None
        self._chunks: dict[str, dict] = {}

    def _load(self, conn: Connection) -> None:
        data = rows(conn, """SELECT c.id, c.document_id, c.chunk_index, c.section, c.content, d.title, d.framework, d.version, d.source_type, d.checksum
                             FROM document_chunks c JOIN documents d ON d.id=c.document_id WHERE d.status='ACTIVE' AND d.trusted=1 ORDER BY c.id""")
        version = hashlib.sha256("|".join(f"{r['id']}:{r['checksum']}" for r in data).encode()).hexdigest()[:12]
        if version == self._version:
            return
        self._chunks = {f"KB:doc{r['document_id']}:c{r['chunk_index']}": {**r, "id": f"KB:doc{r['document_id']}:c{r['chunk_index']}"} for r in data}
        self.store.build(list(self._chunks), [f"{c['title']} {c['section']} {c['content']}" for c in self._chunks.values()])
        self._version = version

    def retrieve(self, conn: Connection, query: str, k: int = 5) -> Retrieval:
        self._load(conn)
        raw_hits = self.store.search(query, k * 4)
        per_doc: dict[int, int] = {}
        chosen = []
        for h in raw_hits:
            c = self._chunks[h.chunk_id]
            if per_doc.get(c["document_id"], 0) >= MAX_PER_DOC:
                continue
            per_doc[c["document_id"]] = per_doc.get(c["document_id"], 0) + 1
            chosen.append({**c, "score": round(h.score, 4)})
            if len(chosen) >= k:
                break
        top = chosen[0]["score"] if chosen else 0.0
        return Retrieval(chosen, top >= MIN_CONFIDENT_SCORE, top, self._version or "empty")

    @property
    def index_version(self) -> str:
        return self._version or "unbuilt"


_index = KnowledgeIndex()


def get_index() -> KnowledgeIndex:
    return _index


def citation(chunk: dict) -> dict:
    return {"source_id": chunk["id"], "title": chunk["title"], "section": chunk["section"], "score": chunk.get("score"),
            "framework": chunk.get("framework"), "version": chunk.get("version")}
