"""VectorStore interface + a lightweight local TF-IDF implementation (scikit-learn).

The interface keeps the implementation replaceable (e.g. Gemini embeddings + Chroma/FAISS) without touching callers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

import numpy as np


@dataclass
class Hit:
    chunk_id: str
    score: float


class VectorStore(ABC):
    @abstractmethod
    def build(self, ids: list[str], texts: list[str]) -> None: ...

    @abstractmethod
    def search(self, query: str, k: int, allowed_ids: set[str] | None = None) -> list[Hit]: ...

    @property
    @abstractmethod
    def size(self) -> int: ...


class TfidfVectorStore(VectorStore):
    name = "tfidf-cosine"

    def __init__(self) -> None:
        self._ids: list[str] = []
        self._vectorizer = None
        self._matrix = None

    def build(self, ids: list[str], texts: list[str]) -> None:
        from sklearn.feature_extraction.text import TfidfVectorizer

        self._ids = list(ids)
        if not texts:
            self._vectorizer, self._matrix = None, None
            return
        self._vectorizer = TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2), sublinear_tf=True, token_pattern=r"(?u)\b[\w.&-]{2,}\b")
        self._matrix = self._vectorizer.fit_transform(texts)  # rows are L2-normalised -> dot product == cosine

    def search(self, query: str, k: int, allowed_ids: set[str] | None = None) -> list[Hit]:
        if self._vectorizer is None or not query.strip():
            return []
        q = self._vectorizer.transform([query])
        sims = (self._matrix @ q.T).toarray().ravel()
        order = np.argsort(-sims)
        hits: list[Hit] = []
        for i in order:
            if sims[i] <= 0:
                break
            if allowed_ids is not None and self._ids[i] not in allowed_ids:
                continue
            hits.append(Hit(self._ids[i], float(sims[i])))
            if len(hits) >= k:
                break
        return hits

    @property
    def size(self) -> int:
        return len(self._ids)
