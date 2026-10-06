"""Transparent data-quality score.

quality_score = max(0, 100 - missing_required_penalty - invalid_value_penalty
                            - duplicate_penalty - referential_integrity_penalty)

Each penalty = weight x 100 x (affected rows / rows read).
Weights: missing 1.0, invalid 1.0, duplicates 0.5, referential 1.0.
"""
from __future__ import annotations

WEIGHTS = {"missing": 1.0, "invalid": 1.0, "duplicate": 0.5, "referential": 1.0}


def quality_score(read: int, missing: int = 0, invalid: int = 0, duplicates: int = 0, orphans: int = 0) -> dict:
    if read <= 0:
        return {"score": 0.0, "penalties": {}}
    pen = {
        "missing_required": WEIGHTS["missing"] * 100 * missing / read,
        "invalid_value": WEIGHTS["invalid"] * 100 * invalid / read,
        "duplicate": WEIGHTS["duplicate"] * 100 * duplicates / read,
        "referential_integrity": WEIGHTS["referential"] * 100 * orphans / read,
    }
    return {"score": round(max(0.0, 100 - sum(pen.values())), 1), "penalties": {k: round(v, 2) for k, v in pen.items()}}
