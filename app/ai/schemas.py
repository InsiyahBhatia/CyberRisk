"""Structured response schema the model must produce. Scores/levels are NOT model-owned: they are attached server-side."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    statement: str = Field(min_length=3, max_length=600)
    type: Literal["organizational", "framework"] = "organizational"  # organizational = about our data; framework = about a standard/policy
    evidence_ids: list[str] = Field(default_factory=list, max_length=12)


class Action(BaseModel):
    action: str = Field(min_length=3, max_length=400)
    rationale: str = Field(default="", max_length=400)
    requires_human_approval: bool = True


class Citation(BaseModel):
    source_id: str
    title: str = ""
    section: str = ""


class AIAnswer(BaseModel):
    summary: str = Field(min_length=1, max_length=1500)
    findings: list[Finding] = Field(default_factory=list, max_length=12)
    recommended_actions: list[Action] = Field(default_factory=list, max_length=8)
    citations: list[Citation] = Field(default_factory=list, max_length=20)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    confidence: float = Field(ge=0, le=1)
    insufficient_evidence: bool = False
    clarification: str | None = Field(None, max_length=400)
