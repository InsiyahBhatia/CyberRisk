"""Guarded AI request pipeline:
user query -> input guardrail -> deterministic facts -> RAG retrieval -> RAG guardrail -> context assembly -> Gemini
-> output guardrail (+ one repair attempt) -> citation/evidence validation -> audit log -> response.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from sqlalchemy import Connection

from app.ai import prompts
from app.ai.context import Facts
from app.ai.llm import LLMClient, LLMUnavailable, schema_hint
from app.ai.schemas import AIAnswer
from app.config import get_settings
from app.db.session import execute, one
from app.guardrails import input as input_guard
from app.guardrails import output as output_guard
from app.guardrails import rag as rag_guard
from app.rag.retrieve import KnowledgeIndex, citation, get_index

TASKS_NEEDING_REVIEW = {"mapping", "executive_summary"}  # may be shared externally / change compliance status -> human review


@dataclass
class AIResult:
    status: str                       # OK | BLOCKED | ABSTAINED | OUTPUT_REJECTED | UNAVAILABLE
    message: str = ""
    answer: dict | None = None
    deterministic: dict = field(default_factory=dict)
    citations: list[dict] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    guardrails: dict = field(default_factory=dict)
    validation: dict = field(default_factory=dict)
    retrieval: dict = field(default_factory=dict)
    requires_approval: bool = False
    interaction_id: int | None = None
    model: str = ""
    prompt_version: str = prompts.PROMPT_VERSION

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _abstain_answer(clarification: str) -> dict:
    return AIAnswer(summary="Insufficient evidence to answer this reliably.", insufficient_evidence=True, confidence=0.0, clarification=clarification).model_dump()


def _log(conn: Connection, *, enabled: bool = True, task: str, query: str, sanitized: str, model: str, retrieval_ids: list[str], response: dict | None,
         grounding: float | None, guardrail_status: str, validation: dict, requires_approval: bool) -> int | None:
    if not enabled:
        return None  # eval runs are not written to the governance log
    res = execute(conn, """INSERT INTO ai_interactions (task, user_query, sanitized_query, model, prompt_version, retrieval_ids, retrieval_count, response,
                              grounding_score, guardrail_status, output_validation, requires_approval)
                           VALUES (:task,:q,:sq,:m,:pv,:rid,:rc,:resp,:g,:gs,:ov,:ra)""",
                   task=task, q=sanitized, sq=sanitized, m=model, pv=prompts.PROMPT_VERSION, rid=json.dumps(retrieval_ids), rc=len(retrieval_ids),
                   resp=json.dumps(response) if response else None, g=grounding, gs=guardrail_status, ov=json.dumps(validation), ra=int(requires_approval))
    return res.lastrowid


def run_task(conn: Connection, task: str, question: str, facts: Facts, llm: LLMClient | None, *, use_rag: bool = True, k: int = 5,
             index: KnowledgeIndex | None = None, require_scope: bool = True, extra_chunks: list[dict] | None = None, log: bool = True) -> AIResult:
    """`extra_chunks` lets the eval harness inject retrieved context (e.g. poisoned documents) through the same guardrails."""
    model = getattr(llm, "model", "") if llm else ""
    index = index or get_index()

    # 1. input guardrail
    gi = input_guard.check_input(question, require_scope=require_scope) if question else input_guard.InputResult(True, "PASSED", "")
    guard_info = {"input_status": gi.status, "input_flags": gi.flags, "pii_redacted": gi.pii_types}
    if not gi.allowed:
        label = "[blocked: " + ",".join(gi.flags) + "]"
        iid = _log(conn, enabled=log, task=task, query=label, sanitized=label, model=model, retrieval_ids=[], response=None, grounding=None,
                   guardrail_status="BLOCKED", validation={"blocked": gi.flags}, requires_approval=False)
        return AIResult("BLOCKED", gi.refusal or "Request blocked.", guardrails=guard_info, interaction_id=iid, model=model)

    # 2-3. retrieval + RAG guardrail
    chunks: list[dict] = []
    retrieval_meta = {"ids": [], "index_version": index.index_version, "top_score": 0.0, "confident": False, "dropped_poisoned": []}
    if use_rag:
        query = " ".join(x for x in (gi.sanitized, facts.retrieval_query) if x).strip()
        r = index.retrieve(conn, query, k)
        san = rag_guard.sanitize_chunks(r.chunks)
        chunks = san.clean
        retrieval_meta = {"ids": [c["id"] for c in chunks], "index_version": r.index_version, "top_score": r.top_score, "confident": r.confident,
                          "dropped_poisoned": san.flagged}
    if extra_chunks:
        san = rag_guard.sanitize_chunks(extra_chunks)
        chunks += san.clean
        retrieval_meta["ids"] += [c["id"] for c in san.clean]
        retrieval_meta["dropped_poisoned"] += san.flagged
    guard_info["rag_chunks_dropped"] = len(retrieval_meta["dropped_poisoned"])

    # abstain without calling the model when there is nothing to ground an answer on
    confident_kb = bool(chunks) and (retrieval_meta["confident"] or bool(extra_chunks))
    if (not facts.items and not confident_kb) or (task == "rag_answer" and not confident_kb):
        ans = _abstain_answer("No relevant organisational facts or knowledge-base passages were found. Add a source document or rephrase the question.")
        iid = _log(conn, enabled=log, task=task, query=gi.sanitized, sanitized=gi.sanitized, model=model, retrieval_ids=retrieval_meta["ids"], response=ans,
                   grounding=1.0, guardrail_status=gi.status, validation={"abstained": "no evidence"}, requires_approval=False)
        return AIResult("ABSTAINED", "Insufficient evidence.", ans, facts.deterministic, [], [], guard_info, {}, retrieval_meta, False, iid, model)

    # 4. context assembly
    facts_json = json.dumps(facts.items, indent=1, default=str)
    knowledge = rag_guard.fence(chunks)
    context_text = facts_json + "\n" + "\n".join(c["content"] for c in chunks)
    allowed = output_guard.AllowedContext(evidence_ids=set(facts.items) | {c["id"] for c in chunks}, kb_ids={c["id"] for c in chunks},
                                          context_text=context_text, risk_level=facts.risk_level, numbers=output_guard.numbers_in(facts_json))
    system = prompts.SYSTEM_PROMPT
    user = prompts.build_user_prompt(task, gi.sanitized, facts_json, knowledge, schema_hint(AIAnswer))

    # 5. model call + output guardrail (one repair attempt)
    if llm is None:
        return AIResult("UNAVAILABLE", "No LLM API key is configured (GROQ_API_KEY or GEMINI_API_KEY).", guardrails=guard_info, model=model)
    result = None
    attempt_user = user
    for attempt in range(2):
        try:
            raw = llm.generate_json(system, attempt_user)
        except LLMUnavailable as exc:
            return AIResult("UNAVAILABLE", str(exc), guardrails=guard_info, retrieval=retrieval_meta, model=model)
        result = output_guard.validate_output(raw, allowed)
        if result.valid:
            break
        attempt_user = (
            user
            + "\n\n<PREVIOUS_RESPONSE_REJECTED>\n"
            + "; ".join(result.errors)[:600]
            + f"\nValid evidence/citation IDs you are allowed to use are ONLY: {', '.join(sorted(allowed.evidence_ids))}"
            + "\nReturn corrected JSON that fixes these problems and follows every rule.\n</PREVIOUS_RESPONSE_REJECTED>"
        )

    model = getattr(llm, "model", model)  # the model that actually answered (may be a fallback)
    validation = result.summary() | {"attempts": attempt + 1}
    if not result.valid:
        iid = _log(conn, enabled=log, task=task, query=gi.sanitized, sanitized=gi.sanitized, model=model, retrieval_ids=retrieval_meta["ids"], response=None,
                   grounding=result.grounding_score, guardrail_status=gi.status, validation=validation, requires_approval=False)
        return AIResult("OUTPUT_REJECTED", "The model response failed validation and was withheld.", None, facts.deterministic, [], [], guard_info, validation, retrieval_meta, False, iid, model)

    # 6. attach authoritative metadata (titles/sections come from the store, not the model) and deterministic values
    answer = result.answer
    by_id = {c["id"]: c for c in chunks}
    cites = [citation(by_id[c.source_id]) for c in answer.citations if c.source_id in by_id]
    evidence = [{"id": i, "kind": "database" if i.startswith("DB:") else "knowledge", "summary": _summ(facts.items.get(i) or by_id.get(i))}
                for i in dict.fromkeys(e for f in answer.findings for e in f.evidence_ids)]
    needs_review = task in TASKS_NEEDING_REVIEW or any(a.requires_human_approval for a in answer.recommended_actions)
    out = answer.model_dump()
    if facts.risk_level:
        out["risk_level"] = facts.risk_level  # deterministic value always wins
    iid = _log(conn, enabled=log, task=task, query=gi.sanitized, sanitized=gi.sanitized, model=model, retrieval_ids=retrieval_meta["ids"], response=out,
               grounding=result.grounding_score, guardrail_status=gi.status, validation=validation, requires_approval=needs_review)
    note = f"Answered by fallback model {model} because {llm.primary} was unavailable." if getattr(llm, "fell_back", False) else ""
    return AIResult("OK", note, out, facts.deterministic, cites, evidence, guard_info, validation, retrieval_meta, needs_review, iid, model)


def _summ(item) -> str:
    if not item:
        return ""
    if "content" in item:
        return f"{item.get('title', '')} - {item.get('section', '')}"
    return ", ".join(f"{k}={v}" for k, v in list(item.items())[:6])[:200]


def parse_mapping_suggestions(conn: Connection, risk_id: int, interaction_id: int, answer: dict) -> int:
    """Persist AI mapping suggestions as PENDING rows; they never count as compliance until a human approves them."""
    n = 0
    for f in answer.get("findings", []):
        if f.get("type") != "framework":
            continue
        for ev in f.get("evidence_ids", []):
            km = re.match(r"^KB:doc(\d+):c(\d+)$", ev)
            chunk = one(conn, """SELECT c.section, d.framework FROM document_chunks c JOIN documents d ON d.id=c.document_id
                                 WHERE c.document_id=:d AND c.chunk_index=:i""", d=int(km.group(1)), i=int(km.group(2))) if km else None
            if not chunk:
                continue
            m = re.match(r"^([A-Z]{2}\.[A-Z]{2}-\d{2}|A\.\d{1,2}\.\d{1,2}|CC\d\.\d|A1\.\d)\b", chunk.get("section", ""))
            if not m:
                continue
            ctl = one(conn, """SELECT c.id, c.framework_id FROM controls c JOIN frameworks fw ON fw.id=c.framework_id
                               WHERE c.control_code=:c AND fw.name=:fw""", c=m.group(1), fw=chunk.get("framework"))
            if not ctl:
                continue
            if one(conn, "SELECT 1 AS x FROM control_mappings WHERE source_type='risk' AND source_id=:r AND control_id=:c", r=risk_id, c=ctl["id"]):
                continue
            execute(conn, """INSERT INTO control_mappings (source_type, source_id, framework_id, control_id, mapping_reason, confidence, origin, review_state, ai_interaction_id)
                             VALUES ('risk',:r,:fw,:c,:why,:conf,'AI_SUGGESTED','PENDING',:i)""",
                    r=risk_id, fw=ctl["framework_id"], c=ctl["id"], why=f["statement"][:500], conf=answer.get("confidence", 0.5), i=interaction_id)
            n += 1
    return n
