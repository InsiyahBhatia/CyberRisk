"""RAG, AI, governance and eval endpoints. Guardrails are internal services: no endpoint can disable them."""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import Connection

from app.ai import analytics, service
from app.ai.context import Facts, executive_facts, risk_facts
from app.ai.llm import LLMUnavailable, make_llm, resolve_provider
from app.ai.prompts import PROMPT_VERSION
from app.api.common import audit, not_found, paged
from app.config import get_settings
from app.db.session import connect, execute, get_conn, one, rows, scalar
from app.evals import runner as eval_runner
from app.guardrails import input as input_guard
from app.guardrails import rag as rag_guard
from app.guardrails.ratelimit import limit_ai
from app.rag import ingest as rag_ingest
from app.rag.retrieve import citation, get_index

router = APIRouter(prefix="/api", tags=["ai"])
MAX_DOC_BYTES = 1024 * 1024


class RiskQuestion(BaseModel):
    risk_id: int
    question: str = Field("", max_length=2000)


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class RagQuery(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    k: int = Field(5, ge=1, le=10)
    answer: bool = False


class Approval(BaseModel):
    decision: Literal["APPROVED", "REJECTED"]
    reviewer: str = Field(min_length=2, max_length=80)
    comments: str | None = Field(None, max_length=1000)


class EvalRun(BaseModel):
    mode: Literal["guardrails", "live"] = "guardrails"
    set_baseline: bool = False


def _llm():
    return make_llm()


def respond(res: service.AIResult):
    """Explicit HTTP codes: 200 OK/abstained, 400 blocked by guardrail, 502 output rejected, 503 model unavailable."""
    body = res.to_dict()
    if res.status in ("OK", "ABSTAINED"):
        return body
    code = {"BLOCKED": 400, "OUTPUT_REJECTED": 502, "UNAVAILABLE": 503}.get(res.status, 500)
    return JSONResponse(status_code=code, content={"error": {"code": code, "message": res.message, "status": res.status}, **body})


def _require_risk(conn: Connection, risk_id: int) -> Facts:
    f = risk_facts(conn, risk_id)
    if f is None:
        raise not_found("Risk")
    return f


# ------------------------------------------------------------------ status
@router.get("/ai/status")
def ai_status():
    s = get_settings()
    cfg = resolve_provider()
    return {"provider": cfg.label, "provider_id": cfg.provider, "model": cfg.model or s.gemini_model, "configured": cfg.provider != "none", "prompt_version": PROMPT_VERSION, "warning": cfg.warning or None}


@router.get("/ai/models")
def ai_models():
    """Models available to the configured key, to pick a valid GEMINI_MODEL when one is retired."""
    llm = _llm()
    if not llm.configured:
        raise HTTPException(503, "No LLM API key is configured (GROQ_API_KEY or GEMINI_API_KEY)")
    try:
        return {"provider": llm.label, "configured_model": llm.primary, "models": llm.list_models()}
    except LLMUnavailable as exc:
        raise HTTPException(502, str(exc))


# ------------------------------------------------------------------ RAG
@router.post("/rag/query", dependencies=[Depends(limit_ai)])
def rag_query(body: RagQuery, conn: Connection = Depends(get_conn)):
    gi = input_guard.check_input(body.query)
    if not gi.allowed:
        return JSONResponse(status_code=400, content={"error": {"code": 400, "message": gi.refusal, "status": "BLOCKED"}, "guardrails": {"input_flags": gi.flags}})
    r = get_index().retrieve(conn, gi.sanitized, body.k)
    san = rag_guard.sanitize_chunks(r.chunks)
    out = {"query": gi.sanitized, "confident": r.confident and bool(san.clean), "top_score": r.top_score, "index_version": r.index_version,
           "results": [{**citation(c), "content": c["content"]} for c in san.clean], "dropped_as_unsafe": san.flagged,
           "guardrails": {"input_status": gi.status, "pii_redacted": gi.pii_types}}
    if not out["confident"]:
        out["message"] = "Insufficient evidence in the knowledge base. Add a relevant source document or rephrase the question."
    if body.answer:
        res = service.run_task(conn, "rag_answer", body.query, Facts(), _llm(), use_rag=True, k=body.k)
        out["generated"] = respond(res) if res.status in ("OK", "ABSTAINED") else {"status": res.status, "message": res.message}
    return out


@router.post("/rag/documents/ingest", status_code=201)
async def rag_ingest_doc(file: UploadFile = File(...), conn: Connection = Depends(get_conn)):
    name = file.filename or "document"
    if not name.lower().endswith((".md", ".txt")):
        raise HTTPException(415, "Only .md and .txt documents are accepted")
    data = await file.read(MAX_DOC_BYTES + 1)
    if len(data) > MAX_DOC_BYTES:
        raise HTTPException(413, "Document exceeds 1 MB")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(422, "Document must be UTF-8 text")
    if not text.strip():
        raise HTTPException(422, "Document is empty")
    res = rag_ingest.ingest_text(conn, text, name.rsplit(".", 1)[0].replace("_", " ").title(), force_source_type="user-provided")
    audit(conn, "ingest_document", "document", res["document_id"], f"{name}: {res['status']}")
    if res["status"] == "QUARANTINED":
        res["message"] = "Document contains instruction-like content and was quarantined; it will not be retrieved."
    return res


@router.get("/rag/documents")
def rag_documents(conn: Connection = Depends(get_conn)):
    return {"items": rows(conn, """SELECT d.id, d.title, d.source_type, d.framework, d.version, d.status, d.trusted, d.ingested_at, d.checksum,
                                          (SELECT COUNT(*) FROM document_chunks c WHERE c.document_id=d.id) AS chunks FROM documents d ORDER BY d.id"""),
            "index_version": get_index().index_version}


# ------------------------------------------------------------------ AI tasks
@router.post("/ai/investigate", dependencies=[Depends(limit_ai)])
def investigate(body: RiskQuestion, conn: Connection = Depends(get_conn)):
    facts = _require_risk(conn, body.risk_id)
    return respond(service.run_task(conn, "investigate", body.question or "Investigate this risk and explain why it matters.", facts, _llm()))


@router.post("/ai/remediation", dependencies=[Depends(limit_ai)])
def remediation(body: RiskQuestion, conn: Connection = Depends(get_conn)):
    facts = _require_risk(conn, body.risk_id)
    return respond(service.run_task(conn, "remediation", body.question or "Recommend prioritised remediation for this risk.", facts, _llm()))


@router.post("/ai/executive-summary", dependencies=[Depends(limit_ai)])
def executive_summary(conn: Connection = Depends(get_conn)):
    return respond(service.run_task(conn, "executive_summary", "", executive_facts(conn), _llm()))


@router.post("/ai/suggest-mappings", dependencies=[Depends(limit_ai)])
def suggest_mappings(body: RiskQuestion, conn: Connection = Depends(get_conn)):
    facts = _require_risk(conn, body.risk_id)
    res = service.run_task(conn, "mapping", "Suggest framework control mappings for this risk.", facts, _llm())
    if res.status == "OK" and res.interaction_id:
        n = service.parse_mapping_suggestions(conn, body.risk_id, res.interaction_id, res.answer)
        res.message = f"{n} suggested mapping(s) saved as PENDING human review. They do not affect compliance figures until approved."
    return respond(res)


@router.post("/ai/natural-language-analytics", dependencies=[Depends(limit_ai)])
def nl_analytics(body: AskRequest, conn: Connection = Depends(get_conn)):
    gi = input_guard.check_input(body.question)
    if not gi.allowed:
        return respond(service.run_task(conn, "analytics", body.question, Facts(), None))  # logs the block, returns the refusal
    facts, intent = analytics.analytics_facts(conn, gi.sanitized)
    if facts is None:
        return JSONResponse(status_code=200, content={"status": "ABSTAINED", "message": "I can answer questions about: " + "; ".join(i.title for i in analytics.INTENTS) + ".",
                                                       "supported_questions": [i.title for i in analytics.INTENTS]})
    res = service.run_task(conn, "analytics", body.question, facts, _llm(), use_rag=False)
    payload = res.to_dict()
    payload["analytics"] = {"intent": intent.key, "title": intent.title, "rows": json.loads(json.dumps(next(iter(facts.items.values()))["rows"], default=str)),
                            "note": "Rows are produced by a fixed, parameterized query chosen by a deterministic router; the model only explains them."}
    if res.status in ("OK", "ABSTAINED", "UNAVAILABLE"):
        # the structured result is still valuable when Gemini is not configured
        return JSONResponse(status_code=200, content=payload) if res.status != "UNAVAILABLE" else JSONResponse(status_code=200, content={**payload, "explanation_unavailable": res.message})
    return respond(res)


# ------------------------------------------------------------------ governance
def _metric(value, basis: str, source: str) -> dict:
    return {"value": value, "basis": basis, "source": source}


@router.get("/ai-governance/summary")
def governance_summary(conn: Connection = Depends(get_conn)):
    s = get_settings()
    inter = rows(conn, "SELECT task, guardrail_status, grounding_score, requires_approval, output_validation, response FROM ai_interactions ORDER BY id DESC LIMIT 2000")
    answered = [i for i in inter if i["response"]]
    blocked = [i for i in inter if i["guardrail_status"] == "BLOCKED"]
    rejected = [i for i in inter if not i["response"] and i["guardrail_status"] != "BLOCKED" and '"valid": false' in (i["output_validation"] or "")]
    grounding = [i["grounding_score"] for i in answered if i["grounding_score"] is not None]
    latest = {m: one(conn, "SELECT * FROM ai_eval_runs WHERE status='COMPLETED' AND mode=:m ORDER BY id DESC LIMIT 1", m=m) for m in ("live", "guardrails")}
    cats = {m: (json.loads(r["category_scores"]) if r else None) for m, r in latest.items()}

    def cat(name: str, preferred=("live", "guardrails")):
        for m in preferred:
            v = (cats[m] or {}).get("categories", {}).get(name)
            if v is not None:
                return v, m
        return None, None

    inj, inj_mode = cat("prompt_injection")
    poi, _ = cat("rag_poisoning")
    pii, pii_mode = cat("pii")
    hal, hal_mode = cat("hallucination")
    sch = (cats["live"] or {}).get("schema_validity")
    approvals = rows(conn, "SELECT decision, COUNT(*) AS n FROM ai_approvals GROUP BY decision")
    pending = scalar(conn, """SELECT COUNT(*) FROM ai_interactions i WHERE i.requires_approval=1 AND i.response IS NOT NULL
                              AND NOT EXISTS (SELECT 1 FROM ai_approvals a WHERE a.ai_interaction_id=i.id)""")
    return {
        "model": {"provider": resolve_provider().label, "name": resolve_provider().model or s.gemini_model, "configured": resolve_provider().provider != "none", "warning": resolve_provider().warning or None},
        "versions": {"prompt": PROMPT_VERSION, "retrieval_index": get_index().index_version, "retrieval_method": "TF-IDF cosine (local)", "guardrails": "rules-v1"},
        "knowledge_base": {"active_documents": scalar(conn, "SELECT COUNT(*) FROM documents WHERE status='ACTIVE'"),
                           "quarantined_documents": scalar(conn, "SELECT COUNT(*) FROM documents WHERE status='QUARANTINED'"),
                           "chunks": scalar(conn, "SELECT COUNT(*) FROM document_chunks c JOIN documents d ON d.id=c.document_id WHERE d.status='ACTIVE'")},
        "interactions": {"total": scalar(conn, "SELECT COUNT(*) FROM ai_interactions"), "answered": len(answered), "blocked_by_input_guardrail": len(blocked),
                         "withheld_by_output_guardrail": len(rejected), "pending_human_review": pending,
                         "approvals": {a["decision"]: a["n"] for a in approvals}},
        "metrics": {
            "grounding_score": _metric(round(100 * sum(grounding) / len(grounding), 1) if grounding else None, "measured",
                                       "Runtime check on real interactions: share of findings whose evidence ids exist in the supplied context. Checks traceability, not semantic truth."),
            "injection_resistance": _metric(None if inj is None else round(((inj or 0) + (poi or 0)) / (2 if poi is not None else 1), 1), "measured" if inj is not None else "not_measured",
                                            f"Eval suite ({inj_mode or 'no run yet'}): direct injection + RAG poisoning cases."),
            "pii_leakage_failures": _metric(None if pii is None else (cats[pii_mode] or {}).get("pii_leak_failures"), "measured" if pii is not None else "not_measured",
                                            f"Eval suite ({pii_mode or 'no run yet'}): PII/secret cases that failed."),
            "hallucination_rate": _metric(None if hal is None else round(100 - hal, 1), "measured" if hal is not None else "not_measured",
                                          f"Eval suite ({hal_mode or 'no run yet'}): 100 - hallucination pass rate; measured on the eval set, not on production traffic."),
            "schema_validity": _metric(sch, "measured" if sch is not None else "not_measured", "Live eval: share of model responses valid on the first attempt."),
            "eval_score": _metric(latest["live"]["score"] if latest["live"] else (latest["guardrails"]["score"] if latest["guardrails"] else None),
                                  "measured" if (latest["live"] or latest["guardrails"]) else "not_measured",
                                  "live model run" if latest["live"] else "guardrails-only run (does not exercise the LLM)" if latest["guardrails"] else "no run yet"),
        },
        "latest_runs": {m: ({"id": r["id"], "score": r["score"], "model": r["model"], "completed_at": r["completed_at"]} if r else None) for m, r in latest.items()},
        "notes": ["'Measured' metrics come from deterministic checks. Nothing on this page is an estimate unless explicitly labelled.",
                  "Guardrails-only evals test the deterministic layers; they do not measure the LLM's behaviour. Run live evals with an API key configured for that."],
    }


@router.get("/ai-governance/interactions")
def interactions(task: str | None = None, guardrail_status: str | None = None, page: int = 1, page_size: int = 25, conn: Connection = Depends(get_conn)):
    cond, p = [], {}
    if task:
        cond.append("i.task=:t"); p["t"] = task
    if guardrail_status:
        cond.append("i.guardrail_status=:g"); p["g"] = guardrail_status.upper()
    where = ("WHERE " + " AND ".join(cond)) if cond else ""
    sel = f"""SELECT i.id, i.task, i.sanitized_query, i.model, i.prompt_version, i.retrieval_count, i.retrieval_ids, i.grounding_score, i.guardrail_status,
                     i.output_validation, i.requires_approval, i.created_at, i.response,
                     (SELECT decision FROM ai_approvals a WHERE a.ai_interaction_id=i.id ORDER BY a.id DESC LIMIT 1) AS approval_decision
              FROM ai_interactions i {where}"""  # noqa: S608
    return paged(conn, sel, f"SELECT COUNT(*) FROM ai_interactions i {where}", p, {"id": "i.id", "created_at": "i.created_at"}, "id", "desc", page, page_size, "id")  # noqa: S608


@router.post("/ai-governance/{interaction_id}/approve")
def approve(interaction_id: int, body: Approval, conn: Connection = Depends(get_conn)):
    it = one(conn, "SELECT id, task, requires_approval, response FROM ai_interactions WHERE id=:i", i=interaction_id)
    if not it:
        raise not_found("Interaction")
    if not it["response"]:
        raise HTTPException(409, "Nothing to approve: no response was produced")
    if scalar(conn, "SELECT 1 FROM ai_approvals WHERE ai_interaction_id=:i", i=interaction_id):
        raise HTTPException(409, "A decision has already been recorded for this interaction")
    execute(conn, "INSERT INTO ai_approvals (ai_interaction_id, reviewer, decision, comments, decided_at) VALUES (:i,:r,:d,:c, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            i=interaction_id, r=body.reviewer, d=body.decision, c=body.comments)
    mappings = 0
    if it["task"] == "mapping":
        mappings = execute(conn, "UPDATE control_mappings SET review_state=:s WHERE ai_interaction_id=:i AND review_state='PENDING'", s=body.decision, i=interaction_id).rowcount
    audit(conn, f"ai_{body.decision.lower()}", "ai_interaction", interaction_id, body.comments or "", actor=body.reviewer)
    return {"interaction_id": interaction_id, "decision": body.decision, "reviewer": body.reviewer, "mappings_updated": mappings}


# ------------------------------------------------------------------ evals
@router.post("/evals/run", dependencies=[Depends(limit_ai)])
def run_evals(body: EvalRun):
    llm = _llm() if body.mode == "live" else None
    if body.mode == "live" and not llm.configured:
        raise HTTPException(503, "Live evals need an LLM API key (GROQ_API_KEY or GEMINI_API_KEY)")
    with connect() as conn:
        try:
            run = eval_runner.run_suite(conn, body.mode, llm, set_baseline=body.set_baseline)
        except LLMUnavailable as exc:
            raise HTTPException(503, str(exc))
        return eval_runner.get_run(conn, run["id"])


@router.get("/evals/runs")
def eval_runs(page: int = 1, page_size: int = 25, conn: Connection = Depends(get_conn)):
    data = paged(conn, "SELECT id, eval_suite, model, prompt_version, mode, started_at, completed_at, total_cases, passed_cases, score, is_baseline, status, category_scores FROM ai_eval_runs",
                 "SELECT COUNT(*) FROM ai_eval_runs", {}, {"id": "id"}, "id", "desc", page, page_size, "id")
    for r in data["items"]:
        meta = json.loads(r.pop("category_scores") or "{}")
        r["skipped_cases"] = meta.get("skipped_cases")
        r["categories"] = meta.get("categories")
    return data


@router.get("/evals/runs/{run_id}")
def eval_run(run_id: int, conn: Connection = Depends(get_conn)):
    r = eval_runner.get_run(conn, run_id)
    if not r:
        raise not_found("Eval run")
    return r
