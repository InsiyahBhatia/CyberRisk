"""Output guardrail: schema, grounding, citation, ID, number, secret/PII and prohibited-claim validation."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from pydantic import ValidationError

from app.ai.schemas import AIAnswer
from app.guardrails import rules

CONTROL_ID_RE = re.compile(r"\b(?:[A-Z]{2}\.[A-Z]{2}-\d{2}|A\.\d{1,2}\.\d{1,2}|CC\d\.\d|A1\.\d|T\d{4}(?:\.\d{3})?|[A-Z]{2}\.FAKE-\d+)\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
NUM_CLAIM_RE = re.compile(r"\b(?:risk|residual|inherent|vulnerability|enterprise|overall)?\s*(?:score|rating)\b[^0-9\n]{0,25}(\d+(?:\.\d+)?)", re.I)
ACTION_CLAIM_RE = re.compile(r"\b(?:i|we)(?:\s+have|'ve|\s+just|\s+will)?\s+(?:already\s+)?(?:accepted|approved|executed|applied|disabled|closed|deleted|changed|updated|set|marked|patched)\b", re.I)
CERT_RE = re.compile(r"(soc\s*2|iso\s*/?\s*(?:iec\s*)?27001|nist|pci|hipaa)[^.\n]{0,40}\b(certified|certification|attested|attestation)\b|\b(certified|attested)\b[^.\n]{0,40}(soc\s*2|iso\s*27001)", re.I)
NEGATION_RE = re.compile(r"\b(not|no|cannot|can't|isn't|aren't|without|never|unable|neither|nor|n't)\b|not a|no evidence", re.I)
APPROVAL_ACTION_RE = re.compile(r"\b(accept|approve|waive|certif|attest|mark\b.*\b(compliant|satisfied)|sign\s*off|publish|share externally)", re.I)


@dataclass
class AllowedContext:
    evidence_ids: set[str]          # DB:* and KB:* ids actually supplied to the model
    kb_ids: set[str]
    context_text: str               # everything supplied (facts + retrieved chunks), used for ID/number grounding
    risk_level: str | None = None   # deterministic level the answer must not contradict
    numbers: list[float] = field(default_factory=list)


@dataclass
class OutputResult:
    valid: bool
    errors: list[str]
    warnings: list[str]
    answer: AIAnswer | None
    grounding_score: float
    citation_accuracy: float

    def summary(self) -> dict:
        return {"valid": self.valid, "errors": self.errors, "warnings": self.warnings,
                "grounding_score": self.grounding_score, "citation_accuracy": self.citation_accuracy}


def numbers_in(text: str) -> list[float]:
    return [float(x) for x in re.findall(r"(?<![\w.])\d+(?:\.\d+)?", text)]


def _parse_json(raw: str) -> dict:
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw)
    return json.loads(raw)


def _all_text(a: AIAnswer) -> str:
    parts = [a.summary, a.clarification or ""]
    parts += [f.statement for f in a.findings]
    parts += [x.action + " " + x.rationale for x in a.recommended_actions]
    return "\n".join(parts)


def cert_claim_present(text: str) -> bool:
    """A certification claim that is not negated within the same sentence."""
    for sentence in re.split(r"(?<=[.!?])\s+|\n", text):
        if CERT_RE.search(sentence) and not NEGATION_RE.search(sentence):
            return True
    return False


def validate_output(raw: str, ctx: AllowedContext) -> OutputResult:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        answer = AIAnswer.model_validate(_parse_json(raw))
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        return OutputResult(False, [f"schema_invalid: {str(exc)[:200]}"], [], None, 0.0, 0.0)

    text = _all_text(answer)

    # secrets / PII
    leaked = rules.contains_sensitive(text)
    if leaked:
        errors.append(f"sensitive_data_in_output: {','.join(leaked)}")

    # deterministic risk level must not be contradicted
    if ctx.risk_level and answer.risk_level and answer.risk_level != ctx.risk_level:
        errors.append(f"risk_level_mismatch: model said {answer.risk_level}, calculated {ctx.risk_level}")

    # control / technique IDs and CVEs must come from supplied context
    ctx_upper = ctx.context_text.upper()
    for cid in sorted({m.group().upper() for m in CONTROL_ID_RE.finditer(text)}):
        if cid not in ctx_upper:
            errors.append(f"unsupported_control_id: {cid}")
    for cve in sorted({m.group().upper() for m in CVE_RE.finditer(text)}):
        if cve not in ctx_upper:
            errors.append(f"unsupported_cve: {cve}")

    # numeric score claims must match deterministic values
    allowed_numbers = ctx.numbers or numbers_in(ctx.context_text)
    for m in NUM_CLAIM_RE.finditer(text):
        val = float(m.group(1))
        if not any(abs(val - n) <= 0.06 for n in allowed_numbers):
            errors.append(f"unsupported_risk_score: {val}")

    # prohibited autonomous-action / certification claims
    if ACTION_CLAIM_RE.search(text):
        errors.append("autonomous_action_claim")
    if cert_claim_present(text):
        errors.append("unsupported_compliance_claim")

    # grounding: each finding must cite supplied evidence; framework claims need a KB source
    supported = 0
    for f in answer.findings:
        ids_ok = bool(f.evidence_ids) and all(i in ctx.evidence_ids for i in f.evidence_ids)
        if f.evidence_ids and not ids_ok:
            errors.append(f"unknown_evidence_id: {[i for i in f.evidence_ids if i not in ctx.evidence_ids]}")
        if f.type == "framework" and not any(i in ctx.kb_ids for i in f.evidence_ids):
            ids_ok = False
            errors.append("framework_claim_without_source")
        if not f.evidence_ids:
            errors.append("finding_without_evidence")
        supported += ids_ok
    grounding = supported / len(answer.findings) if answer.findings else (1.0 if answer.insufficient_evidence else 0.0)

    # citations must exist
    bad_cites = [c.source_id for c in answer.citations if c.source_id not in ctx.evidence_ids]
    if bad_cites:
        errors.append(f"unknown_citation: {bad_cites}")
    citation_accuracy = 1.0 if not answer.citations else (len(answer.citations) - len(bad_cites)) / len(answer.citations)

    # abstention consistency
    if not answer.insufficient_evidence and not answer.findings:
        errors.append("no_findings_and_no_abstention")
    if answer.insufficient_evidence and answer.findings:
        warnings.append("abstained_but_listed_findings")
    if not answer.insufficient_evidence and ctx.kb_ids and not answer.citations:
        warnings.append("no_citations")

    # actions that need a human are forced to say so (server-side, not trusted to the model)
    for a in answer.recommended_actions:
        if APPROVAL_ACTION_RE.search(a.action) and not a.requires_human_approval:
            a.requires_human_approval = True
            warnings.append("forced_human_approval_flag")
    if not answer.insufficient_evidence and not answer.recommended_actions:
        warnings.append("no_recommendations")

    return OutputResult(not errors, errors, warnings, answer, round(grounding, 3), round(citation_accuracy, 3))
