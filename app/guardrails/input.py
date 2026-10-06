"""Input guardrail: length -> normalise -> injection/exfiltration/prohibited-action -> PII redaction -> scope."""
from __future__ import annotations

from dataclasses import dataclass, field

from app.config import get_settings
from app.guardrails import rules

REFUSALS = {
    "TOO_LONG": "The request is too long. Please shorten it.",
    "EMPTY": "The request is empty.",
    "prompt_injection": "This request looks like an attempt to override application rules and was blocked.",
    "system_prompt_extraction": "System instructions are not available.",
    "exfiltration": "This request asks for secrets or bulk data and was blocked.",
    "prohibited_action": "CyberRisk does not accept, approve, change or execute anything automatically. Those actions require a human decision in the workflow.",
    "fake_claim": "CyberRisk cannot state certification or compliance claims that are not supported by evidence.",
    "OUT_OF_SCOPE": "This assistant only answers questions about cyber risk, vulnerabilities, controls, compliance, incidents and vendors.",
}
PRIORITY = ["exfiltration", "system_prompt_extraction", "prompt_injection", "prohibited_action", "fake_claim"]


@dataclass
class InputResult:
    allowed: bool
    status: str  # PASSED | REDACTED | BLOCKED
    sanitized: str
    flags: list[str] = field(default_factory=list)
    pii_types: list[str] = field(default_factory=list)
    refusal: str | None = None


def check_input(text: str | None, max_chars: int | None = None, require_scope: bool = True) -> InputResult:
    limit = max_chars or get_settings().max_input_chars
    if text is None or not text.strip():
        return InputResult(False, "BLOCKED", "", ["EMPTY"], refusal=REFUSALS["EMPTY"])
    if len(text) > limit:
        return InputResult(False, "BLOCKED", "", ["TOO_LONG"], refusal=REFUSALS["TOO_LONG"])  # raw content not retained
    norm = rules.normalize_text(text)
    flags = rules.find_injection(norm)
    if flags:
        top = next(f for f in PRIORITY if f in flags)
        # Blocked input is not stored: only the category is logged.
        return InputResult(False, "BLOCKED", "", flags, refusal=REFUSALS[top])
    sanitized, pii = rules.redact_pii(norm)
    if require_scope and not any(t in sanitized.lower() for t in rules.SCOPE_TERMS):
        return InputResult(False, "BLOCKED", sanitized, ["OUT_OF_SCOPE"], pii, REFUSALS["OUT_OF_SCOPE"])
    return InputResult(True, "REDACTED" if pii else "PASSED", sanitized, [], pii)
