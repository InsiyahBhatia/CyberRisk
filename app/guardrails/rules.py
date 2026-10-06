"""Detection rules shared by the input, RAG and output guardrails. Heuristic by design: defence in depth, not a silver bullet."""
from __future__ import annotations

import re
import unicodedata

I = re.IGNORECASE
# start of an imperative request ("please accept ...", "Can you approve ..."), so advisory questions are not blocked
CMD = r"(?:^|[.!?]\s+|\b(?:please|pls|can you|could you|go ahead and|just|now)\s+)"

# category -> patterns. Used on user input and on retrieved (untrusted) documents.
INJECTION_RULES: dict[str, list[re.Pattern]] = {
    "prompt_injection": [re.compile(p, I) for p in [
        r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,25}\b(previous|prior|above|earlier|your|all|any)\b[^.\n]{0,25}\b(instructions?|rules?|prompts?|guidelines?|polic(y|ies)|guardrails?|safety)\b",
        r"\byou\s+are\s+now\b",
        r"\b(developer|debug|admin|god|jailbreak(ed)?|dan)\s+mode\b",
        r"\bsystem\s+(override|prompt\s+injection)\b",
        r"\bdo\s+anything\s+now\b",
        r"\bpretend\s+(to\s+be|you\s+are)\b[^.\n]{0,40}\b(unrestricted|no\s+rules|without\s+restrictions)\b",
        r"\bdo\s+not\s+(cite|use|mention)\s+(any\s+)?(sources?|citations?|evidence)\b",
        r"\bnew\s+instructions?\s*:",
    ]],
    "system_prompt_extraction": [re.compile(p, I) for p in [
        r"\b(reveal|show|print|repeat|display|output|leak|tell\s+me|what\s+(is|are))\b[^.\n]{0,40}\b(system|hidden|initial|developer|original|secret)\s+(prompt|instructions?|message|rules)\b",
        r"\brepeat\s+(the\s+)?(words|text)\s+above\b",
        r"\bwhat\s+were\s+you\s+told\s+(to|before)\b",
    ]],
    "exfiltration": [re.compile(p, I) for p in [
        r"\b(reveal|show|print|send|give|dump|leak|expose|output|share|tell\s+me)\b[^.\n]{0,40}\b(api[\s_-]?keys?|secrets?|passwords?|tokens?|credentials?|private\s+keys?|env(ironment)?\s+variables?|\.env)\b",
        r"\b(gemini_api_key|groq_api_key|nvd_api_key)\b",
        r"\b(dump|export|list|show|send|exfiltrate)\b[^.\n]{0,25}\b(all|every|entire|full|whole)\b[^.\n]{0,25}\b(tables?|database|records|employees|users|accounts|rows)\b",
        r"\b(send|email|mail|forward|post|upload|exfiltrate)\b[^.\n]{0,80}[\w.+-]+@[\w-]+\.[\w.-]+",
        r"\bselect\s+\*\s+from\b|\bdrop\s+table\b|\bunion\s+select\b|;\s*(drop|delete|update|insert)\b",
    ]],
    "prohibited_action": [re.compile(p, I) for p in [
        CMD + r"(accept|approve|sign\s*off\s+on|waive|dismiss)\b[^.\n]{0,25}\b(risks?|findings?|exceptions?|controls?)\b",
        CMD + r"close\b[^.\n]{0,15}\b(this|the|that|these|all)\b[^.\n]{0,15}\b(risks?|findings?)\b",
        r"\bmark\b[^.\n]{0,40}\bas\s+(accepted|approved|compliant|satisfied|closed|resolved|implemented)\b",
        CMD + r"(set|change|override|lower|reduce|edit)\b[^.\n]{0,30}\b(score|level|rating)\b[^.\n]{0,20}\b(to|as)\b",
        CMD + r"(execute|run|apply|deploy|perform)\b[^.\n]{0,25}\b(remediation|patch(es)?|fix(es)?|commands?|scripts?)\b",
        CMD + r"(disable|delete|reset|lock|unlock|create)\b[^.\n]{0,25}\b(accounts?|users?|passwords?|firewall)\b",
    ]],
    "fake_claim": [re.compile(p, I) for p in [
        r"\b(state|say|claim|declare|assert|confirm|report)\b[^.\n]{0,40}\b(fully\s+)?(soc\s*2|iso\s*27001|nist|pci|hipaa)\b[^.\n]{0,30}\b(certified|compliant|attested)\b",
        r"\b(is|are)\s+(fully\s+)?(soc\s*2|iso\s*27001)\s+(certified|compliant)\b",
        r"\bcontrol\s+\S+\s+is\s+(satisfied|implemented|met)\s+for\s+all\b",
    ]],
}

PII_RULES: dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+(\.[\w-]+)+\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "PHONE": re.compile(r"(?<!\w)(\+?\d{1,3}[\s.-]?)?(\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\w)"),
}
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SECRET_RULES: dict[str, re.Pattern] = {
    "GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b|\bAQ\.[A-Za-z0-9_\-]{30,}"),
    "GROQ_API_KEY": re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"),
    "OPENAI_STYLE_KEY": re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
}

SCOPE_TERMS = (
    "risk", "vulnerab", "cve", "control", "complian", "framework", "nist", "iso", "soc 2", "soc2", "mitre", "att&ck", "attack", "technique",
    "incident", "vendor", "supplier", "asset", "patch", "remediat", "mfa", "multi-factor", "evidence", "audit", "policy", "policies", "security",
    "threat", "kev", "exploit", "exposure", "score", "business unit", "executive", "summary", "summar", "posture", "gap", "mitigat", "cvss",
    "authenticat", "access", "encrypt", "backup", "logging", "monitor", "recover", "response", "governance", "grc", "data pipeline", "etl",
    "breach", "malware", "phishing", "ransomware", "cyber", "overdue", "sla", "critical", "residual", "inherent",
)


def normalize_text(text: str) -> str:
    """NFKC normalise, drop control/zero-width characters, collapse whitespace (defeats trivial obfuscation)."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if ch in "\n\t" or (unicodedata.category(ch)[0] != "C"))
    return re.sub(r"[ \t\r\f\v]+", " ", text).strip()


def luhn_ok(digits: str) -> bool:
    nums = [int(c) for c in digits][::-1]
    total = sum(n if i % 2 == 0 else (n * 2 - 9 if n * 2 > 9 else n * 2) for i, n in enumerate(nums))
    return total % 10 == 0


def find_injection(text: str) -> list[str]:
    t = normalize_text(text)
    return [cat for cat, pats in INJECTION_RULES.items() if any(p.search(t) for p in pats)]


def redact_pii(text: str) -> tuple[str, list[str]]:
    found: list[str] = []

    def card_sub(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            found.append("CREDIT_CARD")
            return "[REDACTED_CARD]"
        return m.group()

    text = CARD_RE.sub(card_sub, text)
    for name, pat in SECRET_RULES.items():
        text, n = pat.subn(f"[REDACTED_{name}]", text)
        if n:
            found.append(name)
    for name in ("EMAIL", "SSN", "PHONE"):
        text, n = PII_RULES[name].subn(f"[REDACTED_{name}]", text)
        if n:
            found.append(name)
    return text, sorted(set(found))


def contains_sensitive(text: str) -> list[str]:
    """Names of PII/secret classes present (used on model output)."""
    _, found = redact_pii(text)
    return found
