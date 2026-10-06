"""LLM service abstraction. Everything else depends only on `LLMClient`; Gemini and Groq are interchangeable providers.

Provider is chosen from configuration (LLM_PROVIDER, or auto-detected from the key's shape: `gsk_` = Groq, anything else = Gemini),
so a key pasted under the wrong variable name still reaches the right service.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Protocol

import httpx

from app.config import get_settings


class LLMUnavailable(RuntimeError):
    """No API key configured or the provider call failed."""

    def __init__(self, message: str, transient: bool = False):
        super().__init__(message)
        self.transient = transient  # True: demand spike / rate limit / retired model (worth retrying or falling back)


class LLMClient(Protocol):
    model: str

    def generate_json(self, system: str, user: str) -> str: ...


TRANSIENT_MARKERS = ("503", "502", "500", "429", "unavailable", "high demand", "resource_exhausted", "deadline", "timed out", "overloaded", "rate limit", "over capacity")


@dataclass(frozen=True)
class ProviderConfig:
    provider: str            # gemini | groq | none
    label: str
    key: str
    model: str
    fallbacks: tuple[str, ...]
    warning: str = ""


def key_shape(key: str) -> str:
    return "groq" if key.startswith("gsk_") else "gemini"


def resolve_provider() -> ProviderConfig:
    s = get_settings()
    candidates = [(name, v.strip().strip("\"'")) for name, v in (("GROQ_API_KEY", s.groq_api_key), ("GEMINI_API_KEY", s.gemini_api_key)) if v and v.strip()]
    want = s.llm_provider.lower()
    chosen = None
    if want in ("groq", "gemini"):
        chosen = next(((n, k) for n, k in candidates if key_shape(k) == want), None)
        if chosen is None:
            return ProviderConfig("none", "AI", "", "", (), f"LLM_PROVIDER={want} but no {want}-format key was found in GROQ_API_KEY / GEMINI_API_KEY.")
    elif candidates:
        chosen = sorted(candidates, key=lambda c: key_shape(c[1]) != "groq")[0]  # prefer a Groq-shaped key if both exist
    if chosen is None:
        return ProviderConfig("none", "AI", "", "", ())
    name, key = chosen
    provider = key_shape(key)
    expected = "GROQ_API_KEY" if provider == "groq" else "GEMINI_API_KEY"
    warning = f"The key in {name} is a {'Groq' if provider == 'groq' else 'Google Gemini'}-format key, so {'Groq' if provider == 'groq' else 'Gemini'} is being used. Move it to {expected}." if name != expected else ""
    if provider == "groq":
        return ProviderConfig("groq", "Groq", key, s.groq_model, tuple(m.strip() for m in s.groq_fallback_models.split(",") if m.strip()), warning)
    return ProviderConfig("gemini", "Google Gemini", key, s.gemini_model, tuple(m.strip() for m in s.gemini_fallback_models.split(",") if m.strip()), warning)


class _BaseClient:
    """Retry, fallback and error-sanitising logic shared by providers. Subclasses implement `_request`."""

    provider = "none"
    label = "AI"

    def __init__(self, key: str, model: str, fallbacks: list[str] | tuple[str, ...], timeout_s: float = 60.0):
        self._key = key
        self.primary = model
        self.model = model
        self.fallbacks = [m for m in fallbacks if m and m != model]
        self.timeout_s = timeout_s
        self.retries = 2
        self.backoff = 2.0
        self._sleep = time.sleep

    @property
    def configured(self) -> bool:
        return bool(self._key)

    @property
    def fell_back(self) -> bool:
        return self.model != self.primary

    def _clean(self, msg: str) -> str:
        return msg.replace(self._key, "[REDACTED]") if self._key else msg

    def _request(self, model: str, system: str, user: str) -> str:  # pragma: no cover - provider specific
        raise NotImplementedError

    def _call(self, model: str, system: str, user: str) -> str:
        if not self._key:
            raise LLMUnavailable("No API key configured. Set GROQ_API_KEY or GEMINI_API_KEY in .env to enable AI features.")
        for attempt in range(self.retries + 1):
            try:
                text = self._request(model, system, user)
                if not text or not text.strip("\n .…"):  # empty, or just an ellipsis placeholder
                    raise _ProviderError("empty response", transient=True)
                return text
            except _ProviderError as exc:
                msg, low = self._clean(str(exc)), str(exc).lower()
                if exc.transient and exc.kind != "quota" and attempt < self.retries:
                    self._sleep(exc.retry_after or self.backoff * (2 ** attempt))  # bounded retry for demand spikes / rate limits only
                    continue
                if exc.kind == "quota":
                    raise LLMUnavailable(f"{self.label} quota exhausted for model '{model}' (daily/plan limit, not a temporary spike). Wait for it to reset, use a different model or key, "
                                         f"or switch provider (set GROQ_API_KEY=gsk_… from console.groq.com). Provider said: {msg[:120]}", transient=True) from exc
                if exc.kind == "model":
                    raise LLMUnavailable(f"Model '{model}' is not available for this API key (GET /api/ai/models lists what it can use). Provider said: {msg[:160]}", transient=True) from exc
                if exc.kind == "auth":
                    raise LLMUnavailable(f"{self.label} rejected the API key. Check it in .env and restart. Provider said: {msg[:120]}") from exc
                if exc.transient:
                    raise LLMUnavailable(f"{self.label} model '{model}' is busy, rate-limited or returned unusable output (tried {attempt + 1} times). Provider said: {msg[:140]}", transient=True) from exc
                raise LLMUnavailable(f"{self.label} request failed: {msg[:200]}") from exc
        raise LLMUnavailable("unreachable")  # pragma: no cover

    def generate_json(self, system: str, user: str) -> str:
        self.model = self.primary
        errors: list[str] = []
        for m in [self.primary, *self.fallbacks]:
            try:
                out = self._call(m, system, user)
                self.model = m
                return out
            except LLMUnavailable as exc:
                if not exc.transient:
                    raise
                errors.append(str(exc))
        tried = ", ".join([self.primary, *self.fallbacks])
        raise LLMUnavailable(f"No {self.label} model was available (tried {tried}). {errors[0][:200]}", transient=True)

    def list_models(self) -> list[dict]:  # pragma: no cover - provider specific
        raise NotImplementedError


class _ProviderError(Exception):
    def __init__(self, message: str, transient: bool = False, kind: str = "other", retry_after: float | None = None):
        super().__init__(message)
        self.transient, self.kind, self.retry_after = transient, kind, retry_after


class GeminiClient(_BaseClient):
    """Google Gemini via the google-genai SDK."""

    provider, label = "gemini", "Google Gemini"

    def __init__(self, api_key: str | None = None, model: str | None = None, timeout_s: float = 60.0, fallbacks: list[str] | None = None):
        s = get_settings()
        key = api_key if api_key is not None else (resolve_provider().key if resolve_provider().provider == "gemini" else s.gemini_api_key)
        fb = fallbacks if fallbacks is not None else [x.strip() for x in s.gemini_fallback_models.split(",")]
        super().__init__(key, model or s.gemini_model, fb, timeout_s)
        self._client = None

    def _sdk(self):
        if self._client is None:
            from google import genai

            self._client = genai.Client(api_key=self._key)
        return self._client

    def _request(self, model: str, system: str, user: str) -> str:
        from google.genai import types

        try:
            resp = self._sdk().models.generate_content(
                model=model, contents=user,
                config=types.GenerateContentConfig(system_instruction=system, response_mime_type="application/json", temperature=0.0, max_output_tokens=16384,
                                                   http_options=types.HttpOptions(timeout=int(self.timeout_s * 1000))))
        except Exception as exc:
            low = str(exc).lower()
            if "not_found" in low or "no longer available" in low or "is not found" in low:
                raise _ProviderError(str(exc), kind="model") from exc
            if "api key" in low or "permission_denied" in low or "unauthenticated" in low or "api_key_invalid" in low:
                raise _ProviderError(str(exc), kind="auth") from exc
            if "perday" in low.replace(" ", "").replace("_", "") or "per day" in low:
                raise _ProviderError(str(exc), transient=True, kind="quota") from exc
            raise _ProviderError(str(exc), transient=any(t in low for t in TRANSIENT_MARKERS)) from exc
        cands = getattr(resp, "candidates", None) or []
        if "MAX_TOKENS" in (str(getattr(cands[0], "finish_reason", "")) if cands else ""):
            raise _ProviderError("ran out of output tokens before finishing the JSON answer", transient=True)
        return getattr(resp, "text", None) or ""

    def list_models(self) -> list[dict]:
        try:
            out = []
            for m in self._sdk().models.list():
                actions = getattr(m, "supported_actions", None) or []
                if actions and "generateContent" not in actions:
                    continue
                name = (m.name or "").removeprefix("models/")
                out.append({"name": name, "display_name": getattr(m, "display_name", "") or name, "selected": name == self.primary})
            return sorted(out, key=lambda x: x["name"])
        except Exception as exc:
            raise LLMUnavailable(f"Could not list models: {self._clean(str(exc))[:160]}") from exc


class GroqClient(_BaseClient):
    """Groq's OpenAI-compatible chat completions API (JSON mode)."""

    provider, label = "groq", "Groq"
    BASE = "https://api.groq.com/openai/v1"

    def __init__(self, api_key: str | None = None, model: str | None = None, timeout_s: float = 60.0, fallbacks: list[str] | None = None, http: httpx.Client | None = None):
        s = get_settings()
        cfg = resolve_provider()
        key = api_key if api_key is not None else (cfg.key if cfg.provider == "groq" else s.groq_api_key)
        fb = fallbacks if fallbacks is not None else [x.strip() for x in s.groq_fallback_models.split(",")]
        super().__init__(key, model or s.groq_model, fb, timeout_s)
        self._http = http

    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=self.timeout_s)
        return self._http

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"}

    def _request(self, model: str, system: str, user: str) -> str:
        body = {"model": model, "temperature": 0, "max_completion_tokens": 8192, "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            r = self.http.post(f"{self.BASE}/chat/completions", headers=self._headers(), json=body)
        except httpx.HTTPError as exc:
            raise _ProviderError(f"network error: {type(exc).__name__}", transient=True) from exc
        if r.status_code == 200:
            data = r.json()
            choice = (data.get("choices") or [{}])[0]
            if choice.get("finish_reason") == "length":
                raise _ProviderError("ran out of output tokens before finishing the JSON answer", transient=True)
            return (choice.get("message") or {}).get("content") or ""
        err = {}
        try:
            err = r.json().get("error", {})
        except ValueError:
            pass
        msg = f"{r.status_code} {err.get('code') or ''} {err.get('message') or r.text[:120]}".strip()
        low = msg.lower()
        if r.status_code in (401, 403):
            raise _ProviderError(msg, kind="auth")
        if r.status_code == 404 or "does not exist" in low or "decommissioned" in low or "model_not_found" in low or "not have access to model" in low:
            raise _ProviderError(msg, kind="model")
        retry = None
        try:
            retry = min(float(r.headers.get("retry-after", "")), 20.0)
        except ValueError:
            pass
        if r.status_code == 429 and ("per day" in low or "tokens per day" in low or "requests per day" in low):
            raise _ProviderError(msg, transient=True, kind="quota")
        if r.status_code in (429, 500, 502, 503) or "json_validate_failed" in low:
            raise _ProviderError(msg, transient=True, retry_after=retry)
        raise _ProviderError(msg)

    def list_models(self) -> list[dict]:
        try:
            r = self.http.get(f"{self.BASE}/models", headers=self._headers())
            r.raise_for_status()
            skip = ("whisper", "tts", "guard", "orpheus", "playai", "distil", "embed")
            return sorted(({"name": m["id"], "display_name": m["id"], "selected": m["id"] == self.primary} for m in r.json().get("data", []) if not any(x in m["id"] for x in skip)), key=lambda x: x["name"])
        except Exception as exc:
            raise LLMUnavailable(f"Could not list models: {self._clean(str(exc))[:160]}") from exc


def make_llm() -> GeminiClient | GroqClient:
    """The configured provider's client (an unconfigured Gemini client if no key exists, so callers can report `configured=False`)."""
    cfg = resolve_provider()
    if cfg.provider == "groq":
        return GroqClient(api_key=cfg.key, model=cfg.model, fallbacks=list(cfg.fallbacks))
    return GeminiClient(api_key=cfg.key, model=cfg.model, fallbacks=list(cfg.fallbacks)) if cfg.provider == "gemini" else GeminiClient(api_key="", model=get_settings().gemini_model, fallbacks=[])


def get_llm() -> LLMClient:
    return make_llm()


def llm_configured() -> bool:
    return resolve_provider().provider != "none"


def schema_hint(model_cls) -> str:
    return json.dumps(model_cls.model_json_schema(), separators=(",", ":"))
