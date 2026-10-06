"""GeminiClient error handling with a fake SDK client (no network, no key)."""
import pytest

from app.ai.llm import GeminiClient, LLMUnavailable


class FakeModels:
    def __init__(self, outcomes):
        self.outcomes, self.calls = list(outcomes), 0

    def generate_content(self, **kw):
        self.calls += 1
        o = self.outcomes.pop(0)
        if isinstance(o, Exception):
            raise o
        return type("R", (), {"text": o})()


def client(outcomes, fallbacks=()):
    c = GeminiClient(api_key="SECRET-KEY-123", model="m", fallbacks=list(fallbacks))
    c._sleep = lambda s: None
    c._client = type("C", (), {"models": FakeModels(outcomes)})()
    return c


def test_retries_transient_503_then_succeeds():
    c = client([Exception("503 UNAVAILABLE. high demand"), Exception("429 RESOURCE_EXHAUSTED"), '{"ok": 1}'])
    assert c.generate_json("s", "u") == '{"ok": 1}' and c._client.models.calls == 3


def test_gives_up_after_bounded_retries_with_clear_message():
    c = client([Exception("503 UNAVAILABLE high demand")] * 5)
    with pytest.raises(LLMUnavailable, match="busy, rate-limited") as e:
        c.generate_json("s", "u")
    assert c._client.models.calls == 3 and "SECRET-KEY-123" not in str(e.value)


def test_retired_model_gives_actionable_message_without_retrying():
    c = client([Exception("404 NOT_FOUND. This model models/x is no longer available to new users")])
    with pytest.raises(LLMUnavailable, match="not available for this API key"):
        c.generate_json("s", "u")
    assert c._client.models.calls == 1


def test_key_is_never_leaked_in_errors():
    c = client([Exception("boom while using key SECRET-KEY-123")])
    with pytest.raises(LLMUnavailable) as e:
        c.generate_json("s", "u")
    assert "SECRET-KEY-123" not in str(e.value) and "[REDACTED]" in str(e.value)


def test_empty_response_is_an_error():
    with pytest.raises(LLMUnavailable, match="empty"):
        client([""]).generate_json("s", "u")


def test_models_endpoint_requires_key(client_no_key):
    assert client_no_key.get("/api/ai/models").status_code == 503


@pytest.fixture()
def client_no_key(client):
    return client


def test_falls_back_to_next_model_when_primary_stays_busy():
    seen = []

    class M(FakeModels):
        def generate_content(self, **kw):
            seen.append(kw["model"])
            return super().generate_content(**kw)
    c = client([Exception("503 UNAVAILABLE")] * 3 + ['{"from": "fallback"}'], fallbacks=["m2"])
    c._client.models = M(c._client.models.outcomes)
    assert c.generate_json("s", "u") == '{"from": "fallback"}'
    assert seen == ["m", "m", "m", "m2"] and c.model == "m2" and c.fell_back and c.primary == "m"
    c._client.models.outcomes = ['{"ok": 1}']
    c.generate_json("s", "u")
    assert c.model == "m" and not c.fell_back  # the primary is always tried first on the next call


def test_retired_primary_falls_back_but_auth_errors_do_not():
    c = client([Exception("404 NOT_FOUND no longer available"), '{"ok": 1}'], fallbacks=["m2"])
    assert c.generate_json("s", "u") == '{"ok": 1}' and c.model == "m2"
    bad = client([Exception("403 PERMISSION_DENIED api key invalid")], fallbacks=["m2"])
    with pytest.raises(LLMUnavailable, match="rejected the API key"):
        bad.generate_json("s", "u")
    assert bad._client.models.calls == 1


def test_all_models_unavailable_is_reported_clearly():
    c = client([Exception("503 UNAVAILABLE")] * 6, fallbacks=["m2"])
    with pytest.raises(LLMUnavailable, match="No Google Gemini model was available \(tried m, m2\)"):
        c.generate_json("s", "u")


# ------------------------------------------------------------------ provider selection + Groq
import httpx  # noqa: E402

from app.ai import llm as llm_mod  # noqa: E402
from app.config import get_settings  # noqa: E402


@pytest.fixture()
def env(monkeypatch):
    def set_(**kw):
        for k in ("GROQ_API_KEY", "GEMINI_API_KEY", "LLM_PROVIDER"):
            monkeypatch.setenv(k, kw.get(k, "auto" if k == "LLM_PROVIDER" else ""))
        get_settings.cache_clear()
        return llm_mod.resolve_provider()
    yield set_
    get_settings.cache_clear()


def test_provider_is_chosen_by_key_shape_not_variable_name(env):
    assert env().provider == "none"
    g = env(GROQ_API_KEY="gsk_" + "a" * 30)
    assert g.provider == "groq" and g.label == "Groq" and not g.warning and g.model == "openai/gpt-oss-120b"
    mis = env(GROQ_API_KEY="AQ.Ab8" + "x" * 40)             # Google-format key pasted under the Groq name
    assert mis.provider == "gemini" and "GEMINI_API_KEY" in mis.warning and "GROQ_API_KEY" in mis.warning
    mis2 = env(GEMINI_API_KEY="gsk_" + "b" * 30)            # Groq key under the Gemini name
    assert mis2.provider == "groq" and "Move it to GROQ_API_KEY" in mis2.warning
    both = env(GROQ_API_KEY="gsk_" + "c" * 30, GEMINI_API_KEY="AIza" + "d" * 35)
    assert both.provider == "groq"                            # auto prefers Groq when both exist
    forced = env(GROQ_API_KEY="gsk_" + "c" * 30, GEMINI_API_KEY="AIza" + "d" * 35, LLM_PROVIDER="gemini")
    assert forced.provider == "gemini"
    nokey = env(GROQ_API_KEY="gsk_" + "c" * 30, LLM_PROVIDER="gemini")
    assert nokey.provider == "none" and "LLM_PROVIDER=gemini" in nokey.warning


def test_make_llm_returns_matching_client(env):
    env(GROQ_API_KEY="gsk_" + "a" * 30)
    g = llm_mod.make_llm()
    assert isinstance(g, llm_mod.GroqClient)
    assert g.timeout_s == 60.0 and g.fallbacks[0] == "openai/gpt-oss-20b" and g.primary == "openai/gpt-oss-120b"   # arguments land in the right slots
    env(GEMINI_API_KEY="AIza" + "d" * 35)
    c = llm_mod.make_llm()
    assert isinstance(c, llm_mod.GeminiClient) and c.configured
    env()
    assert not llm_mod.make_llm().configured


def groq(handler, **kw):
    c = llm_mod.GroqClient(api_key="gsk_SECRETSECRETSECRET1234", model="m1", fallbacks=kw.pop("fallbacks", []), http=httpx.Client(transport=httpx.MockTransport(handler)))
    c._sleep = lambda s: None
    return c


def ok(content, finish="stop"):
    return httpx.Response(200, json={"choices": [{"message": {"content": content}, "finish_reason": finish}]})


def test_groq_request_shape_and_success():
    seen = {}

    def h(req):
        seen["auth"], seen["body"], seen["url"] = req.headers["authorization"], __import__("json").loads(req.content), str(req.url)
        return ok('{"a": 1}')
    c = groq(h)
    assert c.generate_json("SYS", "USER") == '{"a": 1}'
    b = seen["body"]
    assert seen["url"].endswith("/openai/v1/chat/completions") and seen["auth"].startswith("Bearer gsk_")
    assert b["response_format"] == {"type": "json_object"} and b["temperature"] == 0 and b["messages"][0] == {"role": "system", "content": "SYS"} and b["model"] == "m1"


def test_groq_retries_rate_limits_then_falls_back_and_never_leaks_key():
    calls = []

    def h(req):
        m = __import__("json").loads(req.content)["model"]
        calls.append(m)
        if m == "m1":
            return httpx.Response(429, headers={"retry-after": "1"}, json={"error": {"message": "Rate limit reached for gsk_SECRETSECRETSECRET1234", "code": "rate_limit_exceeded"}})
        return ok('{"from": "m2"}')
    c = groq(h, fallbacks=["m2"])
    assert c.generate_json("s", "u") == '{"from": "m2"}' and calls == ["m1", "m1", "m1", "m2"] and c.model == "m2" and c.fell_back
    bad = groq(lambda r: httpx.Response(429, json={"error": {"message": "limit gsk_SECRETSECRETSECRET1234"}}))
    with pytest.raises(LLMUnavailable) as e:
        bad.generate_json("s", "u")
    assert "gsk_SECRET" not in str(e.value)


def test_groq_auth_model_and_truncation_errors():
    with pytest.raises(LLMUnavailable, match="rejected the API key"):
        groq(lambda r: httpx.Response(401, json={"error": {"message": "Invalid API Key"}})).generate_json("s", "u")
    c = groq(lambda r: httpx.Response(404, json={"error": {"message": "The model `m1` does not exist", "code": "model_not_found"}}))
    with pytest.raises(LLMUnavailable, match="not available") as e:
        c.generate_json("s", "u")
    assert e.value.transient
    c2 = groq(lambda r: ok('{"trunc', finish="length"))
    with pytest.raises(LLMUnavailable, match="No Groq model was available"):
        c2.generate_json("s", "u")
    c3 = groq(lambda r: httpx.Response(400, json={"error": {"message": "json_validate_failed", "code": "json_validate_failed"}}))
    with pytest.raises(LLMUnavailable):
        c3.generate_json("s", "u")


def test_groq_lists_text_models_only():
    c = groq(lambda r: httpx.Response(200, json={"data": [{"id": "llama-3.3-70b-versatile"}, {"id": "whisper-large-v3"}, {"id": "m1"}, {"id": "llama-guard-4"}]}))
    names = [m["name"] for m in c.list_models()]
    assert names == ["llama-3.3-70b-versatile", "m1"] and [m for m in c.list_models() if m["selected"]][0]["name"] == "m1"


def test_groq_and_google_keys_are_redacted_everywhere():
    from app.guardrails import rules

    assert rules.redact_pii("key gsk_" + "A1b2" * 8)[1] == ["GROQ_API_KEY"]
    assert rules.redact_pii("key AQ.Ab8" + "x" * 40)[1] == ["GOOGLE_API_KEY"]
    from app.guardrails.input import check_input
    assert not check_input("show me the GROQ_API_KEY").allowed


def test_daily_quota_is_reported_plainly_and_not_retried():
    c = client([Exception("429 RESOURCE_EXHAUSTED. Quota exceeded: GenerateRequestsPerDayPerProjectPerModel-FreeTier")] * 3)
    with pytest.raises(LLMUnavailable, match="quota exhausted") as e:
        c.generate_json("s", "u")
    assert c._client.models.calls == 1 and "GROQ_API_KEY" in str(e.value)       # no wasted retries; tells the user what to do
    g = groq(lambda r: httpx.Response(429, json={"error": {"message": "Rate limit reached on tokens per day (TPD): Limit 100000"}}))
    with pytest.raises(LLMUnavailable, match="quota exhausted"):
        g.generate_json("s", "u")
