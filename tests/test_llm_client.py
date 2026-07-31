"""Budget guards, caching, and call construction (SPEC.md §8, §9, §14).

No test in this file touches the network. The SDK is replaced by a stub, which is also how
the request parameters get asserted — the shape of the call matters as much as the
response, because a wrong parameter on a pinned model is a 400 nobody sees until the smoke
test.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from review_bot.llm_client import (
    DEFAULT_REVIEW_MODEL,
    DEFAULT_SUMMARY_MODEL,
    REVIEW_MAX_TOKENS,
    BudgetExceeded,
    LLMClient,
    LLMError,
    ResponseCache,
    Usage,
    estimate_cost,
    prompt_key,
)
from review_bot.prompt_builder import Prompt


@dataclass
class _StubUsage:
    input_tokens: int = 100
    output_tokens: int = 50
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0


@dataclass
class _StubBlock:
    text: str
    type: str = "text"


class _StubResponse:
    def __init__(self, text: str = '{"findings": []}', stop_reason: str = "end_turn") -> None:
        self.content = [_StubBlock(text)]
        self.stop_reason = stop_reason
        self.stop_details = None
        self.usage = _StubUsage()


class _StubMessages:
    def __init__(self, response) -> None:
        self._response = response
        self.calls: list[dict] = []

    def create(self, **params):
        self.calls.append(params)
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


class _StubSDK:
    def __init__(self, response) -> None:
        self.messages = _StubMessages(response)


def client_with(response, **kwargs) -> tuple[LLMClient, _StubSDK]:
    client = LLMClient(**kwargs)
    sdk = _StubSDK(response)
    client._client = sdk
    return client, sdk


def a_prompt(user: str = "some diff") -> Prompt:
    return Prompt(system="system instructions", user=user)


# ------------------------------------------------------------------------------------
# Call construction (§8)
# ------------------------------------------------------------------------------------


def test_review_call_pins_the_model_and_sends_effort() -> None:
    client, sdk = client_with(_StubResponse(), effort="medium")
    client.review(a_prompt())

    params = sdk.messages.calls[0]
    assert params["model"] == DEFAULT_REVIEW_MODEL
    assert params["output_config"] == {"effort": "medium"}
    assert params["max_tokens"] == REVIEW_MAX_TOKENS


def test_summary_call_omits_effort() -> None:
    """`effort` is not supported on `claude-haiku-4-5-20251001` and sending it is a 400."""
    client, sdk = client_with(_StubResponse('{"summary": "s"}'))
    client.summarize(a_prompt())

    params = sdk.messages.calls[0]
    assert params["model"] == DEFAULT_SUMMARY_MODEL
    assert "output_config" not in params


def test_no_sampling_parameters_are_sent() -> None:
    """§8 asks for temperature 0, but `claude-sonnet-5` rejects non-default sampling
    parameters with a 400. Byte-stable prompts carry determinism instead (SPEC §8, amended)."""
    client, sdk = client_with(_StubResponse())
    client.review(a_prompt())

    params = sdk.messages.calls[0]
    for removed in ("temperature", "top_p", "top_k"):
        assert removed not in params


def test_system_prompt_is_marked_cacheable() -> None:
    """§8: prompt caching on the system prompt, which is byte-identical by construction."""
    client, sdk = client_with(_StubResponse())
    client.review(a_prompt())

    system = sdk.messages.calls[0]["system"]
    assert system[0]["cache_control"] == {"type": "ephemeral"}
    assert system[0]["text"] == "system instructions"


def test_raw_text_is_returned_unparsed() -> None:
    """Parsing belongs to `schema.py`; this module must not interpret or repair output."""
    client, _ = client_with(_StubResponse("not json at all"))
    assert client.review(a_prompt()) == "not json at all"


def test_non_text_blocks_are_skipped() -> None:
    """Adaptive thinking emits thinking blocks first; only text carries the response."""
    response = _StubResponse()
    response.content = [_StubBlock("", type="thinking"), _StubBlock('{"findings": []}')]
    client, _ = client_with(response)
    assert client.review(a_prompt()) == '{"findings": []}'


# ------------------------------------------------------------------------------------
# Failure modes (§12, §15)
# ------------------------------------------------------------------------------------


def test_refusal_raises_rather_than_retrying() -> None:
    """Security review is exactly the domain the cyber safeguards watch. No retry, no
    rephrase — §12 keeps deterministic findings alive without this call."""
    client, sdk = client_with(_StubResponse(stop_reason="refusal"))
    with pytest.raises(LLMError, match="declined"):
        client.review(a_prompt())
    assert len(sdk.messages.calls) == 1, "a refusal must not be retried"


def test_api_error_raises_and_is_not_retried() -> None:
    import anthropic

    error = anthropic.APIConnectionError(request=None)
    client, sdk = client_with(error)
    with pytest.raises(LLMError):
        client.review(a_prompt())
    assert len(sdk.messages.calls) == 1, "§12 rejects retries around the API call"


def test_empty_response_raises() -> None:
    client, _ = client_with(_StubResponse(text="   "))
    with pytest.raises(LLMError, match="empty"):
        client.review(a_prompt())


# ------------------------------------------------------------------------------------
# Budget guards (§9)
# ------------------------------------------------------------------------------------


def test_oversized_call_aborts_before_sending() -> None:
    client, sdk = client_with(_StubResponse(), max_input_tokens=10)
    with pytest.raises(BudgetExceeded, match="max-input-tokens"):
        client.review(a_prompt("x" * 5000))
    assert sdk.messages.calls == [], "the guard must abort before the request is made"


def test_run_cost_ceiling_aborts_before_sending() -> None:
    client, sdk = client_with(_StubResponse(), max_run_cost=0.0)
    with pytest.raises(BudgetExceeded, match="max-run-cost"):
        client.review(a_prompt())
    assert sdk.messages.calls == []


def test_spent_accumulates_actual_usage() -> None:
    client, _ = client_with(_StubResponse(), max_run_cost=10.0)
    client.review(a_prompt())
    first = client.spent
    assert first > 0
    client.review(a_prompt("different"))
    assert client.spent > first, "cost must accumulate across calls within a run"


def test_dry_run_sends_nothing() -> None:
    """§9: build and print the prompt, estimate token count and cost, send nothing."""
    client, sdk = client_with(_StubResponse())
    report = client.dry_run_report([("review-0", a_prompt(), DEFAULT_REVIEW_MODEL, 8000)])

    assert sdk.messages.calls == []
    assert "some diff" in report and "TOTAL" in report
    assert client.spent == 0.0


def test_unknown_model_is_priced_conservatively() -> None:
    """`--model` can name anything. A guard that under-prices an unknown model is not a
    guard, so the most expensive known rate is assumed."""
    known = estimate_cost(DEFAULT_REVIEW_MODEL, 1000, 1000)
    unknown = estimate_cost("some-future-model", 1000, 1000)
    assert unknown >= known


def test_cache_read_is_cheaper_than_fresh_input() -> None:
    """§8: cache reads bill at 0.1x input, which is the whole reason for caching."""
    fresh = Usage(input_tokens=1000).cost(DEFAULT_REVIEW_MODEL)
    cached = Usage(cache_read_input_tokens=1000).cost(DEFAULT_REVIEW_MODEL)
    assert cached == pytest.approx(fresh * 0.1)


# ------------------------------------------------------------------------------------
# Response cache (`--cache`, §14)
# ------------------------------------------------------------------------------------


def test_cache_is_off_by_default() -> None:
    """§14: a second run should be allowed to produce a better review."""
    client, sdk = client_with(_StubResponse())
    client.review(a_prompt())
    client.review(a_prompt())
    assert len(sdk.messages.calls) == 2


def test_cache_hit_skips_the_api_call(tmp_path) -> None:
    cache = ResponseCache(tmp_path, enabled=True)
    client, sdk = client_with(_StubResponse('{"findings": []}'), cache=cache)

    first = client.review(a_prompt())
    second = client.review(a_prompt())

    assert first == second
    assert len(sdk.messages.calls) == 1, "the second call must be served from disk"


def test_cache_key_changes_with_prompt_model_and_effort() -> None:
    base = prompt_key("claude-sonnet-5", "medium", a_prompt())
    assert prompt_key("claude-sonnet-5", "medium", a_prompt("other")) != base
    assert prompt_key("claude-opus-5", "medium", a_prompt()) != base
    assert prompt_key("claude-sonnet-5", "high", a_prompt()) != base
    assert prompt_key("claude-sonnet-5", "medium", a_prompt()) == base, "keys must be stable"


def test_record_writes_the_raw_response_as_a_fixture(tmp_path) -> None:
    """§14/§17: `--record` overwrites test fixtures from live responses."""
    client, _ = client_with(_StubResponse('{"findings": []}'), record_dir=tmp_path)
    client.review(a_prompt(), label="review-0")

    written = tmp_path / "review-0.json"
    assert written.exists()
    assert written.read_text().strip() == '{"findings": []}'


def test_missing_api_key_is_a_clear_error(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = LLMClient()
    with pytest.raises(LLMError, match="ANTHROPIC_API_KEY"):
        client.review(a_prompt())
