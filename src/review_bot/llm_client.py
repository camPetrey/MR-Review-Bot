"""Anthropic API calls, budget guards, caching (pipeline stage 5, SPEC.md §4).

The only module that touches the network. It owns the two calls of §8, the budget controls
of §9, and the `--cache` / `--record` flags of §14.

**It deliberately does not retry, fall back, or recover.** A failed call raises `LLMError`
and the run continues on deterministic findings alone, which never depended on the network
(§12); a retry loop would trade a visible failure for an invisible one and double the cost
of a bad day. Nor does it repair output — it returns raw response text and `schema.py`
decides whether that text is usable (§15).

Two unrelated things share the word "cache": **prompt caching** (`cache_control` on the
system block) is an API feature, always on, and works because the system prompts are module
constants; **`--cache`** is this tool's own response cache on disk, off by default.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .prompt_builder import Prompt

#: §2 pins these. `claude-sonnet-5` reviews; `claude-haiku-4-5-20251001` summarises,
#: because call 2 is pure summarisation over findings and never sees the diff (§8).
DEFAULT_REVIEW_MODEL = "claude-sonnet-5"
DEFAULT_SUMMARY_MODEL = "claude-haiku-4-5-20251001"

#: Per-call output ceiling. Generous enough that a batch full of findings is not truncated,
#: and on the review model it must also cover thinking tokens, which count against it.
REVIEW_MAX_TOKENS = 8000
SUMMARY_MAX_TOKENS = 2000

#: USD per million tokens, (input, output). Sonnet 5 runs at introductory pricing through
#: 2026-08-31 and reverts afterwards; §8 pins the model and notes the date. Estimates pick
#: the table by date so a run after the changeover prices itself honestly.
_PRICING = {
    "claude-sonnet-5": (3.00, 15.00),
    "claude-sonnet-5@intro": (2.00, 10.00),
    "claude-haiku-4-5-20251001": (1.00, 5.00),
    "claude-opus-5": (5.00, 25.00),
    # Not a model this tool selects, but `--model` accepts anything and the unknown-model
    # fallback below prices at the table maximum. Listing the most expensive model we know
    # of is what keeps that fallback genuinely conservative.
    "claude-fable-5": (10.00, 50.00),
}
SONNET_5_INTRO_ENDS = datetime.date(2026, 8, 31)

#: Prompt-cache economics (§8): reads bill at 0.1x input, writes at 1.25x for the default
#: five-minute TTL.
_CACHE_READ_MULTIPLIER = 0.1
_CACHE_WRITE_MULTIPLIER = 1.25


class LLMError(Exception):
    """The API call did not produce usable text.

    Network failure, an API error, or a safety refusal. `cli.py` reports it on stderr and
    continues with deterministic findings — invariant 3: the highest-confidence signal
    never depends on a network call (§12).
    """


class BudgetExceeded(Exception):
    """A pre-flight guard aborted the run. `cli.py` maps this to exit 3 (§15)."""


@dataclass
class Usage:
    """One call's token accounting, logged to stderr under `--verbose` (§9)."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0

    def cost(self, model: str) -> float:
        rate_in, rate_out = _rates(model)
        return (
            self.input_tokens * rate_in
            + self.cache_read_input_tokens * rate_in * _CACHE_READ_MULTIPLIER
            + self.cache_creation_input_tokens * rate_in * _CACHE_WRITE_MULTIPLIER
            + self.output_tokens * rate_out
        ) / 1_000_000


def _rates(model: str) -> tuple[float, float]:
    today = datetime.datetime.now(tz=datetime.UTC).date()
    if model == "claude-sonnet-5" and today <= SONNET_5_INTRO_ENDS:
        return _PRICING["claude-sonnet-5@intro"]
    if model in _PRICING:
        return _PRICING[model]
    # An unpinned model supplied via `--model`. Price it as the most expensive thing we
    # know about, so the budget guard stays conservative rather than silently permissive.
    # Keyed on output rate: it dominates, since a call's output budget is what `preflight`
    # has to assume in full.
    return max(_PRICING.values(), key=lambda rates: rates[1])


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Worst-case cost in USD for one call, assuming the full output budget is used (§9)."""
    rate_in, rate_out = _rates(model)
    return (input_tokens * rate_in + output_tokens * rate_out) / 1_000_000


# --------------------------------------------------------------------------------------
# Response cache (`--cache`, §14)
# --------------------------------------------------------------------------------------


def prompt_key(model: str, effort: str | None, prompt: Prompt) -> str:
    """Cache key for one call.

    §14 describes `--cache` as keyed by diff hash. Keying on the prompt bytes plus model
    and effort is that, refined: the prompt is a pure function of the diff, and this also
    keys each batch and each of the two calls separately, and invalidates when the model or
    effort changes. Prompts are byte-stable (§8), so the key is too.
    """
    digest = hashlib.sha256()
    for part in (model, effort or "-", prompt.system, prompt.user):
        digest.update(part.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


@dataclass
class ResponseCache:
    """On-disk cache of raw response text, keyed by `prompt_key`.

    There is no `enabled` flag: `LLMClient.cache is None` is the single representation of
    "caching is off", and `--cache` is what decides whether one gets constructed at all.
    """

    directory: Path

    def get(self, key: str) -> str | None:
        path = self.directory / f"{key}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())["response"]

    def put(self, key: str, response: str) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / f"{key}.json").write_text(
            json.dumps({"response": response}, indent=2, sort_keys=True)
        )


# --------------------------------------------------------------------------------------
# The client
# --------------------------------------------------------------------------------------


@dataclass
class LLMClient:
    """Wraps the Anthropic SDK with the budget guard and the caches.

    The SDK client is constructed lazily, so `--dry-run` and `--no-llm` never need
    credentials and unit tests can build an `LLMClient` with no API key present.
    """

    model: str = DEFAULT_REVIEW_MODEL
    summary_model: str = DEFAULT_SUMMARY_MODEL
    effort: str = "medium"
    max_input_tokens: int = 8000
    max_run_cost: float = 0.50
    verbose: bool = False
    cache: ResponseCache | None = None
    record_dir: Path | None = None

    spent: float = field(default=0.0, init=False)
    usages: list[tuple[str, Usage]] = field(default_factory=list, init=False)
    _client: object | None = field(default=None, init=False, repr=False)

    # -- public API ---------------------------------------------------------------------

    def review(self, prompt: Prompt, *, label: str = "review") -> str:
        """Call 1 (§8). Returns raw response text; parsing belongs to `schema.py`."""
        return self._call(
            prompt, model=self.model, max_tokens=REVIEW_MAX_TOKENS, effort=self.effort, label=label
        )

    def summarize(self, prompt: Prompt, *, label: str = "summary") -> str:
        """Call 2 (§8).

        No `effort`: the parameter is not supported on `claude-haiku-4-5-20251001` and
        sending it is a 400. Haiku is chosen here precisely because summarisation does not
        need reasoning depth.
        """
        return self._call(
            prompt,
            model=self.summary_model,
            max_tokens=SUMMARY_MAX_TOKENS,
            effort=None,
            label=label,
        )

    def preflight(self, prompt: Prompt, *, model: str, max_tokens: int) -> float:
        """Estimate a call's cost and abort loudly if a guard would be breached (§9).

        Two guards, both from §9: a single call over `--max-input-tokens`, or a run whose
        projected total exceeds `--max-run-cost`. Raising here means no request is sent.
        Returns the estimate; it does not mutate `spent`, which tracks actual usage.
        """
        input_tokens = prompt.token_estimate
        if input_tokens > self.max_input_tokens:
            raise BudgetExceeded(
                f"call would send ~{input_tokens} input tokens, over the "
                f"--max-input-tokens limit of {self.max_input_tokens}. Pack smaller "
                "batches or raise the limit."
            )

        projected = estimate_cost(model, input_tokens, max_tokens)
        if self.spent + projected > self.max_run_cost:
            raise BudgetExceeded(
                f"run would reach ~${self.spent + projected:.4f}, over the --max-run-cost "
                f"limit of ${self.max_run_cost:.2f} (${self.spent:.4f} already spent)."
            )
        return projected

    def dry_run_report(self, calls: list[tuple[str, Prompt, str, int]]) -> str:
        """`--dry-run`: print what would be sent and what it would cost. Sends nothing (§9)."""
        lines: list[str] = []
        total = 0.0
        for label, prompt, model, max_tokens in calls:
            cost = estimate_cost(model, prompt.token_estimate, max_tokens)
            total += cost
            lines.append("=" * 72)
            lines.append(
                f"[{label}] model={model} ~{prompt.token_estimate} input tokens, "
                f"<={max_tokens} output tokens, worst case ~${cost:.4f}"
            )
            lines.append("-" * 72)
            lines.append(prompt.system)
            lines.append("-" * 72)
            lines.append(prompt.user)
        lines.append("=" * 72)
        lines.append(f"TOTAL worst case: ${total:.4f} across {len(calls)} call(s)")
        return "\n".join(lines)

    def usage_summary(self) -> str:
        """One line per call plus the run total, for stderr (§9)."""
        lines = [
            f"{label}: in={u.input_tokens} out={u.output_tokens} "
            f"cache_read={u.cache_read_input_tokens} "
            f"cache_write={u.cache_creation_input_tokens}"
            for label, u in self.usages
        ]
        lines.append(f"total cost this run: ${self.spent:.4f}")
        return "\n".join(lines)

    # -- internals ----------------------------------------------------------------------

    def _call(
        self, prompt: Prompt, *, model: str, max_tokens: int, effort: str | None, label: str
    ) -> str:
        key = prompt_key(model, effort, prompt)

        if self.cache is not None:
            cached = self.cache.get(key)
            if cached is not None:
                self._log(f"[{label}] cache hit ({key[:12]}) — no API call")
                self._record(label, cached)
                return cached

        self.preflight(prompt, model=model, max_tokens=max_tokens)

        started = time.monotonic()
        text, usage = self._send(prompt, model=model, max_tokens=max_tokens, effort=effort)
        elapsed = time.monotonic() - started

        self.spent += usage.cost(model)
        self.usages.append((label, usage))
        self._log(
            f"[{label}] model={model} {elapsed:.1f}s in={usage.input_tokens} "
            f"out={usage.output_tokens} cache_read={usage.cache_read_input_tokens} "
            f"cache_write={usage.cache_creation_input_tokens} "
            f"cost=${usage.cost(model):.4f} run_total=${self.spent:.4f}"
        )

        if self.cache is not None:
            self.cache.put(key, text)
        self._record(label, text)
        return text

    def _send(
        self, prompt: Prompt, *, model: str, max_tokens: int, effort: str | None
    ) -> tuple[str, Usage]:
        import anthropic

        # No `temperature`/`top_p`/`top_k`. §8 asked for temperature 0, but `claude-sonnet-5`
        # removed the sampling parameters rather than defaulting them — sending one is a 400,
        # so no request may carry it. Determinism rests entirely on the lever §8 itself calls
        # the larger one: prompts are byte-stable by construction in `prompt_builder`.
        # `test_llm_client.py::test_no_sampling_parameters_are_sent` stops this regressing
        # via `--model`.
        params: dict = {
            "model": model,
            "max_tokens": max_tokens,
            # `cache_control` here caches the tools+system prefix. The system prompts are
            # module constants, so that prefix is byte-identical on every call (§8).
            "system": [
                {"type": "text", "text": prompt.system, "cache_control": {"type": "ephemeral"}}
            ],
            "messages": [{"role": "user", "content": prompt.user}],
        }
        if effort is not None:
            params["output_config"] = {"effort": effort}

        try:
            response = self._sdk().messages.create(**params)
        except anthropic.APIError as exc:
            raise LLMError(f"{type(exc).__name__}: {exc}") from exc

        if response.stop_reason == "refusal":
            # Security review is exactly the domain the cyber safeguards watch. Surface it
            # rather than retrying or rephrasing; §12 keeps deterministic findings alive.
            category = getattr(response.stop_details, "category", None)
            raise LLMError(f"the model declined this request (refusal, category={category})")

        text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
        if not text.strip():
            raise LLMError(f"empty response (stop_reason={response.stop_reason})")

        return text, _usage_from(response.usage)

    def _sdk(self):
        if self._client is None:
            import anthropic

            if not os.environ.get("ANTHROPIC_API_KEY"):
                raise LLMError(
                    "ANTHROPIC_API_KEY is not set. Use --no-llm for deterministic findings "
                    "only, or --dry-run to build the prompt without sending it."
                )
            self._client = anthropic.Anthropic()
        return self._client

    def _record(self, label: str, text: str) -> None:
        """`--record`: overwrite the end-to-end fixture from this response (§14, §17)."""
        if self.record_dir is None:
            return
        self.record_dir.mkdir(parents=True, exist_ok=True)
        (self.record_dir / f"{label}.json").write_text(text.strip() + "\n")

    def _log(self, message: str) -> None:
        if self.verbose:
            print(message, file=sys.stderr)


def _usage_from(raw) -> Usage:
    return Usage(
        input_tokens=raw.input_tokens or 0,
        output_tokens=raw.output_tokens or 0,
        cache_read_input_tokens=getattr(raw, "cache_read_input_tokens", 0) or 0,
        cache_creation_input_tokens=getattr(raw, "cache_creation_input_tokens", 0) or 0,
    )
