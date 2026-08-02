"""Output schema (pipeline stage 6): pydantic models, line validation, merge (SPEC.md §4).

Everything standing between an untrusted model response and the reviewer lives here, and
the order is load-bearing: parse (§15), then validate (§11), then merge (§12). Merging
before validation would let a hallucinated file survive by colliding with a real
deterministic finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

if TYPE_CHECKING:
    from .diff_parser import ParsedDiff

Severity = Literal["low", "medium", "high"]
Confidence = Literal["low", "medium", "high"]
Category = Literal[
    "auth_perms",
    "input_validation",
    "injection",
    "hardcoded_secrets",
    "sensitive_logging",
    "unsafe_redirects",
    "dependency_change",
    "crypto_misuse",
]
Source = Literal["deterministic", "llm", "both"]

#: Ordinal for both severity and confidence — they share a scale. One definition, because
#: `prompt_builder` (confidence caps), `renderer` (sorting), and the merge rules below all
#: compare these, and three private copies would be three chances to disagree.
RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}

#: Categories the LLM is allowed to report. `hardcoded_secrets` is deterministic-only —
#: a masked value cannot be evidenced without unmasking it (§5).
LLM_CATEGORIES: frozenset[str] = frozenset(
    {
        "auth_perms",
        "input_validation",
        "injection",
        "sensitive_logging",
        "unsafe_redirects",
        "dependency_change",
        "crypto_misuse",
    }
)


class Finding(BaseModel):
    """One security finding.

    `source` and `rule_id` are internal-only tuning fields. They serialize under their
    `_`-prefixed aliases and are stripped from user-facing output by `public_dict()`.
    """

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    file: str
    line: int | None = None
    """Post-file line number, or None for a file-level finding (§11)."""
    category: Category
    severity: Severity
    confidence: Confidence
    evidence: str
    risk: str
    recommendation: str

    source: Source = Field(default="deterministic", alias="_source")
    rule_id: str | None = Field(default=None, alias="_rule_id")

    def public_dict(self) -> dict:
        """The finding as it reaches the reviewer, with internal fields stripped (§10)."""
        return self.model_dump(exclude={"source", "rule_id"})

    def dedupe_key(self) -> tuple[str, int | None, str]:
        """Dedupe identity per §12.1."""
        return (self.file, self.line, self.category)

    def sort_key(self) -> tuple[str, int, str]:
        """Byte-stable ordering for prompt serialization: `(file, line, category)` (§8)."""
        return (self.file, -1 if self.line is None else self.line, self.category)


class Review(BaseModel):
    """The full run output. JSON is the source of truth; Markdown renders from it (§10)."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    overall_risk: Severity
    findings: list[Finding] = Field(default_factory=list)
    pr_comment: str
    no_findings_reason: str | None = None

    def public_dict(self) -> dict:
        return {
            "summary": self.summary,
            "overall_risk": self.overall_risk,
            "findings": [f.public_dict() for f in self.findings],
            "pr_comment": self.pr_comment,
            "no_findings_reason": self.no_findings_reason,
        }


# --------------------------------------------------------------------------------------
# What the model is allowed to return
# --------------------------------------------------------------------------------------


class LLMFinding(BaseModel):
    """One finding as the review model reports it.

    Deliberately *not* `Finding`. The model does not get to set `_source` or `_rule_id`,
    and `category` is narrowed to exclude `hardcoded_secrets` — that category is
    deterministic-only, because a masked value cannot be evidenced without unmasking it
    (§5). `extra="forbid"` means an invented field is a malformed response, not a field we
    silently drop.
    """

    model_config = ConfigDict(extra="forbid")

    file: str
    line: int | None = None
    category: Literal[
        "auth_perms",
        "input_validation",
        "injection",
        "sensitive_logging",
        "unsafe_redirects",
        "dependency_change",
        "crypto_misuse",
    ]
    severity: Severity
    confidence: Confidence
    evidence: str
    risk: str
    recommendation: str

    def to_finding(self) -> Finding:
        return Finding(
            file=self.file,
            line=self.line,
            category=self.category,
            severity=self.severity,
            confidence=self.confidence,
            evidence=self.evidence,
            risk=self.risk,
            recommendation=self.recommendation,
            source="llm",
        )


class LLMReviewResponse(BaseModel):
    """Call 1's output: findings only. Summary and risk come from call 2 (§8)."""

    model_config = ConfigDict(extra="forbid")

    findings: list[LLMFinding] = Field(default_factory=list)


class LLMSummaryResponse(BaseModel):
    """Call 2's output. The summary model never sees the diff, only files and findings."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    overall_risk: Severity
    pr_comment: str


class MalformedLLMResponse(Exception):
    """The model returned something that is not a valid response for its call.

    Carries `raw` so `cli.py` can print the response verbatim before exiting 2. §15 is
    explicit that there is no auto-repair and no retry: a model that cannot follow the
    output contract is a bug to surface, not a transient fault to paper over.
    """

    def __init__(self, message: str, raw: str) -> None:
        super().__init__(message)
        self.raw = raw


def parse_review_response(raw: str) -> list[Finding]:
    """Parse call 1's response. Raises `MalformedLLMResponse` on anything unexpected."""
    payload = _load_json(raw)
    try:
        parsed = LLMReviewResponse.model_validate(payload)
    except ValidationError as exc:
        raise MalformedLLMResponse(f"review response failed schema validation: {exc}", raw) from exc
    return [finding.to_finding() for finding in parsed.findings]


def parse_summary_response(raw: str) -> LLMSummaryResponse:
    """Parse call 2's response. Raises `MalformedLLMResponse` on anything unexpected."""
    payload = _load_json(raw)
    try:
        return LLMSummaryResponse.model_validate(payload)
    except ValidationError as exc:
        raise MalformedLLMResponse(
            f"summary response failed schema validation: {exc}", raw
        ) from exc


def _load_json(raw: str) -> object:
    """Decode `raw` as a JSON object.

    Fenced code blocks are the one shape tolerated, and only because stripping a ```json
    fence is a *framing* fix, not a content one — the JSON inside is still required to be
    exactly right. Anything else that does not decode is malformed.
    """
    text = _strip_code_fence(raw.strip())
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MalformedLLMResponse(f"response is not valid JSON: {exc}", raw) from exc
    if not isinstance(payload, dict):
        raise MalformedLLMResponse(
            f"response decoded to {type(payload).__name__}, expected a JSON object", raw
        )
    return payload


def _strip_code_fence(text: str) -> str:
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    if len(lines) < 2 or not lines[-1].strip().startswith("```"):
        return text
    return "\n".join(lines[1:-1])


# --------------------------------------------------------------------------------------
# Line validation (§11)
# --------------------------------------------------------------------------------------


@dataclass
class ValidationStats:
    """Tuning metrics, emitted to stderr on every run and included in CI output (§11).

    `unmappable_count` is a metric, not an accepted condition. The target is zero; the fix
    for a non-zero value is prompt work, not tolerance.
    """

    unmappable_count: int = 0
    hallucinated_file_count: int = 0
    hallucinated_files: list[str] = field(default_factory=list)
    unmappable_lines: list[tuple[str, int]] = field(default_factory=list)

    def extend(self, other: ValidationStats) -> None:
        """Fold another batch's stats in. Lives here so a new field is added in one place —
        `cli.py` accumulates per batch and would otherwise silently drop it."""
        self.unmappable_count += other.unmappable_count
        self.hallucinated_file_count += other.hallucinated_file_count
        self.hallucinated_files.extend(other.hallucinated_files)
        self.unmappable_lines.extend(other.unmappable_lines)


def validate_findings(
    findings: list[Finding], diff: ParsedDiff
) -> tuple[list[Finding], ValidationStats]:
    """Check every finding's `(file, line)` against the parsed diff (§11).

    Three cases, exactly as the spec table states them: a line in the file's added-line set
    is accepted; a line outside it degrades to a file-level finding; a file the diff never
    touched is dropped entirely.

    Degrading rather than dropping an unmappable line is deliberate — the model may well
    have found something real in a file it could not cite precisely, and a file-level
    finding is still actionable. A hallucinated *file* has no such reading.
    """
    stats = ValidationStats()
    kept: list[Finding] = []

    for finding in findings:
        parsed_file = diff.file(finding.file)
        if parsed_file is None:
            stats.hallucinated_file_count += 1
            stats.hallucinated_files.append(finding.file)
            continue

        if finding.line is not None and finding.line not in parsed_file.added_line_numbers:
            stats.unmappable_count += 1
            stats.unmappable_lines.append((finding.file, finding.line))
            finding = finding.model_copy(update={"line": None})

        kept.append(finding)

    return kept, stats


# --------------------------------------------------------------------------------------
# Merge, dedupe, confidence promotion (§12)
# --------------------------------------------------------------------------------------


def merge_findings(deterministic: list[Finding], llm: list[Finding]) -> list[Finding]:
    """Merge the two detectors into one findings list (§12).

    Deterministic findings are already in the list before this function is called in
    spirit — they never depended on the network. This only decides what happens where the
    two sides land on the same `(file, line, category)`:

    1. Dedupe on that key.
    2. The deterministic `category`, `file`, and `line` win.
    3. Agreement promotes confidence to `high` and `_source` to `both`. Two independent
       detectors concurring is real evidence.
    4. Keep the LLM's `risk` and `recommendation` (better prose) and the deterministic
       `evidence` (verifiable).

    Rule 3 is written for Tier 2, which is where it changes anything: Tier 1 hits are
    already `high` and their lines are suppressed, so the model should not be reporting
    them at all. Applying it uniformly is therefore a no-op on Tier 1 rather than a
    special case worth branching on.
    """
    merged: dict[tuple[str, int | None, str], Finding] = {}

    for finding in deterministic:
        key = finding.dedupe_key()
        existing = merged.get(key)
        merged[key] = finding if existing is None else _keep_stronger(existing, finding)

    for finding in llm:
        key = finding.dedupe_key()
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
        elif existing.source == "deterministic":
            merged[key] = _promote(existing, finding)
        else:
            merged[key] = _keep_stronger(existing, finding)

    return sorted(merged.values(), key=lambda f: f.sort_key())


def _promote(deterministic: Finding, llm: Finding) -> Finding:
    """Both detectors landed on the same finding. Take the best of each (§12.3, §12.4)."""
    return deterministic.model_copy(
        update={
            "confidence": "high",
            "severity": _max_severity(deterministic.severity, llm.severity),
            "risk": llm.risk,
            "recommendation": llm.recommendation,
            "source": "both",
        }
    )


def _keep_stronger(first: Finding, second: Finding) -> Finding:
    """Two findings from the same source on one key — keep the higher-confidence one.

    Reachable when two deterministic rules in one category fire on one line, or when the
    model reports the same finding twice.
    """
    return second if RANK[second.confidence] > RANK[first.confidence] else first


def _max_severity(first: Severity, second: Severity) -> Severity:
    return first if RANK[first] >= RANK[second] else second


def overall_risk(findings: list[Finding]) -> Severity:
    """Fallback risk level when the summary call did not run (`--no-llm`, or a failure).

    The highest severity present, `low` when there is nothing. The summary model overrides
    this when it runs; this exists so the deterministic-only path still emits a valid
    `Review` (§12).
    """
    if not findings:
        return "low"
    return max((f.severity for f in findings), key=lambda s: RANK[s])
