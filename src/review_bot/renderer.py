"""JSON to Markdown (pipeline stage 7, SPEC.md §4, §13).

The JSON is the source of truth and this module is a projection of it: it adds no judgment,
never filters, caps, re-scores, or re-orders what `schema.py` settled, and only decides
where on the page each finding lands. Two artifacts that could disagree would mean neither
is authoritative.

Raw secret values cannot appear here because they were destroyed upstream (invariant 1), so
a `[MASKED_*]` token is all any evidence string can carry. Rendering evidence verbatim is
what keeps that true — reconstructing or unescaping it would be the only way to break it.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .schema import RANK, Finding, Review

#: Descending, so the header always reads `high · medium · low` regardless of what is present.
_SEVERITY_DISPLAY_ORDER = ("high", "medium", "low")

_DISCLAIMER = (
    "_Advisory only. This review assists a human reviewer, does not gate merges, and "
    "does not replace security review._"
)


def render_markdown(review: Review, excluded_note: str = "") -> str:
    """Render a validated `Review` as reviewer-facing Markdown.

    `excluded_note` is `FilterResult.exclusion_summary()`. It is passed alongside rather
    than carried on `Review` because §10 fixes the output schema exactly, and a count of
    skipped files is presentation, not a finding.
    """
    blocks: list[str] = [
        "# Security review",
        "",
        _header_line(review),
        "",
        review.summary.strip(),
    ]

    if excluded_note:
        blocks += ["", f"> {excluded_note}"]

    if review.findings:
        blocks += ["", "---", "", _findings_section(review.findings)]
    else:
        reason = review.no_findings_reason or "No security findings were identified."
        blocks += ["", "---", "", f"**No findings.** {reason.strip()}"]

    blocks += ["", "---", "", "## PR comment", "", review.pr_comment.strip()]
    blocks += ["", _DISCLAIMER]

    return "\n".join(blocks).rstrip() + "\n"


# --------------------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------------------


def _header_line(review: Review) -> str:
    """`**Overall risk: high** — 3 high · 7 medium · 2 low across 4 files` (§13)."""
    risk = f"**Overall risk: {review.overall_risk}**"
    if not review.findings:
        return f"{risk} — no findings"
    return f"{risk} — {severity_counts(review.findings)} across {_file_count(review.findings)}"


def severity_counts(findings: Iterable[Finding]) -> str:
    """`3 high · 7 medium · 2 low`, omitting severities with no findings."""
    counts = Counter(finding.severity for finding in findings)
    return " · ".join(f"{counts[s]} {s}" for s in _SEVERITY_DISPLAY_ORDER if counts[s])


def _file_count(findings: list[Finding]) -> str:
    total = len({finding.file for finding in findings})
    return f"{total} file" if total == 1 else f"{total} files"


# --------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------


def _findings_section(findings: list[Finding]) -> str:
    parts: list[str] = []
    for path, file_findings in group_by_file(findings):
        parts += [f"## `{path}`", ""]
        for finding in file_findings:
            parts += [_render_finding(finding), ""]
    return "\n".join(parts).rstrip()


def group_by_file(findings: list[Finding]) -> list[tuple[str, list[Finding]]]:
    """Group by file lexicographically, sorting within each file per §13.

    File-level findings (`line: null`) sort to the top of their file's section: they are
    the ones the reviewer cannot navigate to by line number, so burying them under twenty
    line-anchored findings is exactly where they would be missed.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.file, []).append(finding)

    return [(path, sorted(grouped[path], key=_finding_sort_key)) for path in sorted(grouped)]


def _finding_sort_key(finding: Finding) -> tuple[int, int, int, str]:
    """Severity desc, confidence desc, then line ascending with file-level first (§13).

    The ordinals are negated rather than reversing the whole tuple, so line number still
    ascends. Category breaks the remaining ties to keep the order total, and therefore
    stable across runs regardless of the input order.
    """
    return (
        -RANK[finding.severity],
        -RANK[finding.confidence],
        -1 if finding.line is None else finding.line,
        finding.category,
    )


def _render_finding(finding: Finding) -> str:
    location = "File-level" if finding.line is None else f"Line {finding.line}"
    heading = (
        f"### {location} · `{finding.category}` · "
        f"{finding.severity} severity · {finding.confidence} confidence"
    )
    lines = [heading, ""]
    if finding.line is None:
        lines += [
            "_File-level finding: this could not be attributed to a specific added line._",
            "",
        ]
    lines += [
        f"- **Evidence:** {_clean(finding.evidence)}",
        f"- **Risk:** {_clean(finding.risk)}",
        f"- **Recommendation:** {_clean(finding.recommendation)}",
    ]
    return "\n".join(lines)


def _clean(text: str) -> str:
    """Flatten to one bullet line without altering the characters that carry meaning.

    Newlines are collapsed because a raw newline inside a list item silently ends the item.
    Nothing else is touched: escaping or truncating evidence is how a `[MASKED_*]`
    placeholder would stop reading as one (§13).
    """
    return " ".join(text.split())
