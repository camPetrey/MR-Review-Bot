"""Styled terminal output (SPEC.md §13, §24).

Two things are worth asserting here and the rest is decoration.

The first is invariant 7 surviving a rendering library: rich parses `[...]` in a plain
string as markup, so a `[MASKED_AWS_KEY]` placeholder passed as `str` is silently deleted
from the output. That failure is invisible — no error, no warning, just a report where the
proof that masking worked used to be.

The second is §13's "the renderer adds no judgment", which now has to hold across *two*
renderers. The terminal and the Markdown are projections of one `Review`, and a disagreement
between them about ordering or counts would mean neither is authoritative.
"""

from __future__ import annotations

import io
import re

import pytest
from rich.console import Console

from review_bot.renderer import render_markdown
from review_bot.schema import Finding, Review
from review_bot.terminal import (
    CallRecord,
    RunDiagnostics,
    TerminalContext,
    render_diagnostics,
    render_terminal_str,
)


def finding(**overrides) -> Finding:
    base = {
        "file": "src/app.py",
        "line": 12,
        "category": "injection",
        "severity": "high",
        "confidence": "high",
        "evidence": "f-string into .execute() at line 12",
        "risk": "SQL injection.",
        "recommendation": "Parameterize the query.",
    }
    return Finding(**{**base, **overrides})


def review(*findings: Finding, risk: str = "high", **overrides) -> Review:
    base = {
        "summary": "a summary",
        "overall_risk": risk,
        "findings": list(findings),
        "pr_comment": "a comment",
    }
    return Review(**{**base, **overrides})


def render(*args, **kwargs) -> str:
    return render_terminal_str(*args, **kwargs)


# --------------------------------------------------------------------------------------
# Invariant 7 — the reason this file exists
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "placeholder",
    [
        "[MASKED_AWS_KEY]",
        "[MASKED_PRIVATE_KEY]",
        "[MASKED_DB_URL]",
        "[MASKED_TOKEN]",
        "[MASKED_KEY]",
    ],
)
def test_masked_placeholders_survive_rich_markup(placeholder) -> None:
    """Every §5 placeholder renders literally rather than being parsed as a style tag.

    If this fails, the report shows an *empty space* where the masked value was — which
    reads as "there was nothing here", the opposite of what the placeholder means.
    """
    out = render(
        review(finding(evidence=f"`AWS_KEY` assigned a literal value (masked as {placeholder})"))
    )
    assert placeholder in out


def test_bracketed_text_in_any_field_is_not_parsed_as_markup() -> None:
    """The model writes the prose fields, so the same hazard applies to all three."""
    out = render(
        review(
            finding(
                evidence="value is [bold red]not a style[/bold red]",
                risk="see [link=http://x]here[/link]",
                recommendation="use [MASKED_TOKEN] instead",
            )
        )
    )
    for text in ("[bold red]", "[/bold red]", "[link=http://x]", "[MASKED_TOKEN]"):
        assert text in out


def test_summary_and_pr_comment_are_not_parsed_as_markup() -> None:
    out = render(
        review(summary="risk in [MASKED_DB_URL]", pr_comment="rotate [MASKED_AWS_KEY] now")
    )
    assert "[MASKED_DB_URL]" in out
    assert "[MASKED_AWS_KEY]" in out


# --------------------------------------------------------------------------------------
# The renderer adds no judgment (§13), across both renderers
# --------------------------------------------------------------------------------------


def test_overall_risk_is_taken_from_the_review_not_recomputed() -> None:
    """Same assertion as the Markdown renderer's, because the same rule binds both."""
    out = render(review(finding(severity="high"), risk="low"))
    assert "LOW RISK" in out


def test_no_finding_is_dropped_or_capped() -> None:
    findings = [finding(line=n, evidence=f"evidence number {n}") for n in range(1, 26)]
    out = render(review(*findings))
    for n in range(1, 26):
        assert f"evidence number {n}" in out


def test_both_renderers_agree_on_file_order_and_counts() -> None:
    """Two projections of one `Review` that disagreed would mean neither is authoritative."""
    findings = [
        finding(file="src/z.py", line=1, severity="low"),
        finding(file="src/a.py", line=2, severity="high"),
        finding(file="src/m.py", line=3, severity="medium"),
    ]
    terminal = render(review(*findings))
    markdown = render_markdown(review(*findings))

    assert [terminal.index(p) for p in ("src/a.py", "src/m.py", "src/z.py")] == sorted(
        terminal.index(p) for p in ("src/a.py", "src/m.py", "src/z.py")
    )
    # The header counts come from one function, so they cannot drift apart.
    for chunk in ("1 high", "1 medium", "1 low"):
        assert chunk in terminal
        assert chunk in markdown


def test_severity_sorts_high_first_within_a_file() -> None:
    out = render(
        review(
            finding(line=9, severity="low", evidence="the low one"),
            finding(line=1, severity="high", evidence="the high one"),
        )
    )
    assert out.index("the high one") < out.index("the low one")


# --------------------------------------------------------------------------------------
# Content
# --------------------------------------------------------------------------------------


def test_every_required_field_renders() -> None:
    out = render(review(finding()))
    for chunk in (
        "src/app.py",
        "line 12",
        "injection",
        "HIGH",
        "high",
        "f-string into .execute() at line 12",
        "SQL injection.",
        "Parameterize the query.",
        "a comment",
    ):
        assert chunk in out


def test_file_level_findings_are_labelled_and_sort_first() -> None:
    out = render(
        review(
            finding(line=5, evidence="the line one"),
            finding(line=None, evidence="the file one"),
        )
    )
    assert "file-level" in out
    assert out.index("the file one") < out.index("the line one")


def test_agreement_between_detectors_is_visible() -> None:
    """§12.3's confidence promotion is invisible in the fields; only the label shows it."""
    out = render(review(finding(_source="both")))
    assert "rule + model" in out
    assert "rule + model" not in render(review(finding(_source="llm")))


def test_no_findings_states_the_reason() -> None:
    """A clean run says so twice: in the header, and with the reason in the body.

    The header alone is not enough — "no findings" and "the tool did not run properly" look
    identical to a reader who was not watching stderr, and the reason is what distinguishes
    them.
    """
    out = render(
        review(risk="low", no_findings_reason="Parameterized SQL and an allowlisted redirect.")
    )
    assert out.lower().count("no findings") >= 2
    assert "Parameterized SQL and an allowlisted redirect." in out
    assert "LOW RISK" in out


def test_excluded_note_renders() -> None:
    note = "12 files excluded from LLM review (binary)"
    assert note in render(review(finding()), note)


def test_pull_request_context_renders_in_the_header() -> None:
    context = TerminalContext(
        pr_label="psf/requests#7328",
        pr_title="Prevent Response self-reference",
        pr_author="nateprewitt",
        pr_base="main",
        pr_head="fix-redirects",
    )
    out = render(review(finding()), "", context)
    for chunk in ("psf/requests#7328", "Prevent Response self-reference", "@nateprewitt", "main"):
        assert chunk in out


def test_partial_coverage_is_stated() -> None:
    """§15: a failed API call still exits 0, so the report has to say coverage was partial."""
    out = render(review(finding()), "", TerminalContext(partial=True))
    assert "Partial coverage" in out


def test_disclaimer_always_renders() -> None:
    """§1's non-negotiable framing, on both the findings and the no-findings path."""
    assert "Advisory only" in render(review(finding()))
    assert "Advisory only" in render(review(risk="low"))


# --------------------------------------------------------------------------------------
# Shape
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("width", [40, 60, 80, 100, 200])
def test_output_never_exceeds_the_console_width(width) -> None:
    """A line wider than the terminal wraps at a random column and the layout falls apart."""
    out = render(review(finding(file="src/some/deeply/nested/module/path.py")), width=width)
    assert max(len(line) for line in out.splitlines()) <= width


def test_captured_output_has_no_trailing_whitespace() -> None:
    """`--format terminal --output PATH` writes this to a file, where padding is litter."""
    out = render(review(finding()))
    assert all(line == line.rstrip() for line in out.splitlines())


# --------------------------------------------------------------------------------------
# Run diagnostics (§11, §14, §24)
# --------------------------------------------------------------------------------------
#
# The block is presentation and most of it is not worth pinning. What is worth pinning is
# the pair of properties that make it safe to change: that a non-terminal destination still
# gets the greppable `key=value` counters §11 puts in the CI job output, and that a terminal
# destination never *loses* a number to a narrow width.


CALLS = (
    CallRecord("review", "claude-sonnet-5", 8.6, 450, 442, 2065, 0.0057),
    CallRecord("summary", "claude-haiku-4-5-20251001", 4.09, 1137, 385, 0, 0.0031),
)

STAGES = (("parse", 0.0001), ("mask", 0.029), ("review_pass", 8.6), ("summary_pass", 4.09))


def diagnostics(**overrides) -> RunDiagnostics:
    base = {
        "unmappable_count": 0,
        "hallucinated_file_count": 0,
        "source_label": "sample_diffs/auth_bypass.diff",
        "verbose": True,
        "masked_line_count": 0,
        "calls": CALLS,
        "total_cost": 0.0088,
        "stages": STAGES,
    }
    return RunDiagnostics(**{**base, **overrides})


def diagnostics_str(diag: RunDiagnostics, *, width: int = 100, terminal: bool = True) -> str:
    """Render the block and strip the styling, leaving the layout.

    `force_terminal` is the only way to reach the styled branch from a test — the choice is
    `console.is_terminal`, and pytest's capture is not one. `no_color` does not make the
    output plain: it drops colour but keeps bold and dim, which are still escape sequences
    and still count toward `len`, so they come off here rather than in the assertions.
    """
    console = Console(
        file=io.StringIO(),
        width=width,
        force_terminal=terminal,
        highlight=False,
        emoji=False,
    )
    render_diagnostics(diag, console=console)
    return re.sub(r"\x1b\[[0-9;]*m", "", console.file.getvalue())


def test_a_non_terminal_destination_gets_the_greppable_counters() -> None:
    """§11: these go into the CI job output, where a two-column layout is unsearchable."""
    out = diagnostics_str(diagnostics(unmappable_count=3), terminal=False)

    assert "unmappable_count=3" in out
    assert "hallucinated_file_count=0" in out
    assert "masked_line_count=0" in out
    assert "timings:" in out
    assert "total cost this run: $0.0088" in out


def test_a_terminal_destination_gets_the_table() -> None:
    out = diagnostics_str(diagnostics())

    assert "unmappable_count=" not in out, "the styled form drops key=value entirely"
    assert "0 unmappable lines" in out
    assert "$0.0088" in out, "the run total is the number the block exists to surface"
    assert "sample_diffs/auth_bypass.diff" in out


@pytest.mark.parametrize("width", [60, 80, 100, 200])
def test_the_cost_column_survives_every_width(width) -> None:
    """The model name absorbs a narrow terminal; the cost is not reconstructable if cropped."""
    out = diagnostics_str(diagnostics(), width=width)

    for call in CALLS:
        assert f"${call.cost:.4f}" in out
    assert max(len(line) for line in out.splitlines()) <= width


def test_the_default_run_prints_one_line_not_a_block() -> None:
    """Without `--verbose` there is nothing to head, and a heading over one line is chrome."""
    rendered = diagnostics_str(diagnostics(verbose=False))
    out = [line for line in rendered.splitlines() if line.strip()]

    assert len(out) == 1
    assert "0 unmappable lines" in out[0]


def test_counters_are_singular_when_they_are_one() -> None:
    out = diagnostics_str(diagnostics(unmappable_count=1, hallucinated_file_count=1))

    assert "1 unmappable line " in out
    assert "1 hallucinated file " in out


def test_the_detail_behind_a_counter_is_shown_when_there_is_any() -> None:
    """The count says something moved; §11 tunes on knowing where."""
    out = diagnostics_str(
        diagnostics(
            unmappable_count=1,
            unmappable_lines=("src/app/urls.py:4242",),
            hallucinated_file_count=1,
            hallucinated_files=("src/app/nope.py",),
        )
    )

    assert "src/app/urls.py:4242" in out
    assert "src/app/nope.py" in out


def test_the_timing_split_separates_the_network_from_the_pipeline() -> None:
    """"Why was that slow" is answered by the split, not by summing eight stages."""
    out = diagnostics_str(diagnostics())

    assert "12.69s" in out, "review_pass + summary_pass, the part that was the network"
    assert "29.1ms" in out, "everything else"
    assert "review_pass" not in out, "the api total already said it; the detail is local only"
