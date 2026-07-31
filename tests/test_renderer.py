"""Markdown rendering (SPEC.md §13, §17).

Four things are asserted here, and only one of them is cosmetic:

* **Grouping and sorting** — the reviewer's reading order is the product decision §13 makes.
* **The severity header** — it exists so triage happens before scrolling.
* **No cap** — hiding a real finding to save screen space is the worse failure, so the
  count that renders must equal the count that came in, always.
* **Masked placeholders survive** — invariant 7. A raw secret value must never render, and
  the renderer is the last stage that could break that by escaping or rewriting evidence.
"""

from __future__ import annotations

import re

import pytest

from review_bot.renderer import group_by_file, render_markdown, severity_counts
from review_bot.schema import Finding, Review


def finding(
    file: str = "src/a.py",
    line: int | None = 10,
    category: str = "injection",
    severity: str = "high",
    confidence: str = "high",
    evidence: str = "evidence text",
    **kwargs,
) -> Finding:
    return Finding(
        file=file,
        line=line,
        category=category,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        risk=kwargs.pop("risk", "why it matters"),
        recommendation=kwargs.pop("recommendation", "how to fix it"),
        **kwargs,
    )


def review(*findings: Finding, **kwargs) -> Review:
    return Review(
        summary=kwargs.pop("summary", "a summary"),
        overall_risk=kwargs.pop("overall_risk", "high"),
        findings=list(findings),
        pr_comment=kwargs.pop("pr_comment", "a pr comment"),
        **kwargs,
    )


def headings(markdown: str) -> list[str]:
    return [line for line in markdown.splitlines() if line.startswith(("## ", "### "))]


# ------------------------------------------------------------------------------------
# Grouping and sorting (§13)
# ------------------------------------------------------------------------------------


def test_findings_are_grouped_by_file_lexicographically() -> None:
    rendered = render_markdown(
        review(
            finding(file="src/z.py", line=1),
            finding(file="src/a.py", line=1),
            finding(file="src/m.py", line=1),
        )
    )
    files = [h for h in headings(rendered) if h.startswith("## `")]
    assert files == ["## `src/a.py`", "## `src/m.py`", "## `src/z.py`"]


def test_all_findings_for_one_file_land_in_one_section() -> None:
    """Grouping means one heading per file, not one heading per finding."""
    rendered = render_markdown(
        review(
            finding(file="src/a.py", line=1),
            finding(file="src/b.py", line=1),
            finding(file="src/a.py", line=2),
            finding(file="src/a.py", line=3),
        )
    )
    assert rendered.count("## `src/a.py`") == 1
    assert [h for h in headings(rendered) if h.startswith("## `")] == [
        "## `src/a.py`",
        "## `src/b.py`",
    ]


def test_within_a_file_severity_beats_confidence_beats_line() -> None:
    """§13's ordering, with each tier of the key made to disagree with the next."""
    rendered = render_markdown(
        review(
            finding(line=1, severity="low", confidence="high"),
            finding(line=2, severity="high", confidence="low"),
            finding(line=3, severity="high", confidence="high"),
            finding(line=4, severity="medium", confidence="high"),
        )
    )
    lines = [int(m) for m in re.findall(r"### Line (\d+)", rendered)]
    assert lines == [3, 2, 4, 1]


def test_line_number_breaks_a_tie_ascending() -> None:
    rendered = render_markdown(
        review(finding(line=30), finding(line=10), finding(line=20))
    )
    assert [int(m) for m in re.findall(r"### Line (\d+)", rendered)] == [10, 20, 30]


def test_file_level_findings_render_first_in_their_section() -> None:
    """`line: null` sorts to the top: it is the one the reviewer cannot navigate to."""
    rendered = render_markdown(
        review(
            finding(line=5, severity="high", confidence="high"),
            finding(line=None, severity="high", confidence="high"),
        )
    )
    assert rendered.index("### File-level") < rendered.index("### Line 5")
    assert "could not be attributed to a specific added line" in rendered


def test_file_level_finding_never_renders_a_line_number() -> None:
    """Invariant 2: an unmappable finding must not acquire a line on the way to Markdown."""
    rendered = render_markdown(review(finding(line=None)))
    assert "### File-level" in rendered
    assert not re.search(r"### Line \d+", rendered)


def test_group_by_file_does_not_mutate_its_input() -> None:
    findings = [finding(file="src/z.py"), finding(file="src/a.py")]
    original = list(findings)
    group_by_file(findings)
    assert findings == original


# ------------------------------------------------------------------------------------
# Header (§13)
# ------------------------------------------------------------------------------------


def test_severity_header_counts_every_severity_present() -> None:
    rendered = render_markdown(
        review(
            *[finding(line=i, severity="high") for i in range(1, 4)],
            *[finding(line=i, severity="medium") for i in range(10, 17)],
            *[finding(line=i, severity="low") for i in range(20, 22)],
        )
    )
    assert "3 high · 7 medium · 2 low across 1 file" in rendered


def test_severity_header_counts_distinct_files() -> None:
    rendered = render_markdown(
        review(
            finding(file="src/a.py", line=1),
            finding(file="src/a.py", line=2),
            finding(file="src/b.py", line=1),
        )
    )
    assert "across 2 files" in rendered


def test_severity_counts_omit_severities_with_no_findings() -> None:
    assert severity_counts([finding(severity="high")]) == "1 high"
    assert severity_counts([finding(severity="low"), finding(severity="high")]) == "1 high · 1 low"


def test_overall_risk_is_taken_from_the_review_not_recomputed() -> None:
    """The renderer projects the JSON; it does not re-score it."""
    rendered = render_markdown(review(finding(severity="high"), overall_risk="low"))
    assert "**Overall risk: low**" in rendered


def test_excluded_note_renders_when_files_were_skipped() -> None:
    note = "12 files excluded from LLM review (binary, generated, lockfiles)"
    assert note in render_markdown(review(finding()), note)


def test_no_excluded_note_when_nothing_was_skipped() -> None:
    assert "excluded from LLM review" not in render_markdown(review(finding()))


# ------------------------------------------------------------------------------------
# No cap (§13)
# ------------------------------------------------------------------------------------


def test_no_cap_on_findings() -> None:
    """Every finding renders. Noise is a tuning problem, not a truncation problem."""
    findings = [finding(file=f"src/f{i % 7}.py", line=i) for i in range(1, 121)]
    rendered = render_markdown(review(*findings))

    assert len(re.findall(r"^### ", rendered, re.MULTILINE)) == 120
    assert "120 high across 7 files" in rendered


# ------------------------------------------------------------------------------------
# Findings render completely (§13, definition of done)
# ------------------------------------------------------------------------------------


def test_every_required_field_renders() -> None:
    rendered = render_markdown(
        review(
            finding(
                file="src/login.py",
                line=42,
                category="auth_perms",
                severity="medium",
                confidence="low",
                evidence="the evidence",
                risk="the risk",
                recommendation="the recommendation",
            )
        )
    )
    for expected in (
        "src/login.py",
        "Line 42",
        "auth_perms",
        "medium severity",
        "low confidence",
        "the evidence",
        "the risk",
        "the recommendation",
    ):
        assert expected in rendered


def test_internal_fields_never_render() -> None:
    """`_source` and `_rule_id` are tuning fields, stripped before output (§10)."""
    rendered = render_markdown(review(finding(source="both", rule_id="injection.execute_fstring")))
    assert "_source" not in rendered
    assert "both" not in rendered
    assert "injection.execute_fstring" not in rendered


def test_multiline_evidence_stays_inside_its_bullet() -> None:
    """A raw newline in a list item silently ends the item, so evidence is flattened."""
    rendered = render_markdown(review(finding(evidence="line one\nline two\n\nline three")))
    assert "- **Evidence:** line one line two line three" in rendered


def test_no_findings_renders_the_reason() -> None:
    rendered = render_markdown(
        review(no_findings_reason="No security-relevant changes were identified.")
    )
    assert "**No findings.**" in rendered
    assert "No security-relevant changes were identified." in rendered
    assert "no findings" in rendered.lower()


def test_pr_comment_and_advisory_framing_always_render() -> None:
    """§1: the tool assists a human reviewer and does not gate merges. Say so on the page."""
    rendered = render_markdown(review(finding(), pr_comment="please rotate that key"))
    assert "## PR comment" in rendered
    assert "please rotate that key" in rendered
    assert "Advisory only" in rendered


# ------------------------------------------------------------------------------------
# Invariant 7: raw secrets never render (§13, definition of done)
# ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "placeholder",
    ["[MASKED_AWS_KEY]", "[MASKED_PRIVATE_KEY]", "[MASKED_DB_URL]", "[MASKED_TOKEN]", "[MASKED_KEY]"],
)
def test_masked_placeholders_render_verbatim(placeholder: str) -> None:
    """The placeholder is what the reviewer sees, unescaped and unaltered (§13).

    Bracketed text is Markdown link syntax, so a renderer that "helpfully" escaped it would
    change the token the reviewer is being asked to recognise.
    """
    rendered = render_markdown(
        review(
            finding(
                category="hardcoded_secrets",
                evidence=f"`API_KEY` assigned a literal value at line 4 (masked as {placeholder})",
            )
        )
    )
    assert placeholder in rendered


def test_renderer_cannot_reintroduce_a_raw_value() -> None:
    """The renderer only ever copies what the schema handed it, so a value that was masked
    upstream has no path back. Asserted end to end in `test_cli.py` against real diffs."""
    rendered = render_markdown(
        review(finding(evidence="key set to [MASKED_AWS_KEY]", risk="r", recommendation="rec"))
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in rendered
    assert "[MASKED_AWS_KEY]" in rendered


# ------------------------------------------------------------------------------------
# Stability
# ------------------------------------------------------------------------------------


def test_rendering_is_deterministic_regardless_of_input_order() -> None:
    """Byte-identical output from the same findings in a different order (§8's spirit)."""
    findings = [
        finding(file="src/b.py", line=2, severity="low"),
        finding(file="src/a.py", line=9, severity="high"),
        finding(file="src/a.py", line=1, severity="high"),
        finding(file="src/c.py", line=None, severity="medium"),
    ]
    assert render_markdown(review(*findings)) == render_markdown(review(*reversed(findings)))


def test_output_ends_with_exactly_one_newline() -> None:
    rendered = render_markdown(review(finding()))
    assert rendered.endswith("\n")
    assert not rendered.endswith("\n\n")
