"""Schema, line-validation, and merge tests (SPEC.md §10, §11, §12; §17).

The per-module requirement is explicit: a valid response passes, a missing required field
fails with a clear error, an unmappable line degrades to `line: null`, a hallucinated file
is rejected, and merge and confidence promotion behave correctly. Each has a case here.

Nothing in this file touches the network. The "LLM response" is always a string.
"""

from __future__ import annotations

import json

import pytest
from conftest import build_diff, load

from review_bot.schema import (
    Finding,
    LLMFinding,
    MalformedLLMResponse,
    Review,
    merge_findings,
    overall_risk,
    parse_review_response,
    parse_summary_response,
    validate_findings,
)


def llm_response(*findings: dict) -> str:
    return json.dumps({"findings": list(findings)})


def a_finding(**overrides) -> dict:
    base = {
        "file": "src/app/mod.py",
        "line": 2,
        "category": "injection",
        "severity": "high",
        "confidence": "medium",
        "evidence": "`eval(user_input)` on the added line",
        "risk": "Arbitrary code execution if the argument is attacker-influenced.",
        "recommendation": "Replace `eval` with `ast.literal_eval`.",
    }
    base.update(overrides)
    return base


def deterministic(**overrides) -> Finding:
    base = {
        "file": "src/app/mod.py",
        "line": 2,
        "category": "injection",
        "severity": "high",
        "confidence": "low",
        "evidence": "Added line introduces a code-execution sink",
        "risk": "deterministic risk text",
        "recommendation": "deterministic recommendation text",
        "source": "deterministic",
        "rule_id": "injection.code_exec",
    }
    base.update(overrides)
    return Finding(**base)


# ------------------------------------------------------------------------------------
# Parsing (§15)
# ------------------------------------------------------------------------------------


def test_valid_response_parses() -> None:
    findings = parse_review_response(llm_response(a_finding()))
    assert len(findings) == 1
    assert findings[0].category == "injection"
    assert findings[0].source == "llm", "parsed findings must be attributed to the model"


def test_empty_findings_list_is_valid() -> None:
    """Zero findings is a successful review, not an error (§15)."""
    assert parse_review_response('{"findings": []}') == []


def test_missing_required_field_fails_with_a_clear_error() -> None:
    payload = a_finding()
    del payload["risk"]
    with pytest.raises(MalformedLLMResponse) as exc:
        parse_review_response(llm_response(payload))
    assert "risk" in str(exc.value), "the error must name the field that was missing"
    assert exc.value.raw, "the raw response must survive for the exit-2 path to print it"


def test_unknown_field_is_malformed_not_ignored() -> None:
    """`extra=forbid`: an invented field means the model is not following the contract."""
    with pytest.raises(MalformedLLMResponse):
        parse_review_response(llm_response(a_finding(cwe="CWE-95")))


def test_invalid_enum_value_is_malformed() -> None:
    with pytest.raises(MalformedLLMResponse):
        parse_review_response(llm_response(a_finding(severity="critical")))


def test_llm_may_not_report_hardcoded_secrets() -> None:
    """§5: deterministic-only. A masked value cannot be evidenced without unmasking it."""
    with pytest.raises(MalformedLLMResponse):
        parse_review_response(llm_response(a_finding(category="hardcoded_secrets")))


@pytest.mark.parametrize(
    "raw",
    [
        "not json at all",
        "",
        "[]",  # a list, not the object the contract specifies
        '{"findings": "none"}',
        '{"findings": [], "summary": "x"}',  # summary belongs to call 2 (§8)
    ],
)
def test_malformed_responses_raise(raw: str) -> None:
    with pytest.raises(MalformedLLMResponse) as exc:
        parse_review_response(raw)
    assert exc.value.raw == raw, "exit 2 prints the raw response verbatim (§15)"


def test_code_fence_is_tolerated() -> None:
    """Framing, not content. The JSON inside is still held to the full contract."""
    fenced = "```json\n" + llm_response(a_finding()) + "\n```"
    assert len(parse_review_response(fenced)) == 1


def test_summary_response_parses_and_validates() -> None:
    parsed = parse_summary_response(
        json.dumps({"summary": "s", "overall_risk": "high", "pr_comment": "c"})
    )
    assert parsed.overall_risk == "high"

    with pytest.raises(MalformedLLMResponse):
        parse_summary_response(json.dumps({"summary": "s", "overall_risk": "high"}))


# ------------------------------------------------------------------------------------
# Line validation (§11)
# ------------------------------------------------------------------------------------


def test_line_in_the_added_set_is_accepted() -> None:
    diff = build_diff("src/app/mod.py", added=["result = eval(user_expr)"])
    assert diff.files[0].added_line_numbers == frozenset({2})

    kept, stats = validate_findings(parse_review_response(llm_response(a_finding(line=2))), diff)
    assert [f.line for f in kept] == [2]
    assert stats.unmappable_count == 0
    assert stats.hallucinated_file_count == 0


def test_unmappable_line_degrades_to_file_level() -> None:
    """§11: degrade, do not drop. The model may have found something real in a real file."""
    diff = build_diff("src/app/mod.py", added=["result = eval(user_expr)"])

    kept, stats = validate_findings(parse_review_response(llm_response(a_finding(line=999))), diff)
    assert len(kept) == 1, "a real file with a bad line is kept as a file-level finding"
    assert kept[0].line is None
    assert stats.unmappable_count == 1
    assert stats.unmappable_lines == [("src/app/mod.py", 999)]


def test_context_line_number_is_unmappable() -> None:
    """Line 1 is context, not added. The reviewer must not be sent to a line this PR
    did not add — that is the whole point of validating against the *added* set."""
    diff = build_diff("src/app/mod.py", added=["result = eval(user_expr)"])
    kept, stats = validate_findings(parse_review_response(llm_response(a_finding(line=1))), diff)
    assert kept[0].line is None
    assert stats.unmappable_count == 1


def test_hallucinated_file_is_rejected_entirely() -> None:
    diff = build_diff("src/app/mod.py", added=["result = eval(user_expr)"])

    kept, stats = validate_findings(
        parse_review_response(llm_response(a_finding(file="src/app/ghost.py"))), diff
    )
    assert kept == [], "a file the diff never touched has no salvageable reading"
    assert stats.hallucinated_file_count == 1
    assert stats.hallucinated_files == ["src/app/ghost.py"]
    assert stats.unmappable_count == 0, "a rejected file is not also counted as unmappable"


def test_null_line_passes_validation_untouched() -> None:
    diff = build_diff("src/app/mod.py", added=["result = eval(user_expr)"])
    kept, stats = validate_findings(
        parse_review_response(llm_response(a_finding(line=None))), diff
    )
    assert kept[0].line is None
    assert stats.unmappable_count == 0, "an honest file-level finding is not a tuning failure"


def test_validation_is_per_file_not_global() -> None:
    """Line 2 exists in one file but not the other. The set is per file (§11)."""
    diff = load("auth_bypass.diff")
    paths = [f.path for f in diff.files]
    assert len(paths) >= 2

    first, second = diff.files[0], diff.files[1]
    stray = max(second.added_line_numbers)
    assert stray not in first.added_line_numbers

    kept, stats = validate_findings(
        [Finding(**a_finding(file=first.path, line=stray), source="llm")], diff
    )
    assert kept[0].line is None
    assert stats.unmappable_count == 1


# ------------------------------------------------------------------------------------
# Merge, dedupe, confidence promotion (§12)
# ------------------------------------------------------------------------------------


def test_deterministic_findings_survive_without_any_llm_findings() -> None:
    """Invariant 3: deterministic findings never depend on a network call."""
    det = deterministic()
    assert merge_findings([det], []) == [det]


def test_agreement_promotes_confidence_and_marks_both() -> None:
    det = deterministic(confidence="low")
    llm = Finding(**a_finding(), source="llm")

    merged = merge_findings([det], [llm])

    assert len(merged) == 1, "same (file, line, category) is one finding, not two (§12.1)"
    assert merged[0].confidence == "high", "two independent detectors concurring is evidence"
    assert merged[0].source == "both"


def test_merge_keeps_llm_prose_and_deterministic_evidence() -> None:
    """§12.4: the LLM writes better prose, the deterministic rule has verifiable evidence."""
    det = deterministic()
    llm = Finding(**a_finding(), source="llm")

    merged = merge_findings([det], [llm])[0]

    assert merged.evidence == det.evidence
    assert merged.risk == llm.risk
    assert merged.recommendation == llm.recommendation


def test_deterministic_identity_wins_on_conflict() -> None:
    """§12.2: the deterministic `category`, `file`, and `line` win."""
    det = deterministic(rule_id="injection.code_exec")
    llm = Finding(**a_finding(), source="llm")

    merged = merge_findings([det], [llm])[0]

    assert merged.rule_id == "injection.code_exec"
    assert (merged.file, merged.line, merged.category) == det.dedupe_key()


def test_disagreeing_findings_are_both_kept() -> None:
    """Different categories on the same line are different findings, not a conflict."""
    det = deterministic(category="injection")
    llm = Finding(**a_finding(category="input_validation"), source="llm")

    merged = merge_findings([det], [llm])

    assert len(merged) == 2
    assert {f.category for f in merged} == {"injection", "input_validation"}


def test_llm_only_finding_passes_through() -> None:
    llm = Finding(**a_finding(category="input_validation"), source="llm")
    merged = merge_findings([], [llm])
    assert merged == [llm]
    assert merged[0].source == "llm", "no deterministic rule fired, so it is not `both`"


def test_duplicate_llm_findings_collapse_to_the_stronger() -> None:
    low = Finding(**a_finding(confidence="low"), source="llm")
    high = Finding(**a_finding(confidence="high"), source="llm")

    merged = merge_findings([], [low, high])

    assert len(merged) == 1
    assert merged[0].confidence == "high"


def test_file_level_and_line_level_are_distinct_keys() -> None:
    """`line: None` is its own dedupe key — a file-level finding is not the same finding
    as one anchored to a line, and collapsing them would hide one of the two."""
    file_level = Finding(**a_finding(line=None), source="llm")
    line_level = Finding(**a_finding(line=2), source="llm")

    assert len(merge_findings([], [file_level, line_level])) == 2


def test_merged_output_is_sorted_for_stable_output() -> None:
    findings = [
        Finding(**a_finding(file="src/z.py", line=2), source="llm"),
        Finding(**a_finding(file="src/a.py", line=9), source="llm"),
        Finding(**a_finding(file="src/a.py", line=None), source="llm"),
    ]
    merged = merge_findings([], findings)
    assert [(f.file, f.line) for f in merged] == [
        ("src/a.py", None),
        ("src/a.py", 9),
        ("src/z.py", 2),
    ]


# ------------------------------------------------------------------------------------
# Output shape (§10)
# ------------------------------------------------------------------------------------


def test_internal_fields_are_stripped_from_output() -> None:
    """§10: `_source` and `_rule_id` are tuning fields, not reviewer-facing."""
    public = deterministic().public_dict()
    assert "source" not in public and "_source" not in public
    assert "rule_id" not in public and "_rule_id" not in public
    assert set(public) == {
        "file",
        "line",
        "category",
        "severity",
        "confidence",
        "evidence",
        "risk",
        "recommendation",
    }


def test_review_public_dict_matches_the_brief_schema() -> None:
    review = Review(
        summary="s", overall_risk="low", findings=[deterministic()], pr_comment="c"
    )
    payload = review.public_dict()
    assert set(payload) == {
        "summary",
        "overall_risk",
        "findings",
        "pr_comment",
        "no_findings_reason",
    }
    json.dumps(payload)  # must be serialisable as-is; JSON is the source of truth


@pytest.mark.parametrize(
    ("severities", "expected"),
    [([], "low"), (["low"], "low"), (["low", "medium"], "medium"), (["medium", "high"], "high")],
)
def test_overall_risk_fallback(severities: list[str], expected: str) -> None:
    """Used when the summary pass did not run, so `--no-llm` still emits a valid Review."""
    findings = [deterministic(line=i + 2, severity=s) for i, s in enumerate(severities)]
    assert overall_risk(findings) == expected


# ------------------------------------------------------------------------------------
# Contract test (§17) — the highest-value test in the suite
# ------------------------------------------------------------------------------------


def test_every_recorded_fixture_validates_against_the_current_schema(fixtures_dir) -> None:
    """Every recorded fixture must validate against the current pydantic schema.

    The day a required field is added, this breaks and reports that the prompt is out of
    sync with the schema. Do not skip or xfail it to get CI green (CLAUDE.md).
    """
    recorded = sorted(fixtures_dir.glob("*.json"))
    for path in recorded:
        raw = path.read_text()
        if path.name.startswith("summary"):
            parse_summary_response(raw)
        else:
            parse_review_response(raw)


def test_llm_finding_model_covers_every_reportable_category() -> None:
    """A category added to the schema without being added to the LLM's allowed set would
    silently become unreportable. This fails when the two drift apart."""
    from review_bot.schema import LLM_CATEGORIES

    allowed = set(LLMFinding.model_fields["category"].annotation.__args__)
    assert allowed == LLM_CATEGORIES
