"""Filtering, packing, and prompt assembly tests (SPEC.md §7, §8, §11).

Two properties carry most of the weight here:

* **Byte-stability** (§8). Temperature is not a determinism guarantee; identical prompt
  bytes are the larger lever, and they are testable, so they are tested.
* **The line-number contract** (§11). The prompt is where `unmappable_count` is won or
  lost, so the rendering that makes the valid answer set explicit is asserted directly.
"""

from __future__ import annotations

import json

import pytest
from conftest import build_diff, load

from review_bot.diff_parser import parse_diff
from review_bot.prompt_builder import (
    REVIEW_SYSTEM_PROMPT,
    SUMMARY_SYSTEM_PROMPT,
    Batch,
    FileBlock,
    build_review_prompt,
    build_summary_prompt,
    estimate_tokens,
    filter_files,
    pack,
    render_file_block,
)
from review_bot.schema import Finding

# ------------------------------------------------------------------------------------
# Filtering (§7)
# ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("package-lock.json", "lockfiles"),
        ("requirements.txt", "lockfiles"),
        ("go.sum", "lockfiles"),
        ("vendor/lib/thing.py", "generated"),
        ("node_modules/x/index.js", "generated"),
        ("dist/bundle.js", "generated"),
        ("static/app.min.js", "generated"),
        ("api/service_pb2.py", "generated"),
        ("src/schema.generated.ts", "generated"),
    ],
)
def test_excluded_paths_never_reach_the_model(path: str, reason: str) -> None:
    result = filter_files(build_diff(path, added=["x = 1"]))
    assert result.reviewable == []
    assert result.excluded == [(path, reason)]


def test_source_files_are_reviewable() -> None:
    result = filter_files(build_diff("src/app/mod.py", added=["x = 1"]))
    assert [f.path for f in result.reviewable] == ["src/app/mod.py"]
    assert result.excluded == []


def test_binary_and_no_added_lines_are_excluded() -> None:
    from conftest import TEST_DIFFS

    # This diff carries a binary file and a text file, so it also checks that filtering is
    # per file: the text file beside the binary one is still reviewed.
    binary = filter_files(parse_diff((TEST_DIFFS / "binary_file.diff").read_text()))
    assert binary.excluded == [("assets/logo.png", "binary")]
    assert [f.path for f in binary.reviewable] == ["src/app/theme.py"]

    deletion = filter_files(parse_diff((TEST_DIFFS / "deleted_file.diff").read_text()))
    assert deletion.reviewable == []
    assert [reason for _, reason in deletion.excluded] == ["no added lines"]


def test_exclusion_summary_is_reported_to_the_reviewer() -> None:
    """§7: excluded files are counted and reported so the reviewer knows what was skipped."""
    result = filter_files(build_diff("package-lock.json", added=['"lodash": "4.17.21"']))
    assert "1 files excluded" in result.exclusion_summary()
    assert "lockfiles" in result.exclusion_summary()


# ------------------------------------------------------------------------------------
# Line-number rendering (§11)
# ------------------------------------------------------------------------------------


def test_added_lines_carry_their_post_file_line_number() -> None:
    diff = build_diff("src/app/mod.py", added=["a = 1", "b = 2"])
    block = render_file_block(diff.files[0])

    assert "citable_lines: [2, 3]" in block
    assert "+      2 | a = 1" in block
    assert "+      3 | b = 2" in block


def test_context_and_removed_lines_carry_no_line_number() -> None:
    """Citing one is unmappable by definition — the reviewer must not be sent to a line
    this pull request did not add (§11). Withholding the number removes the temptation."""
    diff = build_diff("src/app/mod.py", added=["new = 1"], removed=["old = 1"])
    block = render_file_block(diff.files[0])

    for line in block.splitlines():
        if line.startswith(("-", " " * 9)):
            assert "|" in line
            gutter = line.split("|", 1)[0]
            assert not any(ch.isdigit() for ch in gutter[1:]), f"numbered non-added line: {line!r}"


def test_citable_lines_matches_the_parsed_added_set() -> None:
    """The prompt's promise and `schema.validate_findings`' check must be the same set."""
    diff = load("auth_bypass.diff")
    for parsed_file in diff.files:
        block = render_file_block(parsed_file)
        declared = json.loads(block.split("citable_lines: ")[1].splitlines()[0])
        assert set(declared) == parsed_file.added_line_numbers


# ------------------------------------------------------------------------------------
# Packing (§7)
# ------------------------------------------------------------------------------------


def test_small_files_pack_into_one_call() -> None:
    files = [
        build_diff("src/b.py", added=["b = 1"]).files[0],
        build_diff("src/a.py", added=["a = 1"]).files[0],
    ]
    batches = pack(files, max_input_tokens=8000)
    assert len(batches) == 1
    assert batches[0].paths == ["src/a.py", "src/b.py"]


def test_files_are_sorted_lexicographically_before_packing() -> None:
    """§7/§8: sorted file order is what makes the same diff produce the same prompt bytes."""
    forward = [
        build_diff("src/a.py", added=["a = 1"]).files[0],
        build_diff("src/b.py", added=["b = 1"]).files[0],
    ]
    reverse = list(reversed(forward))
    assert pack(forward)[0].render() == pack(reverse)[0].render()


def test_batches_respect_the_token_budget() -> None:
    files = [build_diff(f"src/f{i}.py", added=["x = 1"] * 20).files[0] for i in range(6)]
    per_file = pack([files[0]], max_input_tokens=100_000)[0].token_estimate

    batches = pack(files, max_input_tokens=per_file * 2)

    assert len(batches) > 1
    for batch in batches:
        # A batch may exceed the budget only when a single block already did (§7).
        assert batch.token_estimate <= per_file * 2 or len(batch.blocks) == 1


def test_oversized_file_is_split_by_hunk_and_confidence_capped() -> None:
    """§7: a file over budget is split, and its findings are capped at `medium`."""
    diff = parse_diff(
        "diff --git a/src/big.py b/src/big.py\n"
        "--- a/src/big.py\n+++ b/src/big.py\n"
        "@@ -1,1 +1,3 @@\n ctx\n+one = 1\n+two = 2\n"
        "@@ -50,1 +52,3 @@\n ctx\n+three = 3\n+four = 4\n"
    )
    blocks = pack(diff.files, max_input_tokens=40)

    assert len(blocks) > 1, "the file should not have survived as one block"
    assert all(b.confidence_capped for batch in blocks for b in batch.blocks)
    assert blocks[0].confidence_cap("src/big.py") == "medium"


def test_confidence_cap_applies_only_to_split_files() -> None:
    whole = pack(build_diff("src/a.py", added=["a = 1"]).files)[0]
    assert whole.confidence_cap("src/a.py") is None


def test_apply_confidence_caps_downgrades_high_only() -> None:
    from review_bot.prompt_builder import apply_confidence_caps

    batch = Batch(blocks=[FileBlock("src/a.py", "", 1, confidence_capped=True)])
    findings = [
        Finding(
            file="src/a.py",
            line=2,
            category="injection",
            severity="high",
            confidence=level,
            evidence="e",
            risk="r",
            recommendation="rec",
            source="llm",
        )
        for level in ("high", "low")
    ]
    capped = apply_confidence_caps(findings, batch)
    assert [f.confidence for f in capped] == ["medium", "low"]


# ------------------------------------------------------------------------------------
# Prompt assembly and byte-stability (§8)
# ------------------------------------------------------------------------------------


def test_review_prompt_is_byte_stable_across_runs() -> None:
    """§8: temperature 0 is worthless if the prompt bytes drift between runs."""
    diff = load("auth_bypass.diff")
    suppressed = {("src/app/urls.py", 33), ("src/app/views/admin.py", 8)}

    first = build_review_prompt(pack(diff.files)[0], suppressed)
    second = build_review_prompt(pack(load("auth_bypass.diff").files)[0], set(suppressed))

    assert first.system == second.system
    assert first.user == second.user


def test_suppression_list_is_sorted_and_serialised_stably() -> None:
    diff = build_diff("src/a.py", added=["a = 1", "b = 2", "c = 3"])
    batch = pack(diff.files)[0]

    forward = build_review_prompt(batch, {("src/a.py", 2), ("src/a.py", 4), ("src/a.py", 3)})
    reverse = build_review_prompt(batch, {("src/a.py", 4), ("src/a.py", 3), ("src/a.py", 2)})

    assert forward.user == reverse.user
    assert forward.user.index('"line": 2') < forward.user.index('"line": 3')


def test_suppression_list_names_only_files_in_this_batch() -> None:
    diff = build_diff("src/a.py", added=["a = 1"])
    prompt = build_review_prompt(pack(diff.files)[0], {("src/elsewhere.py", 7)})
    assert "src/elsewhere.py" not in prompt.user
    assert "Suppression list: none." in prompt.user


def test_tier2_hits_are_not_in_the_prompt() -> None:
    """§8/§12: suppression, not hinting. Only Tier 1 pairs reach the model, and they are
    told to stay away rather than invited to confirm."""
    from review_bot.role_scanner import scan_diff

    diff = load("injection_and_logging.diff")
    scan = scan_diff(diff)
    assert scan.findings, "this sample should produce Tier 2 hits"
    assert scan.suppressed == set(), "these are Tier 2 — nothing to suppress"

    prompt = build_review_prompt(pack(diff.files)[0], scan.suppressed)
    assert "Suppression list: none." in prompt.user
    for finding in scan.findings:
        assert finding.evidence not in prompt.user, "a Tier 2 hit leaked into the prompt as a hint"


def test_system_prompt_has_no_interpolation_points() -> None:
    """A constant with no formatting placeholders cannot drift between calls (§8)."""
    for prompt in (REVIEW_SYSTEM_PROMPT, SUMMARY_SYSTEM_PROMPT):
        assert "{}" not in prompt
        assert "%s" not in prompt


def test_system_prompt_clears_the_cache_minimum() -> None:
    """Prompt caching needs a 1024-token minimum prefix on `claude-sonnet-5`; a shorter
    system prompt silently never caches, and §8's cost model assumes it does."""
    assert estimate_tokens(REVIEW_SYSTEM_PROMPT) >= 1024


def test_system_prompt_forbids_the_deterministic_only_category() -> None:
    """§5: the LLM never reports `hardcoded_secrets` and is instructed not to."""
    assert "hardcoded_secrets" in REVIEW_SYSTEM_PROMPT
    assert "Do NOT report `hardcoded_secrets`" in REVIEW_SYSTEM_PROMPT


def test_summary_prompt_never_contains_the_diff() -> None:
    """§8: call 2 gets the file list and findings only. Never the diff."""
    diff = load("auth_bypass.diff")
    findings = [
        Finding(
            file="src/app/urls.py",
            line=33,
            category="auth_perms",
            severity="high",
            confidence="high",
            evidence="a new admin route was registered",
            risk="r",
            recommendation="rec",
            source="deterministic",
        )
    ]
    prompt = build_summary_prompt([f.path for f in diff.files], [("x.lock", "lockfiles")], findings)

    for parsed_file in diff.files:
        for line in parsed_file.added_lines:
            if line.content.strip():
                assert line.content not in prompt.user, "diff content reached the summary call"
    assert "src/app/urls.py" in prompt.user


def test_summary_prompt_is_byte_stable_regardless_of_finding_order() -> None:
    def finding(path: str, line: int) -> Finding:
        return Finding(
            file=path,
            line=line,
            category="injection",
            severity="high",
            confidence="low",
            evidence="e",
            risk="r",
            recommendation="rec",
            source="llm",
        )

    a, b = finding("src/a.py", 2), finding("src/b.py", 5)
    assert (
        build_summary_prompt(["src/a.py", "src/b.py"], [], [a, b]).user
        == build_summary_prompt(["src/b.py", "src/a.py"], [], [b, a]).user
    )


def test_prompts_contain_no_timestamps_or_identifiers() -> None:
    """§8: no timestamps, run IDs, or UUIDs anywhere in the prompt — they belong in the
    output. This checks the assembled bytes, not just the constants."""
    import re

    diff = load("secrets_and_logging.diff")
    prompt = build_review_prompt(pack(diff.files)[0], set())
    combined = prompt.system + prompt.user

    assert not re.search(r"\b20\d{2}-\d{2}-\d{2}T", combined), "an ISO timestamp reached the prompt"
    assert not re.search(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", combined
    ), "a UUID reached the prompt"


def test_masked_placeholders_reach_the_prompt_and_raw_values_do_not() -> None:
    """Invariant 1, asserted at the boundary it protects: whatever the prompt contains is
    what would go over the wire."""
    from review_bot.secret_masker import mask_diff

    diff = load("secrets_and_logging.diff")
    mask_diff(diff)
    prompt = build_review_prompt(pack(filter_files(diff).reviewable)[0], set())

    assert "[MASKED_" in prompt.user
    for raw in ("AKIAIOSFODNN7EXAMPLE", "hunter2-not-real"):
        assert raw not in prompt.user
