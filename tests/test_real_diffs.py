"""Real GitHub pull-request diffs (SPEC.md §25).

`sample_diffs/` is hand-written to make each rule fire, and the rules were tuned against it.
That makes it a poor witness for whether the tool survives input nobody wrote for it — the
diffs are 30 lines, one hunk, one concern, and every one of them is *supposed* to produce
findings. `real_diffs/` is five real merged public PRs, committed verbatim, and it covers
the pipeline paths a hand-written sample never reaches: a 900-line eleven-file diff that
packs into more than one call, a lockfile-only change where every file is filtered out, and
a pure deletion with no added lines anywhere.

No network here either (§17). The diffs are committed; `make refresh-real-diffs` re-fetches
them and `MANIFEST.json` records where each came from.

**The counts in `MANIFEST.json` are measured, not hoped for**, and this module is what keeps
them that way. Most real PRs produce zero deterministic findings, and a rule change that
starts firing on ordinary code shows up here as a count that no longer matches.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from review_bot.diff_parser import parse_diff
from review_bot.prompt_builder import build_review_prompt, filter_files, pack
from review_bot.role_scanner import scan_diff
from review_bot.schema import merge_findings, validate_findings
from review_bot.secret_masker import mask_diff

REAL_DIFFS = Path(__file__).parent.parent / "real_diffs"
MANIFEST = json.loads((REAL_DIFFS / "MANIFEST.json").read_text())
ENTRIES = {entry["file"]: entry for entry in MANIFEST["diffs"]}
NAMES = sorted(ENTRIES)


def load(name: str):
    return parse_diff((REAL_DIFFS / name).read_text())


def deterministic(diff) -> list:
    """Everything the deterministic layer produces, in the order `cli.py` collects it."""
    return mask_diff(diff).findings + scan_diff(diff).findings


# --------------------------------------------------------------------------------------
# The manifest is the documentation, so it has to be true
# --------------------------------------------------------------------------------------


def test_manifest_lists_exactly_the_committed_diffs() -> None:
    """A diff added without provenance is an unexplained 900 lines in the repository."""
    on_disk = sorted(p.name for p in REAL_DIFFS.glob("*.diff"))
    assert on_disk == NAMES


@pytest.mark.parametrize("name", NAMES)
def test_every_entry_records_its_provenance(name) -> None:
    entry = ENTRIES[name]
    assert entry["repo"].count("/") == 1
    assert isinstance(entry["pr"], int)
    assert entry["url"].startswith("https://github.com/")
    assert entry["exercises"], "a diff with no stated purpose is a diff nobody can retire"


@pytest.mark.parametrize("name", NAMES)
def test_deterministic_finding_counts_match_the_manifest(name) -> None:
    """The documented number is the measured number, and stays that way.

    This is the false-positive canary of §16 applied to real code: `clean_but_suspicious`
    proves the rules stay quiet on code *written* to look alarming, and these prove they
    stay quiet on code nobody wrote for them at all.
    """
    assert len(deterministic(load(name))) == ENTRIES[name]["deterministic_findings"]


# --------------------------------------------------------------------------------------
# Every diff, every invariant
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_real_diffs_parse(name) -> None:
    """Real diffs carry rename headers, mode changes, and `\\ No newline at end of file`."""
    diff = load(name)
    assert len(diff.files) > 0


@pytest.mark.parametrize("name", NAMES)
def test_added_line_numbers_are_consistent(name) -> None:
    """§11 rests on this set being right; a real diff is where the arithmetic gets tested."""
    for parsed_file in load(name).files:
        for line in parsed_file.added_lines:
            assert line.line_no is not None
            assert line.line_no in parsed_file.added_line_numbers
            assert line.source_line_no is None


@pytest.mark.parametrize("name", NAMES)
def test_no_finding_cites_a_line_the_diff_does_not_show(name) -> None:
    """Invariant 2 over real input, deterministic findings included (§11 as amended M4)."""
    diff = load(name)
    for found in deterministic(diff):
        parsed_file = diff.file(found.file)
        assert parsed_file is not None, f"{found.file} is not in the diff"
        if found.line is None:
            continue
        shown = {ln.line_no for hunk in parsed_file.hunks for ln in hunk.lines} - {None}
        assert found.line in shown


@pytest.mark.parametrize("name", NAMES)
def test_masking_runs_before_any_prompt_is_built(name) -> None:
    """Invariant 1 over real input: prompts are built from the masked diff, never the raw one."""
    diff = load(name)
    mask_diff(diff)
    scan = scan_diff(diff)
    for batch in pack(filter_files(diff).reviewable, 8000):
        prompt = build_review_prompt(batch, scan.suppressed)
        assert "BEGIN RSA PRIVATE KEY" not in prompt.user
        assert "AKIA" not in prompt.user


@pytest.mark.parametrize("name", NAMES)
def test_findings_survive_validation_and_merge(name) -> None:
    """The deterministic layer's output is well-formed against its own diff, end to end."""
    diff = load(name)
    found = deterministic(diff)
    merged = merge_findings(found, [])
    assert len(merged) <= len(found)  # merge only ever dedupes
    _, stats = validate_findings([], diff)
    assert stats.hallucinated_file_count == 0


# --------------------------------------------------------------------------------------
# What each diff is kept for
# --------------------------------------------------------------------------------------


def test_dependency_bump_is_entirely_filtered_and_makes_no_call() -> None:
    """Invariant 6 on real input: a lockfile-only PR is Tier 1 findings and zero API calls."""
    diff = load("dependency_bump.diff")
    filtered = filter_files(diff)

    assert filtered.reviewable == []
    assert pack(filtered.reviewable, 8000) == []
    assert {reason for _, reason in filtered.excluded} == {"lockfiles"}

    found = deterministic(diff)
    assert [f.category for f in found] == ["dependency_change", "dependency_change"]
    assert all(f.line is None for f in found), "a manifest finding is file-level (§6)"


def test_large_multi_file_needs_more_than_one_call() -> None:
    """§7's bin-packing, exercised by a diff rather than by a constructed test case.

    `SPEC.md §22` resolved the 8,000-token default by noting that all five sample diffs pack
    into one call well under it — so the splitting path had only ever been exercised by
    tests. This is the first committed diff that actually splits.
    """
    diff = load("large_multi_file.diff")
    filtered = filter_files(diff)
    batches = pack(filtered.reviewable, 8000)

    assert len(diff.files) == 11
    assert len(batches) > 1, "an 11-file, 900-line diff should not fit in one 8k call"
    for batch in batches:
        assert build_review_prompt(batch, set()).token_estimate <= 8000 * 1.5


def test_large_multi_file_keeps_its_documented_false_positive() -> None:
    """The most useful thing in `real_diffs/`: §21 limitation 2, caught on real input.

    detect-secrets fires on documentation showing `http://user:pass@proxy` example URLs.
    It is right that the line is credential-shaped and wrong that it matters, and the path
    heuristic scores `docs/` as `src` and calls it high severity. Asserted rather than fixed:
    the tool cannot tell a live credential from an example without the value, and the value
    is destroyed by design. A rule change that silences this should have to delete the test.
    """
    found = deterministic(load("large_multi_file.diff"))
    secrets = [f for f in found if f.category == "hardcoded_secrets"]

    assert len(secrets) == 2
    assert all(f.file == "docs/advanced.md" for f in secrets)
    assert all(f.severity == "high" for f in secrets)
    assert all("[MASKED_" in f.evidence for f in secrets)


def test_docs_removal_has_nothing_to_review() -> None:
    """A pure deletion: §15's exit-0 path, on a real PR."""
    diff = load("docs_removal.diff")

    assert diff.has_reviewable_changes is False
    assert filter_files(diff).reviewable == []
    assert {reason for _, reason in filter_files(diff).excluded} == {"no added lines"}


def test_redirect_history_does_not_trip_the_redirect_rule() -> None:
    """Real redirect-handling code that the `unsafe_redirects` rule must stay quiet on."""
    found = deterministic(load("redirect_history.diff"))
    assert [f for f in found if f.category == "unsafe_redirects"] == []


def test_debugger_pin_fix_stays_quiet_on_real_auth_code() -> None:
    """An entire PR about PIN authentication, with no deterministic hit.

    Worth asserting because the `auth_perms` rule scans removed lines for auth-shaped
    tokens, and this is exactly the diff where an over-broad version of it would fire.
    """
    found = deterministic(load("debugger_pin_fix.diff"))
    assert found == []
