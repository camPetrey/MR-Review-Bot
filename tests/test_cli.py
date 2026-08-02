"""End-to-end pipeline and exit-code tests (SPEC.md §15, §17).

The LLM is always mocked — unit tests never touch the network (§17). What is exercised
here is the whole pipeline around it: parse, mask, scan, filter, pack, call, validate,
merge, emit, and the exit code that results.

The load-bearing cases are the failure ones. A run that succeeds is easy; the ones worth
asserting are the run that must still produce deterministic findings when the API is down
(invariant 3), and the run that must refuse to guess when the JSON is wrong (§15).
"""

from __future__ import annotations

import json

import pytest
from conftest import SAMPLE_DIFFS

from review_bot import cli
from review_bot.llm_client import REVIEW_MAX_TOKENS, LLMError, Usage

SAMPLES = ["auth_bypass", "injection_and_logging", "secrets_and_logging"]


@pytest.fixture
def fake_llm(monkeypatch):
    """Replace both calls with canned responses. Returns a recorder for the prompts sent."""
    sent: list[str] = []

    def install(review_response: object, summary_response: object) -> list[str]:
        def _review(self, prompt, *, label="review"):
            sent.append(prompt.user)
            if isinstance(review_response, Exception):
                raise review_response
            return review_response

        def _summarize(self, prompt, *, label="summary"):
            sent.append(prompt.user)
            if isinstance(summary_response, Exception):
                raise summary_response
            return summary_response

        monkeypatch.setattr(cli.LLMClient, "review", _review)
        monkeypatch.setattr(cli.LLMClient, "summarize", _summarize)
        return sent

    return install


def run(args: list[str], capsys) -> tuple[int, dict, str]:
    """Run the CLI and return `(exit code, parsed JSON output, stderr)`.

    Forces `--format json` unless the caller chose one. §14 defaults to Markdown for the
    human reading a PR, but the JSON is the source of truth (§10) and is what these
    assertions are about — going through the rendered Markdown would test the renderer's
    phrasing instead of the pipeline's behaviour. `test_renderer.py` covers the Markdown.

    `--dry-run` prints prompts rather than JSON, so a decode failure yields `{}` instead of
    erroring — tests that use it assert on the exit code and on what was sent.
    """
    if "--format" not in args:
        args = [*args, "--format", "json"]
    code = cli.main(args)
    captured = capsys.readouterr()
    try:
        payload = json.loads(captured.out[captured.out.index("{") :])
    except (ValueError, json.JSONDecodeError):
        payload = {}
    return code, payload, captured.err


def summary_json(risk: str = "high") -> str:
    return json.dumps(
        {"summary": "a summary", "overall_risk": risk, "pr_comment": "a comment"}
    )


def review_json(*findings: dict) -> str:
    return json.dumps({"findings": list(findings)})


# ------------------------------------------------------------------------------------
# Exit codes (§15)
# ------------------------------------------------------------------------------------


def test_unparseable_input_exits_1(capsys) -> None:
    code, _, err = run(["tests/diffs/not_a_diff.diff"], capsys)
    assert code == cli.EXIT_PARSE_ERROR
    assert "could not parse diff" in err


def test_non_utf8_diff_exits_1(capsys, tmp_path) -> None:
    """A diff file that is not UTF-8 is bad input (exit 1), not a traceback."""
    diff = tmp_path / "latin1.diff"
    diff.write_bytes("+password = 'caf\xe9'\n".encode("latin-1"))
    code, _, err = run([str(diff)], capsys)

    assert code == cli.EXIT_PARSE_ERROR
    assert "could not read diff" in err


def test_empty_diff_exits_0_without_calling_the_api(capsys, fake_llm) -> None:
    """§15 and invariant 6: never spend money on an empty diff."""
    sent = fake_llm(review_json(), summary_json())
    code, payload, err = run(["tests/diffs/empty.diff"], capsys)

    assert code == cli.EXIT_OK
    assert sent == [], "the API must not be called on a diff with nothing to review"
    assert payload["no_findings_reason"]
    assert "No reviewable changes." in err


def test_fully_filtered_diff_exits_0_without_calling_the_api(capsys, fake_llm, tmp_path) -> None:
    """A lockfile-only diff still produces its Tier 1 finding, and still makes no call."""
    diff = tmp_path / "lock.diff"
    diff.write_text(
        "diff --git a/package-lock.json b/package-lock.json\n"
        "--- a/package-lock.json\n+++ b/package-lock.json\n"
        '@@ -1,1 +1,2 @@\n {\n+  "lodash": "4.17.21"\n'
    )
    sent = fake_llm(review_json(), summary_json())
    code, payload, _ = run([str(diff)], capsys)

    assert code == cli.EXIT_OK
    assert sent == []
    assert [f["category"] for f in payload["findings"]] == ["dependency_change"]


def test_malformed_llm_json_prints_raw_and_exits_2(capsys, fake_llm) -> None:
    """§15: no auto-repair, no retry. The raw response is printed verbatim."""
    fake_llm("I think the code looks fine!", summary_json())
    code = cli.main([str(SAMPLE_DIFFS / "auth_bypass.diff")])
    captured = capsys.readouterr()

    assert code == cli.EXIT_MALFORMED_LLM_JSON
    assert "I think the code looks fine!" in captured.out


def test_budget_guard_exits_3(capsys) -> None:
    code, _, err = run([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--max-input-tokens", "10"], capsys)
    assert code == cli.EXIT_BUDGET
    assert "budget guard" in err


def test_fail_on_high_exits_4_only_when_set(capsys) -> None:
    """§15: the capability without the policy call. Findings alone are still exit 0."""
    path = str(SAMPLE_DIFFS / "auth_bypass.diff")

    default_code, payload, _ = run([path, "--no-llm"], capsys)
    assert default_code == cli.EXIT_OK
    assert any(f["severity"] == "high" for f in payload["findings"])

    gated_code, _, _ = run([path, "--no-llm", "--fail-on", "high"], capsys)
    assert gated_code == cli.EXIT_FAIL_ON


# ------------------------------------------------------------------------------------
# Invariant 3: deterministic findings never depend on a network call (§12)
# ------------------------------------------------------------------------------------


def test_api_failure_still_produces_deterministic_findings(capsys, fake_llm) -> None:
    fake_llm(LLMError("connection reset"), summary_json())
    code, payload, err = run([str(SAMPLE_DIFFS / "auth_bypass.diff")], capsys)

    assert code == cli.EXIT_OK, "an API failure is not a tool failure"
    assert len(payload["findings"]) == 2, "the deterministic auth_perms findings survive"
    assert "connection reset" in err, "the failure must be visible, not swallowed"


def test_summary_failure_still_emits_a_valid_review(capsys, fake_llm) -> None:
    fake_llm(review_json(), LLMError("overloaded"))
    code, payload, err = run([str(SAMPLE_DIFFS / "auth_bypass.diff")], capsys)

    assert code == cli.EXIT_OK
    assert payload["summary"] and payload["pr_comment"], "required fields are never empty (§10)"
    assert payload["overall_risk"] == "high", "falls back to the highest severity present"
    assert "overloaded" in err


def test_no_llm_skips_both_calls(capsys, fake_llm) -> None:
    sent = fake_llm(review_json(), summary_json())
    code, payload, _ = run([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--no-llm"], capsys)

    assert code == cli.EXIT_OK
    assert sent == []
    assert payload["findings"], "deterministic findings are produced without any call"


def test_dry_run_sends_nothing(capsys, fake_llm) -> None:
    sent = fake_llm(review_json(), summary_json())
    code, _, _ = run([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--dry-run"], capsys)
    assert code == cli.EXIT_OK
    assert sent == []


# ------------------------------------------------------------------------------------
# The whole pipeline, mocked (§17)
# ------------------------------------------------------------------------------------


@pytest.mark.parametrize("sample", SAMPLES)
def test_sample_diffs_run_end_to_end(capsys, fake_llm, sample: str) -> None:
    """M4 acceptance: three sample diffs end to end, `unmappable_count` at zero."""
    fake_llm(review_json(), summary_json("medium"))
    code, payload, err = run([str(SAMPLE_DIFFS / f"{sample}.diff")], capsys)

    assert code == cli.EXIT_OK
    assert payload["overall_risk"] == "medium", "the summary model sets overall_risk (§8)"
    assert "unmappable_count=0" in err
    assert "hallucinated_file_count=0" in err


def test_llm_finding_is_validated_merged_and_emitted(capsys, fake_llm) -> None:
    """A model finding on a real added line reaches the output, promoting the Tier 2 hit
    it agrees with to `high` confidence (§12.3)."""
    fake_llm(
        review_json(
            {
                "file": "src/app/db/users.py",
                "line": 8,
                "category": "injection",
                "severity": "high",
                "confidence": "high",
                "evidence": "f-string interpolated into execute()",
                "risk": "SQL injection if uid is user-controlled.",
                "recommendation": "Use a parameterised query.",
            }
        ),
        summary_json(),
    )
    _, payload, err = run([str(SAMPLE_DIFFS / "injection_and_logging.diff")], capsys)

    match = [f for f in payload["findings"] if f["file"] == "src/app/db/users.py"]
    assert len(match) == 1, "the two detectors agreeing is one finding, not two"
    assert match[0]["confidence"] == "high"
    assert match[0]["recommendation"] == "Use a parameterised query.", "LLM prose is kept (§12.4)"
    assert "unmappable_count=0" in err


def test_hallucinated_finding_is_dropped_and_counted(capsys, fake_llm) -> None:
    fake_llm(
        review_json(
            {
                "file": "src/app/does_not_exist.py",
                "line": 3,
                "category": "injection",
                "severity": "high",
                "confidence": "high",
                "evidence": "e",
                "risk": "r",
                "recommendation": "rec",
            }
        ),
        summary_json(),
    )
    _, payload, err = run([str(SAMPLE_DIFFS / "auth_bypass.diff")], capsys)

    assert all(f["file"] != "src/app/does_not_exist.py" for f in payload["findings"])
    assert "hallucinated_file_count=1" in err


def test_unmappable_line_degrades_and_is_counted(capsys, fake_llm) -> None:
    fake_llm(
        review_json(
            {
                "file": "src/app/urls.py",
                "line": 4242,
                "category": "auth_perms",
                "severity": "high",
                "confidence": "medium",
                "evidence": "e",
                "risk": "r",
                "recommendation": "rec",
            }
        ),
        summary_json(),
    )
    _, payload, err = run([str(SAMPLE_DIFFS / "auth_bypass.diff")], capsys)

    degraded = [f for f in payload["findings"] if f["file"] == "src/app/urls.py"]
    assert degraded and degraded[0]["line"] is None, "degrade to file-level, do not drop (§11)"
    assert "unmappable_count=1" in err


def test_no_line_number_renders_that_is_not_in_the_diff(capsys, fake_llm) -> None:
    """Invariant 2, stated as a property over every emitted finding.

    The set checked here is every post-image line the diff shows, not just the added ones.
    The two are not the same, and the difference is deliberate: §11's added-line rule
    governs *LLM* findings, because a model citing a line it did not see is a hallucination.
    A deterministic `auth_perms` finding is the other case — the evidence is a line that no
    longer exists, so `role_scanner` anchors it to the nearest surviving line, which is
    usually the context line the check used to guard. That is a real destination for the
    reviewer, and blanking it to `null` would lose the location of the removal.
    """
    from review_bot.diff_parser import parse_diff

    for sample in SAMPLES:
        fake_llm(review_json(), summary_json())
        _, payload, _ = run([str(SAMPLE_DIFFS / f"{sample}.diff")], capsys)
        diff = parse_diff((SAMPLE_DIFFS / f"{sample}.diff").read_text())

        visible = {
            f.path: {ln.line_no for h in f.hunks for ln in h.lines if ln.line_no is not None}
            for f in diff.files
        }
        for finding in payload["findings"]:
            assert finding["file"] in visible, "a file absent from the diff must never render"
            if finding["line"] is not None:
                assert finding["line"] in visible[finding["file"]], (
                    f"{finding['file']}:{finding['line']} is not a line this diff shows"
                )


def test_raw_secrets_never_appear_in_output(capsys, fake_llm) -> None:
    """Invariant 7 and the definition of done, asserted on the emitted JSON."""
    fake_llm(review_json(), summary_json())
    cli.main([str(SAMPLE_DIFFS / "secrets_and_logging.diff")])
    out = capsys.readouterr().out

    for raw in ("AKIAIOSFODNN7EXAMPLE", "hunter2-not-real"):
        assert raw not in out
    assert "[MASKED_" in out, "the placeholder is what renders instead (§13)"


def test_removed_line_secret_never_reaches_prompt_or_output(capsys, fake_llm, tmp_path) -> None:
    """Invariants 1 and 7 with no line-kind qualifier: a secret on a *removed* line is
    quoted verbatim by the `auth_perms` rule's evidence, which flows into both the summary
    prompt and the report — so the masker must have destroyed the value first."""
    diff = tmp_path / "removed_secret.diff"
    diff.write_text(
        "diff --git a/src/app/views.py b/src/app/views.py\n"
        "--- a/src/app/views.py\n+++ b/src/app/views.py\n"
        "@@ -1,2 +1,2 @@\n def handler(request):\n"
        '-    if request.user.is_admin and token == "ghp_16C7e42F292c6912E7710c838347Ae178B4a":\n'
        "+    pass\n"
    )
    sent = fake_llm(review_json(), summary_json())
    code, payload, _ = run([str(diff)], capsys)

    assert code == cli.EXIT_OK
    auth = [f for f in payload["findings"] if f["category"] == "auth_perms"]
    assert auth, "the removed is_admin check is still reported"
    for text in [json.dumps(payload), *sent]:
        assert "16C7e42F292c6912E7710c838347Ae178B4a" not in text


def test_masking_happens_before_the_prompt_is_built(capsys, fake_llm) -> None:
    """Invariant 1, asserted where it is enforceable: no raw diff content reaches the API."""
    sent = fake_llm(review_json(), summary_json())
    cli.main([str(SAMPLE_DIFFS / "secrets_and_logging.diff")])

    assert sent, "the review call should have been made"
    for prompt in sent:
        for raw in ("AKIAIOSFODNN7EXAMPLE", "hunter2-not-real"):
            assert raw not in prompt


def test_output_file_is_written(capsys, fake_llm, tmp_path) -> None:
    fake_llm(review_json(), summary_json())
    target = tmp_path / "review.json"
    code, _, _ = run([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--output", str(target)], capsys)

    assert code == cli.EXIT_OK
    assert json.loads(target.read_text())["findings"]


# ------------------------------------------------------------------------------------
# --format (§14)
# ------------------------------------------------------------------------------------


def test_markdown_is_the_default_format(capsys, fake_llm) -> None:
    """§14: the default reader is a human looking at a PR."""
    fake_llm(review_json(), summary_json())
    cli.main([str(SAMPLE_DIFFS / "auth_bypass.diff")])
    out = capsys.readouterr().out

    assert out.startswith("# Security review")
    assert "## `src/app/views/admin.py`" in out, "grouped under a file heading (§13)"


def test_format_both_writes_markdown_and_json_side_by_side(capsys, fake_llm, tmp_path) -> None:
    """CI uploads review.md and review.json as artifacts from one run (§18)."""
    fake_llm(review_json(), summary_json())
    target = tmp_path / "review.md"
    code = cli.main(
        [str(SAMPLE_DIFFS / "auth_bypass.diff"), "--format", "both", "--output", str(target)]
    )

    assert code == cli.EXIT_OK
    assert target.read_text().startswith("# Security review")
    assert json.loads((tmp_path / "review.json").read_text())["findings"]


def test_format_both_with_json_output_path_keeps_both_artifacts(fake_llm, tmp_path) -> None:
    """`--output report.json` with `--format both`: with_suffix would be a no-op there,
    and the JSON write would silently clobber the Markdown written a line earlier."""
    fake_llm(review_json(), summary_json())
    target = tmp_path / "review.json"
    code = cli.main(
        [str(SAMPLE_DIFFS / "auth_bypass.diff"), "--format", "both", "--output", str(target)]
    )

    assert code == cli.EXIT_OK
    assert target.read_text().startswith("# Security review"), "Markdown still goes to PATH"
    assert json.loads((tmp_path / "review.json.json").read_text())["findings"]


def test_format_both_to_stdout_emits_both(capsys, fake_llm) -> None:
    fake_llm(review_json(), summary_json())
    cli.main([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--format", "both"])
    out = capsys.readouterr().out

    assert "# Security review" in out
    assert json.loads(out[out.index("{") :])["findings"]


def test_markdown_and_json_report_the_same_findings(capsys, fake_llm) -> None:
    """The Markdown is a projection of the JSON, so nothing may be dropped in rendering."""
    fake_llm(review_json(), summary_json())
    cli.main([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--format", "both"])
    out = capsys.readouterr().out
    payload = json.loads(out[out.index("{") :])

    assert out.count("\n### ") == len(payload["findings"]), "every finding renders (§13)"


def test_empty_diff_still_renders_markdown(capsys, fake_llm) -> None:
    """The no-reviewable-changes path returns early, so it renders through its own branch."""
    fake_llm(review_json(), summary_json())
    code = cli.main(["tests/diffs/empty.diff"])
    out = capsys.readouterr().out

    assert code == cli.EXIT_OK
    assert "**No findings.**" in out


def test_verbose_reports_stage_timings(capsys, fake_llm) -> None:
    fake_llm(review_json(), summary_json())
    _, _, err = run([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--verbose"], capsys)

    assert "timings:" in err
    for stage in ("parse", "mask", "scan", "pack", "merge", "render", "total"):
        assert stage in err


def test_timings_are_not_reported_without_verbose(capsys, fake_llm) -> None:
    fake_llm(review_json(), summary_json())
    _, _, err = run([str(SAMPLE_DIFFS / "auth_bypass.diff")], capsys)
    assert "timings:" not in err


def test_output_is_stable_across_identical_runs(capsys, fake_llm) -> None:
    """The JSON is the source of truth; identical input must produce identical bytes."""
    outputs = []
    for _ in range(2):
        fake_llm(review_json(), summary_json())
        cli.main([str(SAMPLE_DIFFS / "auth_bypass.diff")])
        outputs.append(capsys.readouterr().out)
    assert outputs[0] == outputs[1]


# ------------------------------------------------------------------------------------
# --record (§14, §17)
# ------------------------------------------------------------------------------------


def test_record_writes_fixture_names_derived_from_the_diff(capsys, monkeypatch, tmp_path) -> None:
    """`make record` must overwrite the fixtures the contract test reads, not new files.

    This patches `_send` rather than using the `fake_llm` fixture, because recording is
    inside `LLMClient` and stubbing `review`/`summarize` would skip the code under test.
    The bug this catches is silent: labels not keyed to the diff wrote `review-0.json` and
    `summary.json` while `tests/fixtures/` kept validating the stale originals.
    """
    def fake_send(self, prompt, *, model, max_tokens, effort):
        return (review_json() if max_tokens == REVIEW_MAX_TOKENS else summary_json(), Usage())

    monkeypatch.setattr(cli.LLMClient, "_send", fake_send)
    run([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--record", str(tmp_path)], capsys)

    assert sorted(p.name for p in tmp_path.glob("*.json")) == [
        "review-auth_bypass.json",
        "summary-auth_bypass.json",
    ]


def test_record_stem_names_stdin_runs() -> None:
    """A piped diff has no filename; CI pipes `git diff` in, so it still needs a stem."""
    assert cli._record_stem("-") == "stdin"
    assert cli._record_stem("sample_diffs/auth_bypass.diff") == "auth_bypass"


# ------------------------------------------------------------------------------------
# GitHub pull-request input (§23)
# ------------------------------------------------------------------------------------


@pytest.fixture
def fake_pr(monkeypatch):
    """Stub the GitHub fetch. `github_source` has its own tests; this is the CLI wiring."""
    def install(diff_text: str, *, error: Exception | None = None):
        fetched: list = []

        def _diff(ref, **kwargs):
            fetched.append(ref)
            if error is not None:
                raise error
            return diff_text

        monkeypatch.setattr(cli, "fetch_pr_diff", _diff)
        monkeypatch.setattr(
            cli,
            "fetch_pr_info",
            lambda ref, **kwargs: cli.PullRequestInfo(ref=ref, title="A real PR", author="octocat"),
        )
        return fetched

    return install


def test_pr_flag_reviews_the_fetched_diff(capsys, fake_llm, fake_pr) -> None:
    fake_llm(review_json(), summary_json())
    fetched = fake_pr((SAMPLE_DIFFS / "auth_bypass.diff").read_text())

    code, payload, _ = run(["--pr", "psf/requests#7328"], capsys)

    assert code == 0
    assert payload["findings"]
    assert (fetched[0].owner, fetched[0].repo, fetched[0].number) == ("psf", "requests", 7328)


def test_a_pr_url_works_as_the_positional_argument(capsys, fake_llm, fake_pr) -> None:
    """Pasting a PR URL is what someone actually does, so the positional accepts one."""
    fake_llm(review_json(), summary_json())
    fetched = fake_pr((SAMPLE_DIFFS / "auth_bypass.diff").read_text())

    code, _, _ = run(["https://github.com/psf/requests/pull/7328"], capsys)

    assert code == 0
    assert fetched[0].number == 7328


def test_an_existing_file_always_wins_over_a_pr_shaped_name(capsys, fake_llm, tmp_path) -> None:
    """A file that exists is read as a file, whatever its name looks like."""
    fake_llm(review_json(), summary_json())
    path = tmp_path / "owner-repo-1.diff"
    path.write_text((SAMPLE_DIFFS / "auth_bypass.diff").read_text())

    code, payload, _ = run([str(path)], capsys)
    assert code == 0
    assert payload["findings"]


def test_a_bare_number_is_not_a_pr_in_the_positional_slot(capsys) -> None:
    """`123` is a valid filename. Only `--pr` makes it unambiguous."""
    code, _, err = run(["123"], capsys)
    assert code == cli.EXIT_PARSE_ERROR
    assert "could not read diff" in err


def test_a_failed_fetch_exits_1_like_an_unreadable_diff(capsys, fake_pr) -> None:
    """§23: a PR that cannot be fetched is unusable input, not a tool failure."""
    fake_pr("", error=cli.GitHubError("`gh` is not authenticated. Run `gh auth login`"))

    code, _, err = run(["--pr", "psf/requests#7328"], capsys)

    assert code == cli.EXIT_PARSE_ERROR
    assert "gh auth login" in err


def test_pr_and_a_diff_path_together_are_rejected(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--pr", "o/r#1"])


def test_no_input_at_all_is_rejected(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main([])


def test_a_malformed_pr_reference_is_rejected(capsys) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--pr", "not-a-pull-request"])


def test_pr_runs_record_to_a_filename_derived_from_the_pr(
    capsys, monkeypatch, fake_pr, tmp_path
) -> None:
    """`owner/repo#123` contains `/` and `#`; neither belongs in a fixture filename."""
    def fake_send(self, prompt, *, model, max_tokens, effort):
        return (review_json() if max_tokens == REVIEW_MAX_TOKENS else summary_json(), Usage())

    monkeypatch.setattr(cli.LLMClient, "_send", fake_send)
    fake_pr((SAMPLE_DIFFS / "auth_bypass.diff").read_text())
    run(["--pr", "psf/requests#7328", "--record", str(tmp_path)], capsys)

    assert sorted(p.name for p in tmp_path.glob("*.json")) == [
        "review-pr-psf-requests-7328.json",
        "summary-pr-psf-requests-7328.json",
    ]


# ------------------------------------------------------------------------------------
# Output format (§24)
# ------------------------------------------------------------------------------------


def test_auto_format_is_markdown_when_stdout_is_not_a_terminal(capsys, fake_llm) -> None:
    """§18's workflows and every existing `>` and `| less` depend on this staying true."""
    fake_llm(review_json(), summary_json())
    code = cli.main([str(SAMPLE_DIFFS / "auth_bypass.diff")])
    out = capsys.readouterr().out

    assert code == 0
    assert out.startswith("# Security review")


def test_auto_format_is_terminal_when_stdout_is_a_terminal(capsys, fake_llm, monkeypatch) -> None:
    fake_llm(review_json(), summary_json())
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True, raising=False)

    cli.main([str(SAMPLE_DIFFS / "auth_bypass.diff")])
    out = capsys.readouterr().out

    assert "Security review" in out
    assert not out.startswith("# Security review"), "should be the styled report, not Markdown"


def test_terminal_format_writes_a_file_when_asked(capsys, fake_llm, tmp_path) -> None:
    fake_llm(review_json(), summary_json())
    out_path = tmp_path / "review.txt"
    cli.main(
        [str(SAMPLE_DIFFS / "auth_bypass.diff"), "--format", "terminal", "--output", str(out_path)]
    )

    written = out_path.read_text()
    assert "Security review" in written
    assert all(line == line.rstrip() for line in written.splitlines())


def test_terminal_format_never_leaks_a_raw_secret(capsys, fake_llm) -> None:
    """Invariant 7, through the styled renderer as well as the Markdown one."""
    fake_llm(review_json(), summary_json())
    cli.main([str(SAMPLE_DIFFS / "secrets_and_logging.diff"), "--format", "terminal"])
    out = capsys.readouterr().out

    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[MASKED_" in out


def test_verbose_diagnostics_precede_the_terminal_report(capsys, fake_llm) -> None:
    """stderr is flushed before stdout so counters do not interleave with the boxes.

    `_render` builds the terminal report and `_write` prints it, and this is the behaviour
    that split exists for — a regression would put `timings:` in the middle of a panel.
    """
    fake_llm(review_json(), summary_json())
    cli.main([str(SAMPLE_DIFFS / "auth_bypass.diff"), "--format", "terminal", "--verbose"])
    captured = capsys.readouterr()

    assert "render" in captured.err, "the render stage must still be timed"
    assert "Security review" in captured.out
