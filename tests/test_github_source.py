"""GitHub pull-request input (SPEC.md §23).

Never touches the network (§17). `github_source._run_gh` is the module's only process
boundary by design, so every test here mocks exactly that one function — which is the
property that boundary exists to provide, and is asserted directly in
`test_run_gh_is_the_only_subprocess_call`.

The cases worth having are the parsing edges (a diff path must never be mistaken for a pull
request) and the failure messages (every one of them is a local setup problem, so a message
that does not name the fix is a bug).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from review_bot import github_source as gh
from review_bot.github_source import (
    GitHubError,
    PullRequestInfo,
    PullRequestRef,
    fetch_pr_diff,
    fetch_pr_info,
    looks_like_pr_ref,
    parse_pr_ref,
)

DIFF = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1,2 @@\n x\n+y\n"


@pytest.fixture
def fake_gh(monkeypatch):
    """Replace the one subprocess boundary. Returns the recorded argv list."""
    calls: list[list[str]] = []

    def install(*, stdout: str = "", error: Exception | None = None):
        def _run(args, ref, *, timeout):
            calls.append(args)
            if error is not None:
                raise error
            return stdout

        monkeypatch.setattr(gh, "_run_gh", _run)
        return calls

    return install


# --------------------------------------------------------------------------------------
# Reference parsing
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("https://github.com/psf/requests/pull/7328", PullRequestRef(7328, "psf", "requests")),
        ("http://github.com/psf/requests/pull/7328", PullRequestRef(7328, "psf", "requests")),
        # The shapes a browser actually leaves on the clipboard.
        (
            "https://github.com/psf/requests/pull/7328/files",
            PullRequestRef(7328, "psf", "requests"),
        ),
        (
            "https://github.com/psf/requests/pull/7328#issuecomment-1",
            PullRequestRef(7328, "psf", "requests"),
        ),
        ("psf/requests#7328", PullRequestRef(7328, "psf", "requests")),
        ("psf/requests/pull/7328", PullRequestRef(7328, "psf", "requests")),
        ("psf/requests.git#7328", PullRequestRef(7328, "psf", "requests")),
        ("  psf/requests#7328  ", PullRequestRef(7328, "psf", "requests")),
        # Enterprise hosts are not this module's business to reject — `gh` decides that.
        ("https://git.corp.example/team/app/pull/42", PullRequestRef(42, "team", "app")),
    ],
)
def test_qualified_references_parse(text, expected) -> None:
    assert parse_pr_ref(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "sample_diffs/auth_bypass.diff",
        "real_diffs/dependency_bump.diff",
        "-",
        "/tmp/x.diff",
        "./auth_bypass.diff",
        "",
        "not a ref",
        "psf/requests",
        "https://github.com/psf/requests",
        "https://github.com/psf/requests/issues/7328",
    ],
)
def test_diff_paths_are_never_mistaken_for_pull_requests(text) -> None:
    """The positional slot holds both, so a false positive here reads a PR instead of a file."""
    assert parse_pr_ref(text) is None
    assert looks_like_pr_ref(text) is False


@pytest.mark.parametrize("text", ["123", "#123"])
def test_bare_numbers_need_allow_bare(text) -> None:
    """`123` is a valid filename, so it only means a pull request when `--pr` said so."""
    assert parse_pr_ref(text) is None
    assert parse_pr_ref(text, allow_bare=True) == PullRequestRef(123)


def test_bare_reference_has_no_slug() -> None:
    """No repository means `gh` resolves it from the working directory — `--repo` is omitted."""
    assert PullRequestRef(123).slug is None
    assert str(PullRequestRef(123)) == "#123"
    assert str(PullRequestRef(123, "psf", "requests")) == "psf/requests#123"


# --------------------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------------------


def test_fetch_pr_diff_asks_for_patch_format(fake_gh) -> None:
    """Without `--patch`, `gh` renders a colourised diff and the escapes reach the parser."""
    calls = fake_gh(stdout=DIFF)
    assert fetch_pr_diff(PullRequestRef(7328, "psf", "requests")) == DIFF
    assert calls == [["pr", "diff", "7328", "--patch"]]


def test_empty_diff_is_reported_as_such(fake_gh) -> None:
    """A PR with no file changes, blamed on the PR rather than on the parser."""
    fake_gh(stdout="   \n")
    with pytest.raises(GitHubError, match="empty diff"):
        fetch_pr_diff(PullRequestRef(1, "o", "r"))


def test_fetch_pr_info_parses_metadata(fake_gh) -> None:
    fake_gh(
        stdout='{"number": 7328, "title": "Fix redirects", "author": {"login": "nateprewitt"},'
        ' "baseRefName": "main", "headRefName": "fix", "url": "https://example/pr",'
        ' "additions": 12, "deletions": 3, "changedFiles": 2}'
    )
    info = fetch_pr_info(PullRequestRef(7328, "psf", "requests"))

    assert info.title == "Fix redirects"
    assert info.author == "nateprewitt"
    assert info.base == "main"
    assert info.label == "psf/requests#7328"


def test_fetch_pr_info_never_requests_the_pr_body(fake_gh) -> None:
    """§3: the PR body is attacker-controlled prose with no review value.

    Metadata is header decoration and never reaches a prompt. Keeping `body` out of the
    field list is what stops a later edit from making that untrue by accident.
    """
    calls = fake_gh(stdout="{}")
    fetch_pr_info(PullRequestRef(1, "o", "r"))
    assert "body" not in calls[0][-1]


@pytest.mark.parametrize(
    "failure",
    [
        GitHubError("boom"),
        ValueError("bad"),
    ],
)
def test_metadata_failure_never_fails_the_run(fake_gh, failure) -> None:
    """The diff already arrived; losing the title is not a reason to throw away a review."""
    fake_gh(error=failure)
    assert fetch_pr_info(PullRequestRef(1, "o", "r")) is None


def test_metadata_survives_a_response_missing_every_field(fake_gh) -> None:
    """A `gh` version that renames a field costs the header a line, never the review."""
    fake_gh(stdout="{}")
    info = fetch_pr_info(PullRequestRef(1, "o", "r"))
    assert info == PullRequestInfo(ref=PullRequestRef(1, "o", "r"))


def test_payload_tolerates_a_null_author() -> None:
    """`author` is null for a PR whose account was deleted."""
    info = PullRequestInfo.from_payload(PullRequestRef(1, "o", "r"), {"author": None})
    assert info.author == ""


# --------------------------------------------------------------------------------------
# The subprocess boundary
# --------------------------------------------------------------------------------------


def test_repo_is_passed_when_the_reference_names_one(monkeypatch) -> None:
    seen: list[list[str]] = []

    def _run(command, **kwargs):
        seen.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=DIFF, stderr="")

    monkeypatch.setattr(gh.shutil, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(gh.subprocess, "run", _run)

    fetch_pr_diff(PullRequestRef(7328, "psf", "requests"))
    assert seen[0] == ["gh", "pr", "diff", "7328", "--patch", "--repo", "psf/requests"]


def test_repo_is_omitted_for_a_bare_reference(monkeypatch) -> None:
    """`gh` resolves the repository from the working directory when we do not name one."""
    seen: list[list[str]] = []

    def _run(command, **kwargs):
        seen.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=DIFF, stderr="")

    monkeypatch.setattr(gh.shutil, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(gh.subprocess, "run", _run)

    fetch_pr_diff(PullRequestRef(123))
    assert "--repo" not in seen[0]


def test_missing_gh_names_the_binary_and_an_alternative(monkeypatch) -> None:
    monkeypatch.setattr(gh.shutil, "which", lambda _: None)
    with pytest.raises(GitHubError) as exc:
        fetch_pr_diff(PullRequestRef(1, "o", "r"))

    message = str(exc.value)
    assert "not installed" in message
    assert "cli.github.com" in message
    # §18 pipes a diff in CI, and a fork PR has no `gh` auth. The error should say so.
    assert "review-bot -" in message


def test_timeout_is_reported_rather_than_hanging(monkeypatch) -> None:
    monkeypatch.setattr(gh.shutil, "which", lambda _: "/usr/bin/gh")

    def _run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 30)

    monkeypatch.setattr(gh.subprocess, "run", _run)
    with pytest.raises(GitHubError, match="timed out"):
        fetch_pr_diff(PullRequestRef(1, "o", "r"))


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("gh: To get started with GitHub CLI, please run: gh auth login", "gh auth login"),
        ("Could not resolve to a PullRequest with the number of 99999.", "was not found"),
        ("failed to run git: fatal: not a git repository", "owner/repo#1"),
        ("some unmapped failure", "some unmapped failure"),
    ],
)
def test_failures_name_the_fix(monkeypatch, stderr, expected) -> None:
    """Every failure here is a local setup problem, so each message names its own remedy."""
    monkeypatch.setattr(gh.shutil, "which", lambda _: "/usr/bin/gh")
    monkeypatch.setattr(
        gh.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", stderr),
    )

    with pytest.raises(GitHubError) as exc:
        fetch_pr_diff(PullRequestRef(1, "owner", "repo"))
    assert expected in str(exc.value)


def test_run_gh_is_the_only_subprocess_call() -> None:
    """The seam the whole test file depends on: one `subprocess.run`, in one function.

    A second call site elsewhere in the module would be a code path these tests silently
    stop covering — and a network call that a mocked `_run_gh` no longer prevents (§17).
    """
    source = Path(gh.__file__).read_text()
    assert source.count("subprocess.run(") == 1
