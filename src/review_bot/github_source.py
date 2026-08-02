"""GitHub pull-request input (SPEC.md §14, §23).

Not a pipeline stage. This is an *input adapter* that sits in front of stage 1: it turns a
pull-request reference into the same unified-diff text a file or stdin would have supplied,
and hands it to `diff_parser` unchanged. Nothing downstream knows or cares where the bytes
came from, which is the property that keeps `--pr` from being a second pipeline.

The whole module is a wrapper around the `gh` CLI, and deliberately a thin one. `gh` already
owns credential storage, token refresh, enterprise hosts, and SSO — reimplementing any of
that against `api.github.com` would be a worse copy of a solved problem. §14's "no git
invocation" rule is about *reconstructing a diff from a local repository*, which is the
thing that would force every test to build real commits; fetching a diff the server already
computed does not (see §23 for the amendment).

`_run_gh` is the single process boundary in the module. Every other function is pure string
handling, so the tests mock exactly one thing and the network stays out of the suite (§17).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass

#: How long any one `gh` invocation may take. A PR diff is one HTTP request behind the CLI;
#: anything past this is a hung network, not a slow one, and a CLI that never returns is
#: worse than one that fails.
DEFAULT_TIMEOUT = 30

#: The metadata fields `gh pr view` is asked for. Kept narrow on purpose: this is header
#: decoration (§13), not input to the review, and it never reaches a prompt. Requesting the
#: PR *body* would put attacker-controlled prose one careless edit away from the model, for
#: no benefit the diff does not already carry (§3).
_INFO_FIELDS = "number,title,author,baseRefName,headRefName,url,additions,deletions,changedFiles"


class GitHubError(Exception):
    """A pull request could not be fetched. `cli.py` maps this to exit 1, like a bad diff.

    The message is written to be actionable at the terminal — which binary is missing, which
    command authenticates — because every failure here is a local setup problem the reviewer
    can fix, not a bug in the review.
    """


# --------------------------------------------------------------------------------------
# Reference parsing
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PullRequestRef:
    """A pull request, possibly without its repository.

    `owner`/`repo` are None for a bare `#123`, which means "this repository" — `gh` resolves
    that from the working directory's remotes, and letting it do so is why the bare form is
    worth supporting at all.
    """

    number: int
    owner: str | None = None
    repo: str | None = None

    @property
    def slug(self) -> str | None:
        """`owner/repo`, or None when the reference did not name one."""
        if self.owner and self.repo:
            return f"{self.owner}/{self.repo}"
        return None

    def __str__(self) -> str:
        return f"{self.slug or ''}#{self.number}"


#: `https://github.com/owner/repo/pull/123`, with any trailing `/files`, `#discussion`, or
#: query string. Host is matched loosely so GitHub Enterprise URLs work — `gh` is the thing
#: that decides whether a host is reachable, and hardcoding `github.com` here would reject
#: an enterprise URL this module has no business having an opinion about.
_URL = re.compile(
    r"^https?://[^/]+/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/pull/(?P<number>\d+)(?:[/?#].*)?$"
)

#: `owner/repo#123` and `owner/repo/pull/123`.
_SLUG_HASH = re.compile(r"^(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)#(?P<number>\d+)$")
_SLUG_PATH = re.compile(r"^(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)/pull/(?P<number>\d+)$")

#: `#123` or `123`. Only accepted under `allow_bare` — see `parse_pr_ref`.
_BARE = re.compile(r"^#?(?P<number>\d+)$")

_QUALIFIED = (_URL, _SLUG_HASH, _SLUG_PATH)


def parse_pr_ref(text: str, *, allow_bare: bool = False) -> PullRequestRef | None:
    """Parse a pull-request reference, or return None if `text` is not one.

    Returning None rather than raising is what lets the positional argument accept a diff
    path and a PR URL in the same slot: `cli.py` asks "is this a PR?" and falls through to
    reading a file when the answer is no.

    `allow_bare` is off by default, and that asymmetry is the point. `#123` and `123` are
    only unambiguous when the user has said "this is a pull request" by using `--pr`; as a
    positional they collide with a file that happens to be named `123`. The qualified forms
    cannot collide with a real path, so they are accepted anywhere.
    """
    text = text.strip()
    for pattern in _QUALIFIED:
        if match := pattern.match(text):
            return PullRequestRef(
                number=int(match["number"]),
                owner=match["owner"],
                # `owner/repo.git#1` is a plausible paste; `.git` is not part of the name.
                repo=match["repo"].removesuffix(".git"),
            )

    if allow_bare and (match := _BARE.match(text)):
        return PullRequestRef(number=int(match["number"]))
    return None


def looks_like_pr_ref(text: str) -> bool:
    """True for the qualified forms only. Used to disambiguate the positional argument."""
    return parse_pr_ref(text) is not None


# --------------------------------------------------------------------------------------
# Metadata
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PullRequestInfo:
    """Header decoration for a `--pr` run (§13). Never reaches a prompt."""

    ref: PullRequestRef
    title: str = ""
    author: str = ""
    base: str = ""
    head: str = ""
    url: str = ""
    additions: int = 0
    deletions: int = 0
    changed_files: int = 0

    @property
    def label(self) -> str:
        """`owner/repo#123`, falling back to `#123` when the repo was never named."""
        return str(self.ref)

    @classmethod
    def from_payload(cls, ref: PullRequestRef, payload: dict) -> PullRequestInfo:
        """Build from `gh pr view --json`, tolerating every field being absent.

        Defensive because this is decoration: a `gh` version that renames a field should
        cost the header a line, never the review.
        """
        author = payload.get("author") or {}
        return cls(
            ref=ref,
            title=str(payload.get("title") or ""),
            author=str(author.get("login") or "") if isinstance(author, dict) else "",
            base=str(payload.get("baseRefName") or ""),
            head=str(payload.get("headRefName") or ""),
            url=str(payload.get("url") or ""),
            additions=int(payload.get("additions") or 0),
            deletions=int(payload.get("deletions") or 0),
            changed_files=int(payload.get("changedFiles") or 0),
        )


# --------------------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------------------


def fetch_pr_diff(ref: PullRequestRef, *, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Fetch the unified diff for `ref`.

    `--patch` asks for the same `.diff`-shaped text `git diff` produces, which is what
    `diff_parser` already parses. Without it `gh` renders a colourised diff for a human,
    and the escape sequences would reach `unidiff` as content.
    """
    diff = _run_gh(["pr", "diff", str(ref.number), "--patch"], ref, timeout=timeout)
    if not diff.strip():
        # A real PR with no file changes. Reported here rather than left to the parser,
        # which would call it a malformed diff and blame the wrong thing.
        raise GitHubError(f"{ref} returned an empty diff (no file changes)")
    return diff


def fetch_pr_info(ref: PullRequestRef, *, timeout: int = DEFAULT_TIMEOUT) -> PullRequestInfo | None:
    """Fetch PR metadata for the report header, or None if it cannot be had.

    Best-effort by design: this is the one call whose failure must not fail the run. The
    diff already arrived, the review is the deliverable, and losing the title is not a
    reason to throw it away.
    """
    try:
        raw = _run_gh(
            ["pr", "view", str(ref.number), "--json", _INFO_FIELDS], ref, timeout=timeout
        )
        return PullRequestInfo.from_payload(ref, json.loads(raw))
    except (GitHubError, json.JSONDecodeError, TypeError, ValueError):
        return None


def _run_gh(args: list[str], ref: PullRequestRef, *, timeout: int) -> str:
    """Run `gh` and return stdout. The only process boundary in the module.

    `--repo` is appended rather than baked into `args` so the bare-`#123` case simply omits
    it and lets `gh` resolve the repository from the working directory.
    """
    command = ["gh", *args]
    if slug := ref.slug:
        command += ["--repo", slug]

    if shutil.which("gh") is None:
        raise GitHubError(
            "the GitHub CLI (`gh`) is not installed, and --pr needs it to fetch the diff. "
            "Install it from https://cli.github.com, or pipe a diff instead: "
            "`git diff origin/main...HEAD | review-bot -`"
        )

    try:
        # Fixed argv, never a shell string: `ref` reaches this as an int and two regex-
        # matched name components, so a crafted PR reference cannot become a command.
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitHubError(f"`gh` timed out after {timeout}s fetching {ref}") from exc
    except OSError as exc:  # pragma: no cover - `which` above catches the common case
        raise GitHubError(f"could not run `gh`: {exc}") from exc

    if completed.returncode != 0:
        raise GitHubError(_explain_failure(completed.stderr, ref))
    return completed.stdout


def _explain_failure(stderr: str, ref: PullRequestRef) -> str:
    """Turn a `gh` error into one the reviewer can act on.

    Three failures make up almost all of them, and each has a different fix. `gh`'s own
    message is appended rather than replaced, because the fourth case always exists.
    """
    detail = " ".join(stderr.split()) or "no error output"
    lowered = detail.lower()

    if "gh auth login" in lowered or "authentication" in lowered or "not logged" in lowered:
        return f"`gh` is not authenticated. Run `gh auth login`, then retry. ({detail})"
    if "could not resolve to a pullrequest" in lowered or "no pull requests found" in lowered:
        return f"pull request {ref} was not found. Check the number and the repository. ({detail})"
    if "not a git repository" in lowered or "no git remotes" in lowered:
        return (
            f"{ref} omits the repository and the working directory is not a GitHub checkout. "
            f"Use the `owner/repo#{ref.number}` form instead. ({detail})"
        )
    return f"`gh` failed to fetch {ref}: {detail}"
