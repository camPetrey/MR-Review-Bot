"""Masking tests (SPEC.md §5, §17).

The load-bearing assertion in this file is `test_no_raw_secret_survives_masking`: the
definition of done requires that raw values never appear in output, and that is asserted
here rather than trusted.
"""

from __future__ import annotations

import pytest
from conftest import build_diff, load

from review_bot.secret_masker import mask_diff, path_signal

# (label, snippet, expected placeholder, the raw value that must not survive)
SECRET_CASES = [
    (
        "aws_key",
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        "[MASKED_AWS_KEY]",
        "AKIAIOSFODNN7EXAMPLE",
    ),
    (
        "private_key",
        "KEY = \"-----BEGIN RSA PRIVATE KEY-----\"",
        "[MASKED_PRIVATE_KEY]",
        "BEGIN RSA PRIVATE KEY",
    ),
    (
        "db_url",
        'DATABASE_URL = "postgres://admin:hunter2@db.prod.example.com:5432/app"',
        "[MASKED_DB_URL]",
        "hunter2",
    ),
    (
        "github_token",
        'GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"',
        "[MASKED_TOKEN]",
        "16C7e42F292c6912E7710c838347Ae178B4a",
    ),
    # Deliberately not a live-prefixed vendor key. A realistic `sk_live_...` literal is
    # blocked by GitHub push protection even as a test fixture, and a fixture that cannot
    # be committed is worse than one that exercises the generic keyword path instead.
    (
        "generic_api_key",
        'api_key = "V2hhdGV2ZXJTZWNyZXRWYWx1ZUhlcmU5OTk4"',
        "[MASKED_KEY]",
        "V2hhdGV2ZXJTZWNyZXRWYWx1ZUhlcmU5OTk4",
    ),
    (
        "jwt",
        'auth = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.9d8fXQ"',
        "[MASKED_TOKEN]",
        "eyJzdWIiOiIxIn0",
    ),
]


@pytest.mark.parametrize(("label", "snippet", "placeholder", "raw"), SECRET_CASES)
def test_typed_placeholder_substituted(
    label: str, snippet: str, placeholder: str, raw: str
) -> None:
    diff = build_diff("src/app/config.py", added=[snippet])
    result = mask_diff(diff)

    content = diff.files[0].added_lines[0].content
    assert placeholder in content, f"{label}: expected {placeholder} in {content!r}"
    assert len(result.findings) == 1
    assert result.findings[0].category == "hardcoded_secrets"


@pytest.mark.parametrize(("label", "snippet", "placeholder", "raw"), SECRET_CASES)
def test_no_raw_secret_survives_masking(
    label: str, snippet: str, placeholder: str, raw: str
) -> None:
    """Definition of done: raw values never appear downstream of this stage.

    This catches the truncating detectors — `GitHubTokenDetector` reports only `ghp`, so
    substituting the reported value alone would leave the rest of the token in place.
    """
    diff = build_diff("src/app/config.py", added=[snippet])
    result = mask_diff(diff)

    content = diff.files[0].added_lines[0].content
    assert raw not in content, f"{label}: raw value survived in {content!r}"
    for finding in result.findings:
        assert raw not in finding.evidence
        assert raw not in finding.risk
        assert raw not in finding.recommendation


def test_line_numbers_and_alignment_preserved() -> None:
    """Substitution is in-place: masking must not move any line (§5)."""
    diff = build_diff(
        "src/app/config.py",
        added=["A = 1", 'KEY = "AKIAIOSFODNN7EXAMPLE"', "B = 2"],
    )
    before = [ln.line_no for ln in diff.files[0].added_lines]
    added_before = diff.files[0].added_line_numbers

    mask_diff(diff)

    assert [ln.line_no for ln in diff.files[0].added_lines] == before
    assert diff.files[0].added_line_numbers == added_before
    assert diff.files[0].added_lines[0].content == "A = 1"
    assert diff.files[0].added_lines[2].content == "B = 2"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/app/config.py", "src"),
        ("app/main.py", "src"),
        ("tests/test_login.py", "test"),
        ("test_login.py", "test"),
        ("conftest.py", "test"),
        ("tests/fixtures/creds.py", "test"),
        ("app/users_test.go", "test"),
    ],
)
def test_path_signal(path: str, expected: str) -> None:
    assert path_signal(path) == expected


def test_severity_follows_path_signal() -> None:
    """§5: high for src paths, low for test paths."""
    src = mask_diff(build_diff("src/app/config.py", added=['KEY = "AKIAIOSFODNN7EXAMPLE"']))
    test = mask_diff(build_diff("tests/test_config.py", added=['KEY = "AKIAIOSFODNN7EXAMPLE"']))

    assert src.findings[0].severity == "high"
    assert test.findings[0].severity == "low"


def test_recommendation_always_mentions_rotation() -> None:
    """§5: the tool cannot verify whether the credential is live, so it always says rotate."""
    result = mask_diff(build_diff("src/app/config.py", added=['KEY = "AKIAIOSFODNN7EXAMPLE"']))
    assert "rotate" in result.findings[0].recommendation.lower()


def test_removed_line_secret_is_masked_but_not_reported() -> None:
    """A secret on a removed line was already in the repo, so this PR did not introduce it
    and it earns no finding. It is still *masked*, because removed lines are quoted
    downstream — in the prompt and in `auth_perms` evidence — and invariant 7 has no
    added-lines-only qualifier."""
    diff = build_diff(
        "src/app/config.py",
        removed=['KEY = "AKIAIOSFODNN7EXAMPLE"'],
        added=["KEY = os.environ['K']"],
    )
    result = mask_diff(diff)

    assert result.findings == []
    removed = diff.files[0].removed_lines[0].content
    assert "AKIAIOSFODNN7EXAMPLE" not in removed
    assert "[MASKED_" in removed


def test_clean_but_suspicious_produces_no_secret_findings() -> None:
    """The canary: `scan_line`'s eager entropy search would flag SELECT/FROM/users here."""
    result = mask_diff(load("clean_but_suspicious.diff"))
    assert result.findings == [], [(f.file, f.line, f.evidence) for f in result.findings]


def test_secrets_and_logging_sample() -> None:
    """§16: 2 hardcoded_secrets, severity high (src) and low (test)."""
    diff = load("secrets_and_logging.diff")
    result = mask_diff(diff)

    assert len(result.findings) == 2
    by_file = {f.file: f for f in result.findings}
    assert by_file["src/app/config.py"].severity == "high"
    assert by_file["tests/test_login.py"].severity == "low"

    for raw in ("AKIAIOSFODNN7EXAMPLE", "hunter2-not-real"):
        for parsed_file in diff.files:
            for line in parsed_file.added_lines:
                assert raw not in line.content


def test_binary_files_are_skipped() -> None:
    from conftest import TEST_DIFFS

    from review_bot.diff_parser import parse_diff

    diff = parse_diff((TEST_DIFFS / "binary_file.diff").read_text())
    result = mask_diff(diff)
    assert result.findings == []


# ------------------------------------------------------------------------------------
# Cost of the stage
# ------------------------------------------------------------------------------------


def test_plugin_settings_are_configured_once_per_diff(monkeypatch) -> None:
    """Entering `transient_settings` rebuilds every plugin and busts detect-secrets'
    caches, which profiles at roughly half of this stage. It is therefore entered once per
    diff, not once per file.

    Asserted structurally rather than by wall clock: a timing threshold on a shared CI
    runner is a flaky test, while the call count is exactly the property that was fixed.
    """
    from review_bot import secret_masker

    calls = 0
    original = secret_masker.transient_settings

    def counting(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(secret_masker, "transient_settings", counting)

    diff = _multi_file_diff(6)
    result = mask_diff(diff)

    assert len(result.findings) == 6, "every file is still scanned"
    assert calls == 1, f"configured {calls} times for a 6-file diff; expected once"


def test_same_basename_in_two_directories_is_scanned_separately() -> None:
    """The shared temp directory nests by path digest, so these cannot overwrite each
    other's scan input."""
    diff = _multi_file_diff(2, paths=["src/a/config.py", "src/b/config.py"])
    result = mask_diff(diff)

    assert {f.file for f in result.findings} == {"src/a/config.py", "src/b/config.py"}


def _multi_file_diff(count: int, paths: list[str] | None = None):
    """A diff with `count` distinct files, each carrying one AWS key."""
    from review_bot.diff_parser import parse_diff

    paths = paths or [f"src/app/mod{i}.py" for i in range(count)]
    chunks = []
    for path in paths:
        chunks.append(
            f"diff --git a/{path} b/{path}\n"
            f"index 1111111..2222222 100644\n"
            f"--- a/{path}\n+++ b/{path}\n"
            f"@@ -1,1 +1,2 @@\n # context\n"
            f'+KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        )
    return parse_diff("".join(chunks))
