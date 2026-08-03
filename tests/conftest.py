"""Shared test helpers.

Rule tests need a `ParsedDiff` around a handful of lines without hand-writing a hunk
header and counting it correctly every time, so these build the diff text and run it
through the real parser. Going through `parse_diff` rather than constructing dataclasses
directly keeps the tests honest about line numbering.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from review_bot.diff_parser import ParsedDiff, parse_diff

SAMPLE_DIFFS = Path(__file__).parent.parent / "sample_diffs"
REAL_DIFFS = Path(__file__).parent.parent / "real_diffs"
"""Real merged public PRs (§25). See `tests/test_real_diffs.py`."""
TEST_DIFFS = Path(__file__).parent / "diffs"
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_diffs() -> Path:
    return SAMPLE_DIFFS


@pytest.fixture
def fixtures_dir() -> Path:
    """Recorded LLM responses (§17). `--record` overwrites these from live calls."""
    return FIXTURES


def build_diff(
    path: str,
    added: list[str] | None = None,
    removed: list[str] | None = None,
    context: str = "# context",
) -> ParsedDiff:
    """A one-file, one-hunk diff whose added lines start at post-image line 2."""
    added = added or []
    removed = removed or []
    body = [f" {context}"]
    body += [f"-{line}" for line in removed]
    body += [f"+{line}" for line in added]
    body += [f" {context}"]

    source_len = 2 + len(removed)
    target_len = 2 + len(added)
    text = (
        f"diff --git a/{path} b/{path}\n"
        f"index 1111111..2222222 100644\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -1,{source_len} +1,{target_len} @@\n" + "\n".join(body) + "\n"
    )
    return parse_diff(text)


def added_line(diff: ParsedDiff, index: int = 0) -> str:
    return diff.files[0].added_lines[index].content


def load(name: str) -> ParsedDiff:
    """Parse a sample diff by filename."""
    return parse_diff((SAMPLE_DIFFS / name).read_text())
