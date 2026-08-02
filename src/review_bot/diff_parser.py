"""Unified-diff parsing (pipeline stage 1, SPEC.md §4).

Wraps `unidiff` and re-exposes it as plain dataclasses; every later stage reads this
structure and nothing reaches back into `unidiff` itself. Two guarantees it exists to
provide: `ParsedFile.added_line_numbers` is the authoritative set `schema.py` validates LLM
findings against (§11), and `DiffLine.content` is mutable so `secret_masker` can substitute
in place without disturbing line numbers (§5).

File order is left exactly as the diff gave it — lexicographic sorting is `prompt_builder`'s
job, done at packing time for byte-stability (§7).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

LineKind = Literal["added", "removed", "context"]


class DiffParseError(Exception):
    """The input could not be read as a unified diff. `cli.py` maps this to exit 1 (§15)."""


@dataclass
class DiffLine:
    """One line inside a hunk.

    `content` carries no `+`/`-`/space prefix and no trailing newline. It is mutable
    because `secret_masker` rewrites it in place.
    """

    kind: LineKind
    content: str
    line_no: int | None
    """Post-file (target) line number. Set for added and context lines, `None` for removed."""
    source_line_no: int | None
    """Pre-file (source) line number. Set for removed and context lines, `None` for added."""

    @property
    def is_added(self) -> bool:
        return self.kind == "added"

    @property
    def is_removed(self) -> bool:
        return self.kind == "removed"

    @property
    def is_context(self) -> bool:
        return self.kind == "context"


@dataclass
class Hunk:
    """One `@@` block."""

    source_start: int
    source_length: int
    target_start: int
    target_length: int
    section_header: str
    lines: list[DiffLine] = field(default_factory=list)

    @property
    def added_lines(self) -> list[DiffLine]:
        return [ln for ln in self.lines if ln.is_added]

    @property
    def removed_lines(self) -> list[DiffLine]:
        return [ln for ln in self.lines if ln.is_removed]


@dataclass
class ParsedFile:
    """One file's worth of changes.

    `path` is the post-image path, except for a deletion, where the pre-image path is
    the only one there is.
    """

    path: str
    source_path: str
    target_path: str
    is_binary: bool = False
    is_added_file: bool = False
    is_removed_file: bool = False
    is_rename: bool = False
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def added_lines(self) -> list[DiffLine]:
        return [ln for hunk in self.hunks for ln in hunk.added_lines]

    @property
    def removed_lines(self) -> list[DiffLine]:
        """Removed lines, in diff order. The `auth_perms` rule scans these (§6, Tier 2)."""
        return [ln for hunk in self.hunks for ln in hunk.removed_lines]

    @property
    def added_line_numbers(self) -> frozenset[int]:
        """Post-file line numbers of added lines.

        The authoritative set `schema.py` validates LLM findings against (§11).
        """
        return frozenset(ln.line_no for ln in self.added_lines if ln.line_no is not None)

    @property
    def has_added_lines(self) -> bool:
        """False for pure deletions, renames, mode changes, and binaries — all filtered (§7)."""
        return any(hunk.added_lines for hunk in self.hunks)


@dataclass
class ParsedDiff:
    """The whole diff. Files appear in the order the diff listed them."""

    files: list[ParsedFile] = field(default_factory=list)

    def __iter__(self):
        return iter(self.files)

    def __len__(self) -> int:
        return len(self.files)

    @property
    def has_reviewable_changes(self) -> bool:
        """False means exit 0 without calling the API — never pay for an empty diff (§15)."""
        return any(f.has_added_lines for f in self.files)

    def file(self, path: str) -> ParsedFile | None:
        """The file at `path`, or None if the diff never touched it (a hallucinated file, §11)."""
        for f in self.files:
            if f.path == path:
                return f
        return None

    def added_line_numbers(self, path: str) -> frozenset[int]:
        """Added-line numbers for `path`; empty if the diff does not contain that file."""
        f = self.file(path)
        return f.added_line_numbers if f is not None else frozenset()


def parse_diff(text: str) -> ParsedDiff:
    """Parse unified-diff text.

    Raises `DiffParseError` when the text is not a diff. Whitespace-only input is not an
    error — it is an empty diff, which §15 treats as a successful run with nothing to
    review.
    """
    try:
        patch_set = PatchSet.from_string(text)
    except UnidiffParseError as exc:
        raise DiffParseError(str(exc)) from exc

    if not patch_set and text.strip():
        # unidiff returns an empty PatchSet for arbitrary non-diff text rather than
        # raising. Reporting "no reviewable changes" there would silently swallow a
        # wrong file or a broken pipe, so treat it as a parse failure instead.
        raise DiffParseError("no file sections found; input does not look like a unified diff")

    return ParsedDiff(files=[_parse_file(pf) for pf in patch_set])


def _parse_file(patched_file) -> ParsedFile:
    return ParsedFile(
        path=patched_file.path,
        source_path=_strip_prefix(patched_file.source_file),
        target_path=_strip_prefix(patched_file.target_file),
        is_binary=patched_file.is_binary_file,
        is_added_file=patched_file.is_added_file,
        is_removed_file=patched_file.is_removed_file,
        is_rename=patched_file.is_rename,
        hunks=[_parse_hunk(h) for h in patched_file],
    )


def _parse_hunk(hunk) -> Hunk:
    return Hunk(
        source_start=hunk.source_start,
        source_length=hunk.source_length,
        target_start=hunk.target_start,
        target_length=hunk.target_length,
        section_header=hunk.section_header or "",
        lines=[_parse_line(ln) for ln in hunk],
    )


def _parse_line(line) -> DiffLine:
    if line.is_added:
        kind: LineKind = "added"
    elif line.is_removed:
        kind = "removed"
    else:
        kind = "context"
    return DiffLine(
        kind=kind,
        content=line.value.rstrip("\n").rstrip("\r"),
        line_no=line.target_line_no,
        source_line_no=line.source_line_no,
    )


def _strip_prefix(path: str) -> str:
    """Drop git's `a/` / `b/` prefix, leaving `/dev/null` alone."""
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path
