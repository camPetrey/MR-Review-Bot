"""Diff parsing (SPEC.md §17, M2 acceptance).

The assertion that carries the most weight here is added-line numbering. `added_line_numbers`
is the authoritative set `schema.py` validates every LLM finding against (§11), so an
off-by-one in this file does not surface as a parsing bug — it surfaces as the tool citing
a line that does not exist, which is the one thing §11 exists to prevent. Multi-hunk files
are where that goes wrong, so they are tested against hand-counted numbers rather than
against anything the parser computed.

The rest is graceful handling: binary, added, deleted, renamed, mode-change and empty
diffs all have to parse without raising, because a real PR contains them and a crash here
takes the whole review with it.
"""

from __future__ import annotations

import pytest
from conftest import TEST_DIFFS, build_diff

from review_bot.diff_parser import DiffParseError, parse_diff


def load(name: str):
    return parse_diff((TEST_DIFFS / name).read_text())


# ------------------------------------------------------------------------------------
# Added-line numbering (§11)
# ------------------------------------------------------------------------------------


def test_added_line_numbers_are_post_image_line_numbers() -> None:
    """`@@ -0,0 +1,4 @@` on a new file: the four added lines are 1-4."""
    diff = load("added_file.diff")
    assert diff.files[0].added_line_numbers == {1, 2, 3, 4}


def test_added_line_numbers_across_multiple_hunks() -> None:
    """Hand-counted from `multi_hunk.diff`, not derived from the parser.

    Hunk 1 `+1,3`:  1 context, then `+import json` at 2.
    Hunk 2 `+11,4`: 1 context at 11, then `+verbose` at 12.
    Hunk 3 `+32,5`: 1 context at 32, then `+pass`, `+`, `+# tail` at 33, 34, 35.
    """
    parsed = load("multi_hunk.diff").files[0]
    assert parsed.added_line_numbers == {2, 12, 33, 34, 35}
    assert [ln.content for ln in parsed.added_lines] == [
        "import json",
        "    verbose = False",
        "    pass",
        "",
        "# tail",
    ]


def test_every_added_line_has_a_target_number_and_no_source_number() -> None:
    """An added line does not exist in the pre-image, so `source_line_no` must be None."""
    for parsed_file in load("multi_file.diff").files:
        for line in parsed_file.added_lines:
            assert line.line_no is not None
            assert line.source_line_no is None


def test_removed_lines_have_a_source_number_and_no_target_number() -> None:
    for line in load("deleted_file.diff").files[0].removed_lines:
        assert line.source_line_no is not None
        assert line.line_no is None


def test_context_lines_carry_both_numbers() -> None:
    hunk = load("multi_file.diff").files[0].hunks[0]
    context = [ln for ln in hunk.lines if ln.is_context]
    assert context, "the fixture has context lines"
    for line in context:
        assert line.line_no is not None and line.source_line_no is not None


def test_line_numbers_are_contiguous_within_a_hunk() -> None:
    """Post-image numbering counts added and context lines and skips removed ones."""
    for hunk in load("multi_hunk.diff").files[0].hunks:
        numbered = [ln.line_no for ln in hunk.lines if ln.line_no is not None]
        assert numbered == list(range(hunk.target_start, hunk.target_start + len(numbered)))


def test_content_carries_no_diff_prefix_or_newline() -> None:
    for line in load("added_file.diff").files[0].added_lines:
        assert not line.content.startswith(("+", "-"))
        assert not line.content.endswith(("\n", "\r"))


# ------------------------------------------------------------------------------------
# Multiple files and hunks
# ------------------------------------------------------------------------------------


def test_multiple_files_are_parsed_independently() -> None:
    diff = load("multi_file.diff")
    assert [f.path for f in diff.files] == ["src/app/handlers.py", "src/app/utils.py"]
    assert len(diff) == 2


def test_multiple_hunks_are_preserved_per_file() -> None:
    assert len(load("multi_hunk.diff").files[0].hunks) == 3
    assert len(load("multi_file.diff").files[0].hunks) == 2


def test_file_order_follows_the_diff_not_sorted() -> None:
    """§4: sorting is `prompt_builder`'s job, done at packing time for byte-stability.

    `zzz.py` before `aaa.py` in the input has to stay that way here, so the sort that
    matters is unambiguously the one the packer applies.
    """
    text = "".join(
        f"diff --git a/{p} b/{p}\nindex 1111111..2222222 100644\n"
        f"--- a/{p}\n+++ b/{p}\n@@ -1,1 +1,2 @@\n x = 1\n+y = 2\n"
        for p in ("src/zzz.py", "src/aaa.py", "src/mmm.py")
    )
    assert [f.path for f in parse_diff(text).files] == ["src/zzz.py", "src/aaa.py", "src/mmm.py"]


def test_lookup_by_path() -> None:
    diff = load("multi_file.diff")
    assert diff.file("src/app/utils.py") is not None
    assert diff.file("src/app/nope.py") is None, "a file the diff never touched (§11)"
    assert diff.added_line_numbers("src/app/nope.py") == frozenset()


# ------------------------------------------------------------------------------------
# Graceful handling of the shapes a real PR contains
# ------------------------------------------------------------------------------------


def test_empty_diff_is_not_an_error() -> None:
    """§15: an empty diff is a successful run with nothing to review, not exit 1."""
    diff = load("empty.diff")
    assert len(diff) == 0
    assert diff.has_reviewable_changes is False


def test_whitespace_only_input_is_an_empty_diff() -> None:
    assert parse_diff("   \n\n  ").files == []


def test_binary_file_is_flagged_and_carries_no_added_lines() -> None:
    diff = load("binary_file.diff")
    binary = diff.file("assets/logo.png")

    assert binary is not None and binary.is_binary
    assert binary.added_lines == []
    assert binary.has_added_lines is False
    assert diff.file("src/app/theme.py").has_added_lines, "the text file beside it still parses"


def test_added_file_is_flagged() -> None:
    parsed = load("added_file.diff").files[0]
    assert parsed.is_added_file
    assert parsed.source_path == "/dev/null"
    assert parsed.path == "src/app/newmod.py"


def test_deleted_file_is_flagged_and_has_no_added_lines() -> None:
    """A pure deletion is filtered from LLM review (§7) but still scanned for `auth_perms`."""
    parsed = load("deleted_file.diff").files[0]

    assert parsed.is_removed_file
    assert parsed.has_added_lines is False
    assert [ln.content for ln in parsed.removed_lines][:2] == [
        "def check(user):",
        "    if user.is_admin:",
    ]


def test_renames_are_flagged_with_and_without_an_edit() -> None:
    """Both shapes appear in one diff, and they filter differently (§7).

    A pure rename has no added lines and is excluded from LLM review. A rename that also
    edits the file does have added lines, and the model must see them — dropping it because
    `is_rename` is True would silently skip real changed code.
    """
    diff = load("renamed.diff")
    assert [f.path for f in diff.files] == ["src/a/new_name.py", "docs/manual.md"]
    assert all(f.is_rename for f in diff.files)

    pure, edited = diff.files
    assert pure.source_path == "src/a/old_name.py"
    assert pure.has_added_lines is False

    assert edited.has_added_lines is True
    assert [ln.content for ln in edited.added_lines] == ["New text."]


def test_mode_change_parses_without_added_lines() -> None:
    diff = load("mode_change.diff")
    assert diff.has_reviewable_changes is False


def test_no_newline_at_eof_is_handled() -> None:
    """`\\ No newline at end of file` is a diff marker, not content."""
    parsed = load("no_newline_eof.diff").files[0]
    assert [ln.content for ln in parsed.added_lines] == ["gamma"]


# ------------------------------------------------------------------------------------
# Malformed input (§15: exit 1)
# ------------------------------------------------------------------------------------


def test_truncated_hunk_raises() -> None:
    """The header promises more lines than the hunk contains."""
    with pytest.raises(DiffParseError):
        load("malformed.diff")


def test_prose_is_rejected_rather_than_reported_as_empty() -> None:
    """unidiff returns an empty PatchSet for arbitrary text rather than raising. Treating
    that as "nothing to review" would silently swallow a wrong file or a broken pipe."""
    with pytest.raises(DiffParseError, match="does not look like a unified diff"):
        load("not_a_diff.diff")


def test_parse_error_message_is_preserved() -> None:
    with pytest.raises(DiffParseError) as exc:
        parse_diff("diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1,9 +1,9 @@\n x\n")
    assert str(exc.value), "the underlying reason reaches the user (§15)"


# ------------------------------------------------------------------------------------
# has_reviewable_changes drives the never-call-the-API guard (invariant 6)
# ------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["empty.diff", "deleted_file.diff", "mode_change.diff"])
def test_diffs_with_nothing_added_are_not_reviewable(name: str) -> None:
    assert load(name).has_reviewable_changes is False


@pytest.mark.parametrize(
    "name", ["added_file.diff", "multi_file.diff", "multi_hunk.diff", "renamed.diff"]
)
def test_diffs_with_added_lines_are_reviewable(name: str) -> None:
    assert load(name).has_reviewable_changes is True


# ------------------------------------------------------------------------------------
# Mutability, which `secret_masker` depends on (§5)
# ------------------------------------------------------------------------------------


def test_line_content_is_mutable_in_place() -> None:
    """Masking rewrites `content` and relies on line numbers surviving the substitution."""
    diff = build_diff("src/app/config.py", added=['KEY = "value"'])
    line = diff.files[0].added_lines[0]
    original_line_no = line.line_no

    line.content = 'KEY = "[MASKED_KEY]"'

    assert diff.files[0].added_lines[0].content == 'KEY = "[MASKED_KEY]"'
    assert diff.files[0].added_lines[0].line_no == original_line_no
    assert diff.files[0].added_line_numbers == {original_line_no}
