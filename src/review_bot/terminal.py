"""JSON to styled terminal output (SPEC.md §13, §24).

A *second* projection of the same `Review` that `renderer.py` projects to Markdown, and it
inherits that module's rule verbatim: it adds no judgment. It does not filter, cap, re-score,
or re-order anything `schema.py` settled, and `overall_risk` prints as given. Grouping and
sorting are imported from `renderer` rather than reimplemented — two projections that could
disagree about which finding comes first would mean neither is authoritative, which is the
exact failure §13 wrote that rule to prevent.

It also owns the **run diagnostics** at the bottom of this file — the `--verbose` counters,
call accounting, and stage timings that go to *stderr*. Those are not part of the `Review`
and are not a projection of it, but they are terminal presentation, and putting them here is
what lets them share `build_console`, the width cap, and the palette with the report they
print above. They follow §24's own rule one level down: styled when stderr is a terminal,
and the original plain `key=value` lines when it is a pipe, a file, or a CI log.

**Every string that came from the diff or the model is wrapped in `Text`.** This is a
correctness requirement, not a style one. Rich reads `[...]` in a plain string as markup, so
a `str` carrying `[MASKED_AWS_KEY]` renders as *nothing at all* — the placeholder is parsed
as a style tag and consumed. That would silently delete the one token proving invariant 7
held, turning a masked secret into a blank space in the report. `Text` disables that parse.
Asserted in `test_terminal.py::test_masked_placeholders_survive_rich_markup`.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass

from rich.box import HEAVY, ROUNDED
from rich.console import Console, ConsoleOptions, Group, RenderableType, RenderResult
from rich.padding import Padding
from rich.panel import Panel
from rich.segment import Segment
from rich.table import Table
from rich.text import Text

from .renderer import group_by_file, severity_counts
from .schema import Finding, Review

#: Wide terminals make long prose lines hard to track back to the next line's start. Capping
#: keeps the report readable on an ultrawide without shrinking it on an 80-column one.
MAX_WIDTH = 100

#: One colour per severity, used for the badge, the gutter bar, and the risk header, so the
#: same red always means the same thing wherever it appears.
_SEVERITY_STYLE = {"high": "red", "medium": "yellow", "low": "cyan"}

#: Abbreviated so every badge is the same width and the category column starts on one line.
_SEVERITY_LABEL = {"high": "HIGH", "medium": " MED", "low": " LOW"}

#: Confidence as a three-dot meter. Cheaper to scan down a column than the words are, and it
#: never collides with the severity badge for attention.
_CONFIDENCE_METER = {"high": "●●●", "medium": "●●○", "low": "●○○"}

_LABEL_STYLE = "dim"

#: Width of the field-label column. `Evidence` is the longest label at 8, so 9 leaves one
#: space and starts every value on the same column without opening a gap wide enough to
#: break the association between a label and its text.
_LABEL_WIDTH = 9

#: The severity bar's glyph and the gutter it sits in.
_BAR = "▌ "

_DISCLAIMER = (
    "Advisory only. This review assists a human reviewer, does not gate merges, "
    "and does not replace security review."
)


@dataclass(frozen=True)
class TerminalContext:
    """Optional header decoration. Everything here is presentation, never a finding.

    Passed alongside the `Review` for the same reason §13 passes the exclusion note that
    way: §10 fixes the output schema exactly, and a PR title is not part of it.
    """

    pr_label: str = ""
    pr_title: str = ""
    pr_author: str = ""
    pr_base: str = ""
    pr_head: str = ""
    source_label: str = ""
    partial: bool = False
    """True when the model calls did not run or failed, so coverage is deterministic-only."""


def build_console(*, no_color: bool = False, file=None, width: int | None = None) -> Console:
    """A console configured the way this report wants to be printed.

    Writes to stdout so the report can be piped and redirected like the Markdown it
    replaces; `cli.py` keeps diagnostics on stderr regardless. Rich already honours
    `NO_COLOR` and already strips styling when the destination is not a terminal, so
    `--no-color` only has to force the case rich cannot detect.
    """
    return Console(
        file=file or sys.stdout,
        no_color=no_color,
        width=width,
        soft_wrap=False,
        highlight=False,  # Rich's auto-highlighter would recolour numbers inside evidence.
        emoji=False,  # `:param:` in evidence is not an emoji shortcode.
    )


def prepare_terminal(
    review: Review,
    excluded_note: str = "",
    context: TerminalContext | None = None,
    *,
    console: Console | None = None,
) -> Callable[[], None]:
    """Build the report now; return a callable that prints it later.

    The split exists so `cli.py` can time the render and flush its stderr diagnostics
    *before* the report reaches stdout. Printing inside the render would force a choice
    between the two: either the timings report omits the render stage it is timing, or the
    `--verbose` counters interleave with the boxes they are supposed to precede.
    """
    console = console or build_console()
    # Rich sizes to the real terminal; the cap only ever narrows.
    width = min(console.width, MAX_WIDTH)
    blocks = _report(review, excluded_note, context or TerminalContext(), width)

    def emit() -> None:
        for block in blocks:
            console.print(block)

    return emit


def render_terminal(
    review: Review,
    excluded_note: str = "",
    context: TerminalContext | None = None,
    *,
    console: Console | None = None,
) -> None:
    """Build and print `review` in one step. Output only; returns nothing."""
    prepare_terminal(review, excluded_note, context, console=console)()


def render_terminal_str(
    review: Review,
    excluded_note: str = "",
    context: TerminalContext | None = None,
    *,
    width: int = 90,
    no_color: bool = True,
) -> str:
    """The same report as a string. For tests and for `--output` with `--format terminal`."""
    console = build_console(no_color=no_color, width=width)
    console.begin_capture()
    render_terminal(review, excluded_note, context, console=console)
    captured = console.end_capture()
    # Rich pads every line to the console width, which is invisible on screen and is trailing
    # whitespace in a file. Only the padding is removed; the line structure is what carries
    # the layout, so blank lines stay.
    return "\n".join(line.rstrip() for line in captured.splitlines()) + "\n"


def _report(
    review: Review, excluded_note: str, context: TerminalContext, width: int
) -> list[RenderableType]:
    # A blank line before the header keeps the panel's top border off the terminal's own
    # first row, which otherwise reads as clipped rather than as the top of the report.
    blocks: list[RenderableType] = [Text(""), _header(review, context, width)]

    if summary := review.summary.strip():
        blocks.append(Padding(Text(summary, style="default"), (1, 2, 0, 2)))

    if context.partial:
        blocks.append(
            Padding(
                Text(
                    "⚠  Partial coverage: the model pass did not run. "
                    "Deterministic findings only.",
                    style="bold yellow",
                ),
                (1, 2, 0, 2),
            )
        )

    if excluded_note:
        blocks.append(Padding(Text(f"▸ {excluded_note}", style="dim"), (1, 2, 0, 2)))

    blocks.extend(_findings_blocks(review, width))
    blocks.append(_pr_comment(review, width))
    # A closing rule the same width as every section rule above it, so the report ends on
    # the same visual vocabulary it used throughout instead of just stopping.
    blocks.append(Padding(Text("─" * max(width - 4, 10), style="dim"), (1, 2, 0, 2)))
    blocks.append(Padding(Text(_DISCLAIMER, style="dim italic"), (1, 2, 1, 2)))
    return blocks


# --------------------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------------------


def _header(review: Review, context: TerminalContext, width: int) -> RenderableType:
    """The triage block: risk, counts, and what was reviewed — before any scrolling (§13).

    The verdict, the counts, and the subject each get their own line. Crowding them onto one
    forces a single separator to mean two different things at once — `2 high · 1 low · 3
    files` reads as a four-item list, when it is a three-item list and a scope. Splitting the
    lines removes the ambiguity without needing a second separator character to carry it.
    """
    risk = review.overall_risk
    style = _SEVERITY_STYLE[risk]

    verdict = Text()
    # One space of chip padding, not two: the chip's background starts at the panel's own
    # left padding, so a wider inset makes the verdict look indented relative to the counts
    # line directly beneath it.
    verdict.append(f" {risk.upper()} RISK ", style=f"bold white on {style}")

    rows: list[RenderableType] = [verdict, Text("")]

    if review.findings:
        # `padding=(0, 1, 0, 0)` with the grid's default `pad_edge=False`: no padding at the
        # table's outer edges, one column of padding at the interior seam between the two
        # columns. That seam is what guarantees a gap survives even when the left column's
        # ratio split leaves it no slack (see `_file_heading`, where this matters more).
        counts = Table.grid(expand=True, padding=(0, 1, 0, 0))
        counts.add_column(justify="left", ratio=1)
        counts.add_column(justify="right")
        counts.add_row(_severity_chips(review.findings), Text(_scope(review.findings), "dim"))
        rows.append(counts)
    else:
        rows.append(Text("No findings.", style="dim"))

    if subtitle := _source_line(context):
        rows += [Text(""), subtitle]

    return Panel(
        Group(*rows),
        title=Text("Security review", style="bold"),
        title_align="left",
        border_style=style,
        box=HEAVY,
        width=width,
        padding=(1, 2),
    )


def _scope(findings: list[Finding]) -> str:
    """`across 4 files` — what the counts are counted over."""
    return f"across {_file_count(findings)}"


def _severity_chips(findings: list[Finding]) -> Text:
    """`3 high    7 medium    2 low`, each count in its own severity colour.

    Separated by whitespace rather than by `·`. Three counts in three different colours are
    already visually distinct, so a separator adds punctuation without adding information —
    and it is the same character the header would otherwise use to attach the scope, which
    is what made the old line read as one flat list.

    Built by re-styling `renderer.severity_counts` rather than recounting, so the terminal
    header and the Markdown header can never disagree about the numbers.
    """
    chips = Text()
    for index, part in enumerate(severity_counts(findings).split(" · ")):
        if index:
            chips.append("    ")
        severity = part.split(" ")[-1]
        chips.append(part, style=f"bold {_SEVERITY_STYLE.get(severity, 'default')}")
    return chips


def _file_count(findings: list[Finding]) -> str:
    total = len({finding.file for finding in findings})
    return f"{total} file" if total == 1 else f"{total} files"


def _source_line(context: TerminalContext) -> Text | None:
    """What was reviewed: the PR and its branches, or the diff that was piped in."""
    if not (context.pr_label or context.source_label):
        return None

    line = Text()
    if context.pr_label:
        line.append(context.pr_label, style="bold blue")
        if context.pr_title:
            line.append("  ")
            line.append(context.pr_title)
        details = []
        if context.pr_author:
            details.append(f"@{context.pr_author}")
        if context.pr_base and context.pr_head:
            details.append(f"{context.pr_head} → {context.pr_base}")
        if details:
            line.append("\n")
            line.append("  ·  ".join(details), style="dim")
    else:
        line.append(context.source_label, style="dim")
    return line


# --------------------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------------------


def _findings_blocks(review: Review, width: int) -> list[RenderableType]:
    if not review.findings:
        reason = review.no_findings_reason or "No security findings were identified."
        return [
            Padding(
                Panel(
                    Text(reason.strip()),
                    title=Text("No findings", style="bold green"),
                    title_align="left",
                    border_style="green",
                    box=ROUNDED,
                    padding=(0, 2),
                ),
                (1, 2, 0, 2),
                # Panel inside Padding so it inherits the body's 2-column gutter.
            )
        ]

    blocks: list[RenderableType] = []
    for index, (path, file_findings) in enumerate(group_by_file(review.findings)):
        # Two blank lines between file sections, one between findings within a section: the
        # gap itself should say whether the next thing is a new scope or more of this one,
        # rather than every heading and every finding reading as the same kind of break.
        top = 1 if index == 0 else 2
        blocks.append(Padding(_file_heading(path, file_findings, width - 4), (top, 2, 0, 2)))
        for finding in file_findings:
            # `SeverityBar` renders exactly its content's height, so the separation between
            # findings is this padding and nothing else.
            blocks.append(Padding(_finding_block(finding), (1, 2, 0, 2)))
    return blocks


def _file_heading(path: str, findings: list[Finding], width: int) -> RenderableType:
    """The file path, its severity breakdown, and a rule — the scroll anchor per section.

    The breakdown rather than a bare count, because the count does not answer the question
    the reviewer is asking here, which is "do I need to open this file". `2 findings` is the
    same line whether both are low-confidence style notes or both are removed auth checks;
    `2 high` is not.

    The rule is tinted to the file's worst severity — `findings[0]` after `group_by_file`'s
    sort, so it costs nothing to look up here — the same colour the matching `SeverityBar`
    uses below it, so the eye can match a section to its own bar before reading a word.
    """
    # A long path ellipsizes to fill its column exactly, so the gap before the chips has to
    # be structural, not incidental spare width — otherwise the truncated path runs straight
    # into the count with no space, e.g. `…auth.py1 medium`. Same fix as `_header`'s `counts`.
    heading = Table.grid(expand=True, padding=(0, 1, 0, 0))
    heading.add_column(justify="left", ratio=1)
    heading.add_column(justify="right")
    heading.add_row(Text(path, style="bold white"), _severity_chips(findings))

    rule_style = f"dim {_SEVERITY_STYLE[findings[0].severity]}"
    return Group(heading, Text("─" * max(width, 10), style=rule_style))


class SeverityBar:
    """Renders content with a full-height coloured bar in the left gutter.

    The bar is what makes a long report skimmable — the eye follows a column of red down the
    page without reading a word of it, so it has to run the *height* of the block, and the
    height is not known until the content wraps.

    Neither stock construct does this. A one-cell grid column paints only its first line,
    which reads as a bullet rather than a band. A `Panel` with a left-edge-only box does run
    full height, but `Panel` always draws four edges: blanking three leaves a styled space
    down the right margin and a blank rule above and below every finding. Rendering the
    content to lines and prefixing each one is the only version with no artifacts.
    """

    def __init__(self, renderable: RenderableType, style: str) -> None:
        self.renderable = renderable
        self.style = style

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        inner = options.update_width(max(options.max_width - len(_BAR), 1))
        bar = Segment(_BAR, console.get_style(self.style, default="none"))
        for line in console.render_lines(self.renderable, inner, pad=False):
            yield bar
            yield from line
            yield Segment.line()


def _finding_block(finding: Finding) -> RenderableType:
    """One finding: a severity bar, a title row, then the three prose fields.

    Two layout choices that are the difference between scannable and not:

    **Labels are left-aligned.** Right-aligning `Evidence`/`Risk`/`Fix` lines up their
    colons but leaves their left edges ragged, so the eye has no vertical line to run down.
    Left alignment gives one, and the values still share a column because the label column
    is fixed-width.

    **A blank line separates the fields.** `risk` and `recommendation` are model-written
    prose that routinely wraps to three lines each; without separation those six lines read
    as one paragraph and the labels stop being findable.
    """
    style = _SEVERITY_STYLE[finding.severity]

    fields = Table.grid(padding=(1, 1))
    fields.add_column(width=_LABEL_WIDTH, justify="left", style=_LABEL_STYLE)
    fields.add_column(ratio=1, overflow="fold")
    for label, value in (
        ("Evidence", finding.evidence),
        ("Risk", finding.risk),
        ("Fix", finding.recommendation),
    ):
        # `Text` and not a markup string: evidence carries `[MASKED_*]` (see module docstring).
        fields.add_row(label, Text(_flatten(value)))

    return SeverityBar(
        Group(_title_row(finding, style), Text(""), fields), style=f"bold {style}"
    )


def _title_row(finding: Finding, style: str) -> RenderableType:
    """` HIGH  auth_perms · line 42 · rule+model ······ ●●● high confidence`.

    Two columns rather than one string, so the confidence meters line up down a right-hand
    edge regardless of how long a category name happens to be. Severity therefore reads down
    the left, confidence down the right, and neither column shifts between findings.

    Grouped by question rather than by field: *what and where* on the left (category,
    location, which detector found it), *how sure* on the right. The word "confidence" is
    spelled out because a bare `high` next to a `HIGH` badge is genuinely ambiguous about
    which axis it describes.
    """
    left = Text()
    left.append(f" {_SEVERITY_LABEL[finding.severity]} ", style=f"bold white on {style}")
    left.append("  ")
    left.append(finding.category, style=f"bold {style}")
    left.append("  ·  ", style="dim")
    left.append(_location(finding), style="bold" if finding.line is None else "default")
    if finding.source == "both":
        # §12.3: two independent detectors concurring is the strongest signal the tool has,
        # and it is invisible in the fields — it only shows in how the confidence got there.
        left.append("  ·  ", style="dim")
        left.append("rule + model", style="green")

    right = Text()
    right.append(_CONFIDENCE_METER[finding.confidence], style=style)
    right.append(f"  {finding.confidence} confidence", style="dim")

    row = Table.grid(expand=True, padding=(0, 1, 0, 0))
    row.add_column(justify="left", ratio=1)
    row.add_column(justify="right")
    row.add_row(left, right)
    return row


def _location(finding: Finding) -> str:
    return "file-level" if finding.line is None else f"line {finding.line}"


# --------------------------------------------------------------------------------------
# Footer
# --------------------------------------------------------------------------------------


def _pr_comment(review: Review, width: int) -> RenderableType:
    """The paste-ready comment, boxed so it is obvious where it starts and stops."""
    return Padding(
        Panel(
            Text(review.pr_comment.strip()),
            title=Text("PR comment", style="bold"),
            title_align="left",
            border_style="dim",
            box=ROUNDED,
            width=width - 4,
            padding=(1, 2),
        ),
        (1, 2, 0, 2),
    )


# --------------------------------------------------------------------------------------
# Run diagnostics (stderr, §11, §14)
# --------------------------------------------------------------------------------------

#: Stages that are a blocking network call. Split out in the timing line because they are
#: the only ones a reviewer can do anything about, and they dwarf everything else.
_API_STAGES = frozenset({"review_pass", "summary_pass"})

#: Every pinned model id starts with this. Dropping it costs no information and buys back
#: seven columns in the widest column of the calls table.
_MODEL_PREFIX = "claude-"

#: `summary` is the longest label a call gets once `_call_label` has taken the diff stem off;
#: a batched review pass adds an index, which fits in the same width.
_CALL_LABEL_WIDTH = 9

#: Fits `haiku-4-5-20251001` exactly. A longer id from `--model` truncates, which is the
#: right trade: the alternative is every numeric column shifting between runs.
_MODEL_WIDTH = 18


@dataclass(frozen=True)
class CallRecord:
    """One API call as the diagnostics table wants it: already costed, already totalled.

    A presentation-side mirror of `llm_client.CallLog` rather than that class itself, so
    this module never imports a pipeline stage — the dependency runs one way, from `cli.py`
    into both.
    """

    label: str
    model: str
    seconds: float
    input_tokens: int
    output_tokens: int
    cache_tokens: int
    cost: float


@dataclass(frozen=True)
class RunDiagnostics:
    """Everything `--verbose` reports, as data instead of as pre-formatted lines.

    `cli.py` decides *what* is worth reporting; this module decides what it looks like. The
    split is the reason the same run can print an aligned table to a terminal and the
    original `key=value` lines to a CI log without `cli.py` knowing which happened.
    """

    unmappable_count: int = 0
    hallucinated_file_count: int = 0
    excluded_note: str = ""
    source_label: str = ""
    verbose: bool = False
    masked_line_count: int = 0
    calls: tuple[CallRecord, ...] = ()
    total_cost: float = 0.0
    stages: tuple[tuple[str, float], ...] = ()
    unmappable_lines: tuple[str, ...] = ()
    hallucinated_files: tuple[str, ...] = ()


def build_stderr_console(*, no_color: bool = False) -> Console:
    """A console for diagnostics. Separate from the report's, and bound to stderr."""
    return build_console(no_color=no_color, file=sys.stderr)


def render_diagnostics(diag: RunDiagnostics, *, console: Console | None = None) -> None:
    """Print the run diagnostics to stderr, styled or plain depending on the destination.

    The branch is `console.is_terminal`, the same signal `--format auto` resolves on (§24),
    applied to the other stream. It has to be checked here rather than assumed, because the
    two streams genuinely differ: `review-bot diff > out.md` leaves stdout a file and stderr
    a terminal, and that run should still get the readable version of its own diagnostics.
    """
    console = console or build_stderr_console()
    if not console.is_terminal:
        _plain_diagnostics(diag, console)
        return
    # No width cap here, unlike the report: every row is content-sized, so a wide terminal
    # gets the same block with more empty space to its right rather than a longer line.
    console.print(_diagnostics_block(diag))


def _plain_diagnostics(diag: RunDiagnostics, console: Console) -> None:
    """The unstyled form: byte-for-byte what this tool printed before it had a table.

    Not a fallback but a second audience. §11 puts these counters in the CI job output, and
    what makes them useful there is that they are greppable — `unmappable_count=3` survives
    a log search, a two-column layout with the number under a heading does not.
    """
    out = console.file
    print(
        f"unmappable_count={diag.unmappable_count} "
        f"hallucinated_file_count={diag.hallucinated_file_count}",
        file=out,
    )
    if diag.excluded_note:
        print(diag.excluded_note, file=out)
    if not diag.verbose:
        return

    print(f"masked_line_count={diag.masked_line_count}", file=out)
    print(_timings_line(diag.stages), file=out)
    for call in diag.calls:
        print(
            f"{call.label}: in={call.input_tokens} out={call.output_tokens} "
            f"cache={call.cache_tokens} cost=${call.cost:.4f}",
            file=out,
        )
    if diag.calls:
        print(f"total cost this run: ${diag.total_cost:.4f}", file=out)
    if diag.unmappable_lines:
        print(f"unmappable lines: {list(diag.unmappable_lines)}", file=out)
    if diag.hallucinated_files:
        print(f"hallucinated files: {list(diag.hallucinated_files)}", file=out)


def _diagnostics_block(diag: RunDiagnostics) -> RenderableType:
    """The styled form: a label column, then one row per question the run can answer.

    Laid out as `label   value` rather than as a run of `key=value` pairs because the
    failure mode being fixed is not density, it is having no entry point — eight lines of
    equals signs have no left edge to scan and no shape to tell them apart. A fixed label
    column gives one vertical line to run down and turns "what did this cost" into a lookup
    instead of a read.
    """
    rows: list[tuple[str, RenderableType]] = []

    if diag.verbose and diag.calls:
        rows.append(("calls", _calls_table(diag)))
    rows.append(("checks", _checks_line(diag)))
    if diag.verbose and diag.stages:
        rows.append(("time", _time_block(diag.stages)))
    if diag.excluded_note:
        rows.append(("scope", Text(diag.excluded_note, style="dim")))

    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=_LABEL_WIDTH, justify="left", style=_LABEL_STYLE)
    grid.add_column(ratio=1, overflow="fold")
    for label, value in rows:
        grid.add_row(label, value)

    # A default run prints one line here, and a heading over one line is chrome. The heading
    # earns its place only once there is a table under it that needs saying what it is about.
    blocks: list[RenderableType] = []
    if diag.verbose:
        heading = Text("Run", style="bold dim")
        if diag.source_label:
            heading.append(f"  {diag.source_label}", style="dim")
        blocks += [heading, Text("")]

    # Trailing blank line: this block and the report land on one screen, and without a gap
    # the diagnostics read as the report's first paragraph.
    return Padding(Group(*blocks, grid), (0, 2, 1, 2))


def _calls_table(diag: RunDiagnostics) -> RenderableType:
    """One row per API call, plus the run total under the column it totals.

    Column headers instead of an `in=`/`out=` prefix on every number: the units repeat on
    every row and the numbers do not, so naming them once is what lets the digits line up
    into a column the eye can compare down.
    """
    table = Table.grid(padding=(0, 2))
    # Exactly one column is allowed to flex, and it is the model. Left to itself the grid
    # shrinks whichever column is widest, which on a narrow terminal means truncating the
    # cost to `$0.03…` — the one number nobody can reconstruct from the others. Pinning
    # everything else makes the model name absorb the squeeze instead, and a model id
    # missing its tail is still legible as which model ran.
    table.add_column(justify="left", width=_CALL_LABEL_WIDTH, no_wrap=True, overflow="ellipsis")
    # No `no_wrap`: that flag is what marks a column unshrinkable, and this is the column
    # that has to give. `overflow="ellipsis"` makes it shorten rather than wrap.
    table.add_column(justify="left", overflow="ellipsis", max_width=_MODEL_WIDTH)
    for _ in range(5):  # time, in, out, cached, cost
        table.add_column(justify="right", no_wrap=True, overflow="fold")

    header = ("", "model", "time", "in", "out", "cache", "cost")
    table.add_row(*(Text(cell, style="dim") for cell in header))

    for call in diag.calls:
        table.add_row(
            Text(call.label, style="bold"),
            Text(call.model.removeprefix(_MODEL_PREFIX), style="dim"),
            Text(_duration(call.seconds)),
            Text(f"{call.input_tokens:,}"),
            Text(f"{call.output_tokens:,}"),
            Text(f"{call.cache_tokens:,}", style="dim" if not call.cache_tokens else "green"),
            Text(f"${call.cost:.4f}"),
        )

    if len(diag.calls) > 1:
        table.add_row("", "", "", "", "", Text("total", style="dim"),
                      Text(f"${diag.total_cost:.4f}", style="bold"))
    return table


def _checks_line(diag: RunDiagnostics) -> Text:
    """§11's two counters, plus the masking counter under `--verbose`.

    A zero here is the expected answer, so zeros are dimmed and only a non-zero count takes
    colour — the line should cost nothing to skip past on a healthy run and catch the eye on
    an unhealthy one. Masked lines are exempt: a non-zero there is masking working (§5), not
    a problem, so it never turns yellow.
    """
    line = Text()
    counters = [
        (diag.unmappable_count, "unmappable line", True),
        (diag.hallucinated_file_count, "hallucinated file", True),
    ]
    if diag.verbose:
        counters.append((diag.masked_line_count, "masked line", False))

    for index, (count, label, warns) in enumerate(counters):
        if index:
            line.append("  ·  ", style="dim")
        style = "bold yellow" if count and warns else ("dim" if not count else "default")
        line.append(f"{count} {label}{'' if count == 1 else 's'}", style=style)

    for label, values in (
        ("unmappable", diag.unmappable_lines),
        ("hallucinated", diag.hallucinated_files),
    ):
        if values:
            # The counters say something moved; these say where, which is what tuning acts on.
            line.append(f"\n{label}: ", style="dim")
            line.append(", ".join(str(value) for value in values))
    return line


def _time_block(stages: tuple[tuple[str, float], ...]) -> RenderableType:
    """Total first, then the split that explains it, then the per-stage detail.

    Three levels because there are three questions, asked in that order: how long did this
    take, was it the network or us, and which stage. Printing only the flat stage list makes
    the first two questions arithmetic.
    """
    elapsed = dict(stages)
    total = sum(elapsed.values())
    api = sum(seconds for name, seconds in elapsed.items() if name in _API_STAGES)
    local = total - api

    headline = Text()
    headline.append(_duration(total), style="bold")
    if api:
        headline.append("   api ", style="dim")
        headline.append(_duration(api))
        headline.append("  ·  local ", style="dim")
        headline.append(_duration(local))

    detail = Text(
        " · ".join(
            f"{name} {_duration(seconds)}"
            for name, seconds in stages
            if name not in _API_STAGES
        ),
        style="dim",
    )
    return Group(headline, detail)


def _timings_line(stages: tuple[tuple[str, float], ...]) -> str:
    """`timings: parse 1.2ms · mask 8.4ms · … · total 2.31s` — the plain-text form."""
    if not stages:
        return "timings: (none recorded)"
    body = " · ".join(f"{name} {_duration(seconds)}" for name, seconds in stages)
    return f"timings: {body} · total {_duration(sum(s for _, s in stages))}"


def _duration(seconds: float) -> str:
    return f"{seconds * 1000:.1f}ms" if seconds < 1 else f"{seconds:.2f}s"


def _flatten(text: str) -> str:
    """Collapse whitespace without touching the characters that carry meaning.

    Same contract as `renderer._clean`: escaping or truncating is the only way a
    `[MASKED_*]` placeholder would stop reading as one (§13).
    """
    return " ".join(text.split())
