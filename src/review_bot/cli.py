"""Argument parsing, input, orchestration, exit codes (SPEC.md §4, §14, §15).

This module sequences the pipeline and owns nothing else. Every decision it makes belongs
to a stage: what to mask is `secret_masker`'s, what to suppress is `role_scanner`'s, what
to send is `prompt_builder`'s, whether to send it is `llm_client`'s, and whether the answer
is usable is `schema.py`'s. What lives here is the order, the flags, and the exit codes.

The order is load-bearing: masking runs on the parsed diff before `prompt_builder` is even
constructed (invariant 1), and deterministic findings are collected before the first call
so they are emitted whether or not it succeeds (invariant 3, §12).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .diff_parser import DiffParseError, ParsedDiff, parse_diff
from .github_source import (
    GitHubError,
    PullRequestInfo,
    fetch_pr_diff,
    fetch_pr_info,
    looks_like_pr_ref,
    parse_pr_ref,
)
from .llm_client import (
    DEFAULT_REVIEW_MODEL,
    DEFAULT_SUMMARY_MODEL,
    REVIEW_MAX_TOKENS,
    SUMMARY_MAX_TOKENS,
    BudgetExceeded,
    LLMClient,
    LLMError,
    ResponseCache,
)
from .prompt_builder import (
    DEFAULT_MAX_INPUT_TOKENS,
    apply_confidence_caps,
    build_review_prompt,
    build_summary_prompt,
    filter_files,
    pack,
)
from .renderer import render_markdown
from .role_scanner import register_suppressions, scan_diff
from .schema import (
    Finding,
    LLMSummaryResponse,
    MalformedLLMResponse,
    Review,
    ValidationStats,
    merge_findings,
    overall_risk,
    parse_review_response,
    parse_summary_response,
    validate_findings,
)
from .secret_masker import mask_diff
from .terminal import (
    CallRecord,
    RunDiagnostics,
    TerminalContext,
    build_console,
    build_stderr_console,
    prepare_terminal,
    render_diagnostics,
    render_terminal_str,
)

EXIT_OK = 0
EXIT_PARSE_ERROR = 1
EXIT_MALFORMED_LLM_JSON = 2
EXIT_BUDGET = 3
EXIT_FAIL_ON = 4

DEFAULT_CACHE_DIR = Path(".review_bot_cache")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="review-bot",
        description=(
            "Security review of a unified Git diff. Advisory only: it assists a human "
            "reviewer and does not gate merges."
        ),
    )
    parser.add_argument(
        "source",
        metavar="DIFF_PATH | PR_URL",
        nargs="?",
        help="Path to a unified diff, '-' to read stdin, or a GitHub pull request "
             "(https://github.com/owner/repo/pull/123, or owner/repo#123).",
    )
    parser.add_argument("--pr", metavar="REF",
                        help="Review a GitHub pull request. Accepts a URL, owner/repo#123, "
                             "or a bare 123 for the current repository. Fetched with `gh`.")
    parser.add_argument("--format", choices=["auto", "terminal", "markdown", "json", "both"],
                        default="auto",
                        help="Output format. 'auto' (default) is terminal when stdout is a "
                             "TTY and markdown when it is piped. JSON is the source of "
                             "truth either way.")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colour in terminal output. NO_COLOR is honoured too.")
    parser.add_argument("--output", metavar="PATH",
                        help="Write output to a file (default stdout). With --format both, "
                             "Markdown goes to PATH and JSON to PATH with a .json suffix.")
    parser.add_argument("--model", default=DEFAULT_REVIEW_MODEL, help="Override the review model")
    parser.add_argument("--summary-model", default=DEFAULT_SUMMARY_MODEL)
    parser.add_argument("--effort", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--fail-on", choices=["none", "high"], default="none",
                        help="Exit 4 when findings reach this severity. Off by default.")
    parser.add_argument("--cache", action="store_true",
                        help="Reuse cached responses by prompt hash. Off by default.")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--record", metavar="DIR", type=Path,
                        help="Write raw responses to DIR as test fixtures")
    parser.add_argument("--dry-run", action="store_true",
                        help="Build and price the prompts, send nothing")
    parser.add_argument("--no-llm", action="store_true", help="Deterministic findings only")
    parser.add_argument("--max-input-tokens", type=int, default=DEFAULT_MAX_INPUT_TOKENS)
    parser.add_argument("--max-run-cost", type=float, default=0.50)
    parser.add_argument("--verbose", action="store_true",
                        help="Per-call usage and timing to stderr")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    timings = Timings()

    try:
        source = _resolve_source(args, parser)
    except GitHubError as exc:
        # A pull request that cannot be fetched is unusable input, exactly like a diff that
        # cannot be read, so it takes the same exit code (§15, §23).
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_PARSE_ERROR
    except (OSError, UnicodeDecodeError) as exc:
        # UnicodeDecodeError: a diff file that is not UTF-8 (Latin-1 content is common in
        # older repositories) is unreadable input, not a crash.
        print(f"error: could not read diff: {exc}", file=sys.stderr)
        return EXIT_PARSE_ERROR

    try:
        with timings("parse"):
            diff = parse_diff(source.text)
    except DiffParseError as exc:
        print(f"error: could not parse diff: {exc}", file=sys.stderr)
        return EXIT_PARSE_ERROR

    if not diff.has_reviewable_changes:
        # §15: exit 0 with valid JSON and a reason. The LLM is not called — never spend
        # money on an empty diff (invariant 6).
        print("No reviewable changes.", file=sys.stderr)
        _emit(args, _empty_review("The diff contains no added lines to review."), source)
        return EXIT_OK

    # ---- Deterministic stages. These run before anything reaches the network. ----------
    with timings("mask"):
        mask_result = mask_diff(diff)  # invariant 1: masks in place, before prompt_builder
    with timings("scan"):
        scan_result = scan_diff(diff)
        register_suppressions(scan_result, mask_result.findings)
    deterministic: list[Finding] = mask_result.findings + scan_result.findings

    with timings("pack"):
        filtered = filter_files(diff)
        batches = pack(filtered.reviewable, args.max_input_tokens)

    llm_findings: list[Finding] = []
    stats = ValidationStats()
    summary: LLMSummaryResponse | None = None

    skip_llm = args.no_llm or not batches
    if not batches and not args.no_llm:
        # Every file was filtered out. Invariant 6 again: nothing to review, no call.
        print("No files eligible for LLM review; deterministic findings only.", file=sys.stderr)

    stem = source.stem
    client = LLMClient(
        model=args.model,
        summary_model=args.summary_model,
        effort=args.effort,
        max_input_tokens=args.max_input_tokens,
        max_run_cost=args.max_run_cost,
        verbose=args.verbose,
        cache=ResponseCache(args.cache_dir) if args.cache else None,
        record_dir=args.record,
    )

    if args.dry_run:
        return _dry_run(
            args, client, batches, filtered, deterministic, scan_result.suppressed,
            scan_result.candidates,
        )

    if not skip_llm:
        try:
            with timings("review_pass"):
                llm_findings, stats = _review_pass(
                    client, batches, scan_result.suppressed, scan_result.candidates, diff, stem
                )
        except _LLM_FAILURES as exc:
            if (code := _report_llm_failure(exc, "review pass")) is not None:
                return code
            skip_llm = True

    with timings("merge"):
        findings = merge_findings(deterministic, llm_findings)

    if not skip_llm:
        try:
            with timings("summary_pass"):
                raw = client.summarize(
                    build_summary_prompt(
                        [f.path for f in filtered.reviewable], filtered.excluded, findings
                    ),
                    label=f"summary-{stem}",
                )
                summary = parse_summary_response(raw)
        except _LLM_FAILURES as exc:
            if (code := _report_llm_failure(exc, "summary pass")) is not None:
                return code

    review = _assemble(findings, summary, filtered)
    with timings("render"):
        rendered = _render(
            args, review, filtered.exclusion_summary(), source, partial=summary is None
        )
    # Metrics go to stderr before the report goes to stdout: when both land on a terminal,
    # the diagnostics scroll away above the report instead of interleaving with its boxes.
    # `_render` only *builds* the terminal report; `_write` is what prints it.
    _report_metrics(args, stats, filtered, client, timings, mask_result, source)
    _write(args, rendered)

    if args.fail_on == "high" and any(f.severity == "high" for f in review.findings):
        return EXIT_FAIL_ON
    return EXIT_OK


# --------------------------------------------------------------------------------------
# Stages
# --------------------------------------------------------------------------------------


#: The three ways an LLM stage can fail. `_report_llm_failure` maps each to an exit code.
_LLM_FAILURES = (MalformedLLMResponse, BudgetExceeded, LLMError)


def _report_llm_failure(exc: Exception, stage: str) -> int | None:
    """Report a failed LLM stage; return its exit code, or None to continue without it.

    §15 draws the line at whether the model answered. Malformed JSON is exit 2 with the raw
    response printed verbatim — the model *did* answer and the answer was unusable, which
    is a contract breach worth failing on, and there is no repair and no retry. A budget
    abort is exit 3. Everything else — network failure, an API error, a refusal — is not a
    *tool* failure: invariant 3 produces the deterministic findings regardless, so the run
    says coverage was partial and carries on at exit 0.
    """
    if isinstance(exc, MalformedLLMResponse):
        print(f"error: {exc}", file=sys.stderr)
        print(exc.raw)
        return EXIT_MALFORMED_LLM_JSON
    if isinstance(exc, BudgetExceeded):
        print(f"error: budget guard aborted the run: {exc}", file=sys.stderr)
        return EXIT_BUDGET
    print(f"warning: {stage} failed, continuing without it: {exc}", file=sys.stderr)
    return None


def _review_pass(
    client: LLMClient,
    batches: list,
    suppressed: set[tuple[str, int]],
    candidates: list[Finding],
    diff: ParsedDiff,
    stem: str,
) -> tuple[list[Finding], ValidationStats]:
    """Call 1 over every batch, validating each response against the parsed diff (§11).

    Validation happens per batch rather than once at the end so `hallucinated_file_count`
    attributes correctly: a file absent from *this* batch but present elsewhere in the diff
    is not a hallucination, it is the model citing something it legitimately saw earlier.
    """
    collected: list[Finding] = []
    stats = ValidationStats()

    for index, batch in enumerate(batches):
        # The batch index is only in the label when there is more than one batch, so the
        # common single-batch run records to `review-<stem>.json` — the fixture name the
        # contract test reads. See `_record_stem`.
        suffix = f"-{index}" if len(batches) > 1 else ""
        raw = client.review(
            build_review_prompt(batch, suppressed, candidates), label=f"review-{stem}{suffix}"
        )
        validated, batch_stats = validate_findings(parse_review_response(raw), diff)
        collected.extend(apply_confidence_caps(validated, batch))
        stats.extend(batch_stats)

    return collected, stats


def _dry_run(
    args, client: LLMClient, batches, filtered, deterministic, suppressed, candidates
) -> int:
    """`--dry-run`: build and price every prompt, send nothing (§9).

    The summary prompt is built from deterministic findings alone, since the review pass
    that would add to them never runs. It is representative of shape and roughly of size,
    which is what a cost estimate needs.
    """
    calls = [
        (
            f"review-{i}",
            build_review_prompt(b, suppressed, candidates),
            args.model,
            REVIEW_MAX_TOKENS,
        )
        for i, b in enumerate(batches)
    ]
    calls.append(
        (
            "summary",
            build_summary_prompt(
                [f.path for f in filtered.reviewable], filtered.excluded, deterministic
            ),
            args.summary_model,
            SUMMARY_MAX_TOKENS,
        )
    )
    print(client.dry_run_report(calls))
    return EXIT_OK


def _assemble(findings: list[Finding], summary: LLMSummaryResponse | None, filtered) -> Review:
    if summary is not None:
        return Review(
            summary=summary.summary,
            overall_risk=summary.overall_risk,
            findings=findings,
            pr_comment=summary.pr_comment,
            no_findings_reason=None if findings else "No security findings were identified.",
        )

    # No summary pass: --no-llm, or the call failed. Synthesise something honest rather
    # than leaving required fields empty — the JSON is the source of truth (§10).
    counts = f"{len(findings)} finding(s)"
    note = filtered.exclusion_summary()
    detail = f" {note}." if note else ""
    return Review(
        summary=(
            f"Deterministic review only (no model summary available). {counts} across "
            f"{len({f.file for f in findings})} file(s).{detail}"
        ),
        overall_risk=overall_risk(findings),
        findings=findings,
        pr_comment=(
            f"Automated security review found {counts}. This run produced deterministic "
            "findings only; treat the coverage as partial and review manually."
        ),
        no_findings_reason=None if findings else "No deterministic security findings.",
    )


def _report_metrics(
    args,
    stats: ValidationStats,
    filtered,
    client: LLMClient,
    timings: Timings,
    mask_result,
    source: Source,
) -> None:
    """Collect what the run has to say about itself; `terminal` decides how it looks.

    §11: both counters go to stderr on every run and into the CI job output — which is why
    this is unconditional and only the detail behind it is gated on `--verbose`. Masking is
    in that detail because it is the one stage whose success is invisible in the output: a
    run that masked nothing and a run whose masking silently no-opped look identical.
    """
    render_diagnostics(
        RunDiagnostics(
            unmappable_count=stats.unmappable_count,
            hallucinated_file_count=stats.hallucinated_file_count,
            excluded_note=filtered.exclusion_summary(),
            source_label=source.label,
            verbose=args.verbose,
            masked_line_count=mask_result.masked_line_count,
            calls=tuple(
                CallRecord(
                    label=_call_label(call.label, source.stem),
                    model=call.model,
                    seconds=call.seconds,
                    input_tokens=call.usage.input_tokens,
                    output_tokens=call.usage.output_tokens,
                    cache_tokens=call.cache_tokens,
                    cost=call.cost,
                )
                for call in client.calls
            ),
            total_cost=client.spent,
            stages=timings.stages,
            unmappable_lines=tuple(str(line) for line in stats.unmappable_lines),
            hallucinated_files=tuple(stats.hallucinated_files),
        ),
        console=build_stderr_console(no_color=args.no_color),
    )


def _call_label(label: str, stem: str) -> str:
    """`review-auth_bypass` -> `review`, once the table has a heading naming the source.

    The stem is in the call label because `--record` names fixture files with it (§17), and
    repeating it on every row of a table that already says which diff it reviewed is the
    kind of redundancy that made the old block unreadable.
    """
    return label.removesuffix(f"-{stem}") or label


# --------------------------------------------------------------------------------------
# Input and output
# --------------------------------------------------------------------------------------


@dataclass
class Source:
    """Where the diff came from, and how the run should label it.

    One object rather than three parallel variables because every consumer wants a
    different part of it: `parse_diff` wants the text, `--record` wants the stem, the
    terminal header wants the pull request. Bundling them keeps `main` from threading three
    arguments through calls that only use one.
    """

    text: str
    stem: str
    """`--record` / `--verbose` call label, derived from the input (see below)."""
    label: str = ""
    pr: PullRequestInfo | None = None

    def terminal_context(self, *, partial: bool) -> TerminalContext:
        if self.pr is None:
            return TerminalContext(source_label=self.label, partial=partial)
        return TerminalContext(
            pr_label=self.pr.label,
            pr_title=self.pr.title,
            pr_author=self.pr.author,
            pr_base=self.pr.base,
            pr_head=self.pr.head,
            partial=partial,
        )


def _resolve_source(args, parser: argparse.ArgumentParser) -> Source:
    """Turn the arguments into diff text plus the labels the run needs (§14, §23).

    The positional slot accepts a path *or* a pull request, which is the whole ergonomic
    point of `--pr` being optional — pasting a PR URL is what someone actually does. That is
    safe only because `looks_like_pr_ref` rejects the bare-number forms: a URL and
    `owner/repo#123` cannot be mistaken for a real path, and `123` can.

    An existing file always wins over a reference that looks like a PR, so a directory
    genuinely containing `owner/repo#1` still reads as the file it is.
    """
    if args.pr and args.source:
        parser.error("give a diff path or --pr, not both")
    if not args.pr and not args.source:
        parser.error("a diff path, '-' for stdin, or --pr is required")

    if args.pr:
        ref = parse_pr_ref(args.pr, allow_bare=True)
        if ref is None:
            parser.error(
                f"--pr {args.pr!r} is not a pull request reference. Expected a URL, "
                "owner/repo#123, or a bare number."
            )
        return _fetch_source(ref)

    source: str = args.source
    if source != "-" and not Path(source).exists() and looks_like_pr_ref(source):
        return _fetch_source(parse_pr_ref(source))

    return Source(text=_read_input(source), stem=_record_stem(source), label=_source_label(source))


def _fetch_source(ref) -> Source:
    """Fetch a pull request through `gh`.

    The diff is required and its failure aborts the run; the metadata is decoration and its
    failure is silent (`fetch_pr_info` returns None). Losing a title is not a reason to
    throw away a review that already arrived.
    """
    text = fetch_pr_diff(ref)
    info = fetch_pr_info(ref)
    return Source(
        text=text,
        # `owner/repo#123` contains `/` and `#`; neither belongs in a fixture filename.
        stem=f"pr-{ref.owner or 'local'}-{ref.repo or 'repo'}-{ref.number}".replace("/", "-"),
        label=str(ref),
        pr=info or PullRequestInfo(ref=ref),
    )


def _read_input(source: str) -> str:
    """A path or `-` for stdin. Never shells out to git (§14)."""
    if source == "-":
        return sys.stdin.read()
    return Path(source).read_text()


def _source_label(source: str) -> str:
    return "stdin" if source == "-" else source


def _record_stem(source: str) -> str:
    """Name `--record` output after the input diff, so `make record` overwrites the
    fixtures the contract test actually reads (§17).

    Labelling the calls `review`/`summary` alone would write one pair of files per run and
    every diff would clobber the last; `tests/fixtures/` is keyed by sample diff, so the
    stem has to be too. Also the `--verbose` log label, which is more use than an index.
    """
    return "stdin" if source == "-" else Path(source).stem


def _empty_review(reason: str) -> Review:
    return Review(
        summary="No reviewable changes in this diff.",
        overall_risk="low",
        findings=[],
        pr_comment="No reviewable code changes were found in this diff.",
        no_findings_reason=reason,
    )


def _to_json(review: Review) -> str:
    """`sort_keys=True` so a fixture diff shows a content change, never a key reordering."""
    return json.dumps(review.public_dict(), indent=2, sort_keys=True, ensure_ascii=False)


def _resolve_format(args) -> str:
    """Resolve `--format auto` to a concrete format.

    Terminal when a human is looking at it, Markdown when something else is. The detection
    is `stdout.isatty()`, which is the same signal that already decides whether the styled
    output would have been legible: a redirect or a pipe wants the Markdown that CI, `>`,
    and `| less` have always got, and defaulting to it is what keeps §18's workflows and
    every existing script working unchanged.
    """
    if args.format != "auto":
        return args.format
    return "terminal" if sys.stdout.isatty() else "markdown"


@dataclass
class Report:
    """A rendered review, ready to be written.

    `emit` is the terminal report's deferred print. It exists because styled output cannot
    be a string without losing what makes it styled — rich sizes boxes to the real console
    width and colours them to the real destination, and both are decided by the console
    object, not recoverable from captured text. So the console-bound path carries a closure
    instead of a string, and `_write` calls it at the same point it would have printed.
    Bound for `--output` there is no terminal to size to, and it captures to a string like
    every other format.
    """

    artifacts: dict[str, str] = field(default_factory=dict)
    emit: Callable[[], None] | None = None


def _render(
    args,
    review: Review,
    excluded_note: str = "",
    source: Source | None = None,
    *,
    partial: bool = False,
) -> Report:
    """Produce every artifact `--format` asked for, keyed by extension."""
    context = (source or Source(text="", stem="")).terminal_context(partial=partial)
    fmt = _resolve_format(args)

    if fmt == "terminal":
        if args.output:
            return Report(artifacts={"term": render_terminal_str(review, excluded_note, context)})
        return Report(
            emit=prepare_terminal(
                review, excluded_note, context, console=build_console(no_color=args.no_color)
            )
        )

    artifacts: dict[str, str] = {}
    if fmt in ("markdown", "both"):
        artifacts["md"] = render_markdown(review, excluded_note)
    if fmt in ("json", "both"):
        artifacts["json"] = _to_json(review) + "\n"
    return Report(artifacts=artifacts)


def _write(args, report: Report) -> None:
    """Write to `--output` or stdout.

    `--format both` needs two destinations, and CI wants both as named artifacts (§18), so
    the JSON takes the output path with a `.json` suffix. Without `--output` both go to
    stdout in a fixed order — Markdown first, since that is the one a human is reading.
    """
    if report.emit is not None:
        report.emit()
        return

    artifacts = report.artifacts
    if not args.output:
        print("\n".join(artifacts[key].rstrip() for key in ("md", "json") if key in artifacts))
        return

    path = Path(args.output)
    if "term" in artifacts:
        path.write_text(artifacts["term"])
        return
    if "md" in artifacts:
        path.write_text(artifacts["md"])
    if "json" in artifacts:
        json_path = path
        if "md" in artifacts:
            # When PATH already ends in .json, with_suffix is a no-op and the JSON would
            # silently overwrite the Markdown just written — append instead.
            json_path = path.with_suffix(".json")
            if json_path == path:
                json_path = path.with_name(path.name + ".json")
        json_path.write_text(artifacts["json"])


def _emit(args, review: Review, source: Source | None = None) -> None:
    """Render and write in one step, for the paths that return before the full pipeline."""
    _write(args, _render(args, review, "", source))


# --------------------------------------------------------------------------------------
# Timing
# --------------------------------------------------------------------------------------


class Timings:
    """Wall-clock time per pipeline stage, reported under `--verbose` (§14).

    Wall-clock rather than CPU time because the number a reviewer waiting on a run cares
    about is how long the API calls took, and those are spent blocked on the network.
    """

    def __init__(self) -> None:
        self._elapsed: dict[str, float] = {}

    @contextmanager
    def __call__(self, stage: str):
        start = time.perf_counter()
        try:
            yield
        finally:
            # Accumulate: a stage entered more than once reports its total, not its last.
            self._elapsed[stage] = self._elapsed.get(stage, 0.0) + time.perf_counter() - start

    @property
    def total(self) -> float:
        return sum(self._elapsed.values())

    @property
    def stages(self) -> tuple[tuple[str, float], ...]:
        """Pipeline order, since that is insertion order. Formatting belongs to `terminal`."""
        return tuple(self._elapsed.items())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
