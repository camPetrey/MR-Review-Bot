"""Argument parsing, input, orchestration, exit codes (SPEC.md §4, §14, §15).

This module sequences the pipeline and owns nothing else. Every decision it makes belongs
to a stage: what to mask is `secret_masker`'s, what to suppress is `role_scanner`'s, what
to send is `prompt_builder`'s, whether to send it is `llm_client`'s, and whether the answer
is usable is `schema.py`'s. What lives here is the order, the flags, and the exit codes.

The order is load-bearing. Masking runs on the parsed diff before `prompt_builder` is even
constructed, so no raw diff content can reach the API (invariant 1). Deterministic findings
are collected before the first call and are emitted whether or not that call succeeds
(invariant 3, §12).

Timing is collected here for the same reason: a stage boundary is the only place that knows
where one stage ends and the next begins. `--verbose` reports it (§14).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from .diff_parser import DiffParseError, ParsedDiff, parse_diff
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
        "diff",
        metavar="DIFF_PATH",
        help="Path to a unified diff, or '-' to read stdin. No git invocation (§14).",
    )
    parser.add_argument("--format", choices=["markdown", "json", "both"], default="markdown",
                        help="Output format (§14). JSON is the source of truth either way.")
    parser.add_argument("--output", metavar="PATH",
                        help="Write output to a file (default stdout). With --format both, "
                             "Markdown goes to PATH and JSON to PATH with a .json suffix.")
    parser.add_argument("--model", default=DEFAULT_REVIEW_MODEL, help="Override the review model")
    parser.add_argument("--summary-model", default=DEFAULT_SUMMARY_MODEL)
    parser.add_argument("--effort", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--fail-on", choices=["none", "high"], default="none",
                        help="Exit 4 when findings reach this severity. Off by default (§15).")
    parser.add_argument("--cache", action="store_true",
                        help="Reuse cached responses by prompt hash. Off by default (§14).")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--record", metavar="DIR", type=Path,
                        help="Write raw responses to DIR as test fixtures (§17)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Build and price the prompts, send nothing (§9)")
    parser.add_argument("--no-llm", action="store_true", help="Deterministic findings only")
    parser.add_argument("--max-input-tokens", type=int, default=DEFAULT_MAX_INPUT_TOKENS)
    parser.add_argument("--max-run-cost", type=float, default=0.50)
    parser.add_argument("--verbose", action="store_true", help="Per-call usage and timing to stderr")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    timings = Timings()

    try:
        with timings("parse"):
            diff = parse_diff(_read_input(args.diff))
    except DiffParseError as exc:
        print(f"error: could not parse diff: {exc}", file=sys.stderr)
        return EXIT_PARSE_ERROR
    except OSError as exc:
        print(f"error: could not read diff: {exc}", file=sys.stderr)
        return EXIT_PARSE_ERROR

    if not diff.has_reviewable_changes:
        # §15: exit 0 with valid JSON and a reason. The LLM is not called — never spend
        # money on an empty diff (invariant 6).
        print("No reviewable changes.", file=sys.stderr)
        _emit(args, _empty_review("The diff contains no added lines to review."))
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
    summary: object | None = None

    skip_llm = args.no_llm or not batches
    if not batches and not args.no_llm:
        # Every file was filtered out. Invariant 6 again: nothing to review, no call.
        print("No files eligible for LLM review; deterministic findings only.", file=sys.stderr)

    client = LLMClient(
        model=args.model,
        summary_model=args.summary_model,
        effort=args.effort,
        max_input_tokens=args.max_input_tokens,
        max_run_cost=args.max_run_cost,
        verbose=args.verbose,
        cache=ResponseCache(args.cache_dir, enabled=args.cache) if args.cache else None,
        record_dir=args.record,
    )

    if args.dry_run:
        return _dry_run(args, client, batches, filtered, deterministic, scan_result.suppressed)

    if not skip_llm:
        try:
            with timings("review_pass"):
                llm_findings, stats = _review_pass(client, batches, scan_result.suppressed, diff)
        except MalformedLLMResponse as exc:
            # §15: print the raw response verbatim and exit 2. No repair, no retry.
            print(f"error: {exc}", file=sys.stderr)
            print(exc.raw)
            return EXIT_MALFORMED_LLM_JSON
        except BudgetExceeded as exc:
            print(f"error: budget guard aborted the run: {exc}", file=sys.stderr)
            return EXIT_BUDGET
        except LLMError as exc:
            # Invariant 3: deterministic findings are still produced when the call fails.
            print(f"warning: review pass failed, continuing without it: {exc}", file=sys.stderr)
            skip_llm = True

    with timings("merge"):
        findings = merge_findings(deterministic, llm_findings)

    if not skip_llm:
        try:
            with timings("summary_pass"):
                raw = client.summarize(
                    build_summary_prompt(
                        [f.path for f in filtered.reviewable], filtered.excluded, findings
                    )
                )
                summary = parse_summary_response(raw)
        except MalformedLLMResponse as exc:
            print(f"error: {exc}", file=sys.stderr)
            print(exc.raw)
            return EXIT_MALFORMED_LLM_JSON
        except BudgetExceeded as exc:
            print(f"error: budget guard aborted the run: {exc}", file=sys.stderr)
            return EXIT_BUDGET
        except LLMError as exc:
            print(f"warning: summary pass failed, continuing without it: {exc}", file=sys.stderr)

    review = _assemble(findings, summary, filtered)
    with timings("render"):
        rendered = _render(args, review, filtered.exclusion_summary())
    _report_metrics(stats, filtered, client, timings, mask_result, args.verbose)
    _write(args, rendered)

    if args.fail_on == "high" and any(f.severity == "high" for f in review.findings):
        return EXIT_FAIL_ON
    return EXIT_OK


# --------------------------------------------------------------------------------------
# Stages
# --------------------------------------------------------------------------------------


def _review_pass(
    client: LLMClient,
    batches: list,
    suppressed: set[tuple[str, int]],
    diff: ParsedDiff,
) -> tuple[list[Finding], ValidationStats]:
    """Call 1 over every batch, validating each response against the parsed diff (§11).

    Validation happens per batch rather than once at the end so `hallucinated_file_count`
    attributes correctly: a file absent from *this* batch but present elsewhere in the diff
    is not a hallucination, it is the model citing something it legitimately saw earlier.
    """
    collected: list[Finding] = []
    stats = ValidationStats()

    for index, batch in enumerate(batches):
        prompt = build_review_prompt(batch, suppressed)
        raw = client.review(prompt, label=f"review-{index}")
        parsed = parse_review_response(raw)
        validated, batch_stats = validate_findings(parsed, diff)
        collected.extend(apply_confidence_caps(validated, batch))

        stats.unmappable_count += batch_stats.unmappable_count
        stats.hallucinated_file_count += batch_stats.hallucinated_file_count
        stats.hallucinated_files.extend(batch_stats.hallucinated_files)
        stats.unmappable_lines.extend(batch_stats.unmappable_lines)

    return collected, stats


def _dry_run(args, client: LLMClient, batches, filtered, deterministic, suppressed) -> int:
    """`--dry-run`: build and price every prompt, send nothing (§9).

    The summary prompt is built from deterministic findings alone, since the review pass
    that would add to them never runs. It is representative of shape and roughly of size,
    which is what a cost estimate needs.
    """
    calls = [
        (f"review-{i}", build_review_prompt(b, suppressed), args.model, REVIEW_MAX_TOKENS)
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


def _assemble(findings: list[Finding], summary, filtered) -> Review:
    note = filtered.exclusion_summary()
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
    risk = overall_risk(findings)
    counts = f"{len(findings)} finding(s)"
    detail = f" {note}." if note else ""
    return Review(
        summary=(
            f"Deterministic review only (no model summary available). {counts} across "
            f"{len({f.file for f in findings})} file(s).{detail}"
        ),
        overall_risk=risk,
        findings=findings,
        pr_comment=(
            f"Automated security review found {counts}. This run produced deterministic "
            "findings only; treat the coverage as partial and review manually."
        ),
        no_findings_reason=None if findings else "No deterministic security findings.",
    )


def _report_metrics(
    stats: ValidationStats,
    filtered,
    client: LLMClient,
    timings: Timings,
    mask_result,
    verbose: bool,
) -> None:
    """§11: both counters go to stderr on every run and into the CI job output."""
    print(
        f"unmappable_count={stats.unmappable_count} "
        f"hallucinated_file_count={stats.hallucinated_file_count}",
        file=sys.stderr,
    )
    if note := filtered.exclusion_summary():
        print(note, file=sys.stderr)
    if verbose:
        # Masking is the one stage whose success is invisible in the output: a run that
        # masked nothing and a run whose masking silently no-opped look identical.
        print(f"masked_line_count={mask_result.masked_line_count}", file=sys.stderr)
        print(timings.report(), file=sys.stderr)
    if verbose and client.usages:
        print(client.usage_summary(), file=sys.stderr)
    if verbose and stats.unmappable_lines:
        print(f"unmappable lines: {stats.unmappable_lines}", file=sys.stderr)
    if verbose and stats.hallucinated_files:
        print(f"hallucinated files: {stats.hallucinated_files}", file=sys.stderr)


# --------------------------------------------------------------------------------------
# Input and output
# --------------------------------------------------------------------------------------


def _read_input(source: str) -> str:
    """A path or `-` for stdin. Never shells out to git (§14)."""
    if source == "-":
        return sys.stdin.read()
    return Path(source).read_text()


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


def _render(args, review: Review, excluded_note: str = "") -> dict[str, str]:
    """Produce every artifact `--format` asked for, keyed by extension."""
    artifacts: dict[str, str] = {}
    if args.format in ("markdown", "both"):
        artifacts["md"] = render_markdown(review, excluded_note)
    if args.format in ("json", "both"):
        artifacts["json"] = _to_json(review) + "\n"
    return artifacts


def _write(args, artifacts: dict[str, str]) -> None:
    """Write to `--output` or stdout.

    `--format both` needs two destinations, and CI wants both as named artifacts (§18), so
    the JSON takes the output path with a `.json` suffix. Without `--output` both go to
    stdout in a fixed order — Markdown first, since that is the one a human is reading.
    """
    if not args.output:
        print("\n".join(artifacts[key].rstrip() for key in ("md", "json") if key in artifacts))
        return

    path = Path(args.output)
    if "md" in artifacts:
        path.write_text(artifacts["md"])
    if "json" in artifacts:
        json_path = path if "md" not in artifacts else path.with_suffix(".json")
        json_path.write_text(artifacts["json"])


def _emit(args, review: Review) -> None:
    """Render and write in one step, for the paths that return before the full pipeline."""
    _write(args, _render(args, review))


# --------------------------------------------------------------------------------------
# Timing
# --------------------------------------------------------------------------------------


class Timings:
    """Wall-clock time per pipeline stage, reported under `--verbose` (§14).

    Deliberately wall-clock rather than CPU time: the number that matters to a reviewer
    waiting on a run is how long the API calls took, and those are almost entirely spent
    blocked on the network. Insertion order is preserved so the report reads as the
    pipeline order, which is what makes an outlier stage obvious at a glance.
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

    def report(self) -> str:
        """`timings: parse 1.2ms · mask 8.4ms · … · total 2.31s`."""
        if not self._elapsed:
            return "timings: (none recorded)"
        stages = " · ".join(f"{name} {_duration(s)}" for name, s in self._elapsed.items())
        return f"timings: {stages} · total {_duration(self.total)}"


def _duration(seconds: float) -> str:
    return f"{seconds * 1000:.1f}ms" if seconds < 1 else f"{seconds:.2f}s"


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
