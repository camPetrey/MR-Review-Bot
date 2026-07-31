# Security PR Review Bot

A CLI tool that reads a unified Git diff, identifies suspicious code changes, and produces
reviewer-ready comments.

**It assists a human reviewer. It does not gate merges and does not replace security
review.** Every exit code signals whether the *tool* worked, not how bad the findings were.

See `SPEC.md` for the full specification and `Claude.md` for working conventions.

## Install

```
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Set `ANTHROPIC_API_KEY` for anything that calls the API. The deterministic layer
(`--no-llm`) needs no key.

## Usage

```
review-bot [DIFF_PATH | -] [options]
```

```bash
# Review a diff file, Markdown to stdout
review-bot changes.diff

# Review the current branch against main. The tool never shells out to git — you pipe it in
git diff origin/main...HEAD | review-bot -

# Both artifacts from one run: review.md and review.json
review-bot changes.diff --format both --output review.md

# Deterministic rules only. No network, no key, no cost
review-bot changes.diff --no-llm

# Build and price the prompts without sending them
review-bot changes.diff --dry-run
```

| Flag | Default | Purpose |
|---|---|---|
| `--format {markdown,json,both}` | `markdown` | Output format. JSON is the source of truth. |
| `--output PATH` | stdout | Write to a file. With `both`, JSON goes to `PATH.json`. |
| `--model ID` | `claude-sonnet-5` | Override the review model |
| `--effort {low,medium,high}` | `medium` | Effort level |
| `--fail-on {none,high}` | `none` | Exit 4 on findings at/above this severity |
| `--summary-model ID` | `claude-haiku-4-5-20251001` | Override the summary model |
| `--cache` | off | Reuse responses by prompt hash |
| `--cache-dir PATH` | `.review_bot_cache` | Where `--cache` reads and writes |
| `--record DIR` | off | Overwrite test fixtures from live responses |
| `--dry-run` | off | Build the prompts, price them, send nothing |
| `--no-llm` | off | Deterministic findings only |
| `--max-input-tokens N` | 8000 | Per-call budget guard |
| `--max-run-cost N` | 0.50 | Per-run budget guard, in dollars |
| `--verbose` | off | Per-call usage and per-stage timings to stderr |

### Exit codes

| Code | Condition |
|---|---|
| `0` | Ran successfully. Findings present or absent — both are success. A failed API call is also `0`: the deterministic findings still stand. |
| `1` | The diff failed to parse |
| `2` | The model returned malformed JSON. The raw response is printed verbatim; there is no auto-repair and no retry. |
| `3` | A budget guard aborted the run |
| `4` | Findings met `--fail-on` (only reachable when the flag is set) |

## Demo

```
make demo
```

Runs the reviewer over three sample diffs and prints what a reviewer would see on the PR.
**No API key, no network call, no cost** — every response is replayed from the committed
response cache (`.review_bot_cache/`), which is why this works on a fresh clone before
anything is configured. Prompts are byte-stable, so the same diffs replay the same review.

The three diffs are the whole argument for the tool in order:

| Diff | What it demonstrates |
|---|---|
| `auth_bypass.diff` | A permission check removed behind a query parameter — a logic flaw that has to be *read*, not matched. This is the half of the review the deterministic rules cannot do. |
| `secrets_and_logging.diff` | The deterministic layer: found with no network call, and the credential masked **before** the prompt exists, so no raw value can reach the API or the output. |
| `clean_but_suspicious.diff` | Code that reads alarming and is fine. The false-positive canary — a reviewer who gets paged for this stops reading the reviewer at all. |

The demo aborts rather than run cold: a missing cache entry would silently degrade to
deterministic-only findings, which is correct behaviour for the tool and a dishonest demo.
Rebuild the cache with `make record-cache` (needs a key) after changing a prompt or a
sample diff.

### Where it sits in the review workflow

```bash
git diff origin/main...HEAD | review-bot - --format both --output review.md
```

That is the same command `.github/workflows/review.yml` runs on every pull request. The job
uploads `review.md` and `review.json` as build artifacts and writes the Markdown to the job
summary. It is `continue-on-error`: it never posts a comment and never blocks a merge. Fork
PRs get no API key and fall back to `--no-llm` rather than failing — partial coverage,
stated as partial, beats no review.

## How it works

```
diff -> diff_parser -> secret_masker -> role_scanner -> prompt_builder -> llm_client -> schema -> renderer
```

Two detectors run independently. **Deterministic rules** (13 rule ids across 7 categories)
never touch the network, so they are produced even when the API call fails. The **LLM pass**
reviews what the rules cannot — most importantly missing input validation, which no regex
can detect. Where the two agree on the same file, line and category, confidence is promoted
to `high`.

Masking runs on the parsed diff **before** anything reaches the network. Secret values are
replaced in place with typed placeholders (`[MASKED_AWS_KEY]`, `[MASKED_DB_URL]`, …), so no
raw credential ever enters a prompt or an output. This is asserted in the test suite, not
assumed.

Every line number the model reports is validated against the set of lines the diff actually
contains. A line outside that set degrades to a file-level finding; a file the diff never
touched is dropped. `unmappable_count` and `hallucinated_file_count` go to stderr on every
run.

## Development

```
make test      # pytest, never touches the network
make lint      # ruff
make bench     # time the deterministic stages against synthetic diffs
make dry-run   # build and price every prompt, send nothing
make demo      # replay the recorded cache over 3 sample diffs. No key, no cost.
make smoke     # ONE real API call pair. Manual only, never in CI.
make record    # overwrite tests/fixtures/ from live responses
make record-cache  # rebuild the demo cache from live responses
```

CI runs lint, tests and a dry run on every PR (`test.yml`), and runs the bot against the
PR's own diff (`review.yml`). The review job is `continue-on-error` and never blocks a
merge. Fork PRs get no API key and fall back to `--no-llm` rather than failing.

## Known limitations

These are real boundaries, not bugs to be filed.

1. **Assists, does not replace, human security review.** Advisory only; never blocks a merge.
2. **Cannot distinguish a live credential from a test fixture** beyond a path heuristic.
   Masking destroys the information that judgment would need, by design. Rotation is
   therefore always recommended.
3. **Cannot detect the absence of input validation deterministically.** You cannot regex
   something that is not there. `input_validation` is LLM-only and consequently the least
   reliable category.
4. **Cross-file findings are unreliable.** Files are packed per call, so auth removed in one
   file and exploited in another may not connect. The summary pass partially compensates.
5. **No taint analysis.** The tool detects that a dangerous sink was introduced, not that
   attacker-controlled data reaches it.
6. **Roughly 90% run-to-run stability, not 100%.** Prompts are byte-stable by construction,
   but floating-point non-associativity in batched inference and provider-side model updates
   mean identical input can still produce a slightly different review.
7. **Diff-only context.** No knowledge of surrounding code, project conventions, or existing
   mitigations, so it will occasionally flag something already handled elsewhere.
8. **Prompt injection is detected, not prevented.** The diff is untrusted, attacker-controlled
   input. A sufficiently novel injection may still influence the review; any detected attempt
   is surfaced as a finding so the reviewer knows to look manually.
9. **Lockfiles get only a "dependency changed" flag**, not a vulnerability assessment. Pair
   this with a real SCA tool.

## Cost

`claude-sonnet-5` is priced at $2/$10 per MTok through **2026-08-31**; standard $3/$15
pricing resumes 2026-09-01. `claude-haiku-4-5-20251001` handles the summary pass at $1/$5.
Both model IDs are pinned.

Measured across all five sample diffs (two calls each):

| | Per run | All five |
|---|---|---|
| `--dry-run` estimate | $0.094 | $0.47 |
| Actual | $0.004 – $0.013 | **$0.035** |

The estimate is 7–25× high **by design**: `--max-run-cost` is checked *before* the request,
where the real output length is unknowable, so a call is priced at its full `max_tokens`. A
guard that can under-estimate is not a guard. The consequence to know about is that the
budget is spent in *estimated* dollars — the default `--max-run-cost 0.50` trips after
roughly ten review calls, so a diff large enough to pack into that many batches can abort a
run that would have cost pennies. Raise `--max-run-cost` when that happens.

Prompt caching cuts the review call's input further: the system prompt is byte-stable, so it
is written once per session and read on every subsequent call.
