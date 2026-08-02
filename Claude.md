# Security PR Review Bot

CLI tool: unified Git diff in, schema-validated security findings out. Python 3.12, Anthropic API.

`SPEC.md` is the source of truth for what and why. This file is how to work here.
Do not restate spec decisions here — cite the section.

<!-- Seeded by hand day 0. Grow by the second-mistake rule. Do not re-run /init. -->

## Commands

```
make test        # pytest, no network
make lint        # ruff
make bench       # time the deterministic stages, no network
make dry-run     # build and price the prompts, send nothing
make smoke       # ONE real API call pair. Manual only. Never in CI.
make record      # overwrite tests/fixtures/ from live responses
make refresh-real-diffs   # re-fetch real_diffs/ from GitHub. Manual only. (§25)
make review-pr PR=o/r#1   # review a real PR. Live API calls. Manual only. (§23)
```

`--pr` needs `gh` authenticated (`gh auth login`, or `GH_TOKEN` in `.env`). `owner/repo#123`
needs no quoting — `#` mid-word is not a comment in any shell. A *leading* `#` is, so the
bare form is `--pr '#123'` in a script.

Setup (no venv is committed):

```
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

Single test / single lint target:

```
.venv/bin/pytest tests/test_role_scanner.py::test_some_case
.venv/bin/ruff check src/review_bot/cli.py
```

## Architecture

All stages are implemented as of M5. Pipeline order and module ownership (SPEC.md §4):

```
diff -> diff_parser -> secret_masker -> role_scanner -> prompt_builder -> llm_client -> schema -> renderer -> output
```

`cli.py` orchestrates; every other module is one pipeline stage and owns exactly one thing
(diff parsing, masking, deterministic rules, prompt assembly, the API call, validation/merge,
Markdown rendering). Cross-stage logic belongs in the stage that owns the concern, not in
`cli.py` — see the "Ask first" rule below before adding a new module.

**Two modules attach to the pipeline without being stages of it (§4, M7).** `github_source.py`
is an input adapter in front of `diff_parser`: it turns a PR reference into the same diff text
a file would have, and nothing downstream can tell the difference. `terminal.py` is a second
projection of `schema.py`'s output, a sibling of `renderer.py` — it imports `group_by_file`
and `severity_counts` from it rather than reimplementing them, because two renderers that
could disagree about ordering would mean neither artifact is authoritative. The pipeline is
still seven stages long. Attach at an existing boundary before lengthening it.

`terminal.py` also owns the **stderr run diagnostics** (`RunDiagnostics`, §24), which are not
a projection of `Review` but are terminal presentation, and belong where `build_console`, the
width cap, and the palette already live. `cli.py` decides *what* to report and passes data,
never formatted lines; the module decides how it looks and whether stderr is a terminal at
all. Adding a number to the block means adding a field there, not a `print` in `cli.py`.

Two things live outside the pipeline entirely: `scripts/` (`bench.py`, the local timing
harness, and `refresh_real_diffs.py`, the only thing in the repo that reaches github.com) and
`.github/workflows/` (§18). Neither is a stage; neither is imported by one.

**Cost lives at stage boundaries, not in the loops.** The masker's plugin configuration is
entered once per *diff*, not once per file — that one change halved the stage. Before
optimizing anything here, run `make bench` and read the per-file column: flat is correct,
rising means fixed setup is being paid per file.

## Invariants

Correctness guarantees, not preferences. Breaking one is a bug even if tests pass.

1. **Mask before the network.** `secret_masker` runs on the parsed diff, before `prompt_builder`.
   No raw diff content reaches the API.
2. **No line number renders that isn't in the parsed diff.** Unmappable → `line: null`.
   Bad file → reject. (§11)
3. **Deterministic findings bypass the LLM entirely** and must still be produced when the API
   call fails. (§12)
4. **Malformed LLM JSON → print raw, exit 2.** No auto-repair, no retry. (§15)
5. **Prompts are byte-stable.** Sorted lists, `sort_keys=True`, no timestamps or UUIDs. (§8)
6. **Never call the API on an empty or fully-filtered diff.** Exit 0.
7. **Raw secret values never appear in output.** Asserted in tests.
8. **Every diff- or model-sourced string reaches `rich` as a `Text`, never a `str`.** Rich
   parses `[...]` as markup, so a `str` carrying `[MASKED_AWS_KEY]` renders as *nothing* —
   silently, which makes it invariant 7 failing with no error and no leak. (§24)

## Do not

Each is a reasonable instinct the spec already rejected. If one looks right, argue with the
spec section — don't implement it.

- Hand-roll diff parsing or secret detection. Wrap `unidiff` and `detect-secrets`.
- Suppress a Tier 2 hit, or feed a Tier 1 hit to the LLM as something to confirm. Tier 1 is
  certain and stays suppression-only; Tier 2 is the candidate list, asked to be confirmed
  independently, not nudged toward agreement. (§12)
- Add retries, fallback models, or error recovery around the API call.
- Let the LLM report `hardcoded_secrets`. Deterministic-only. (§5)
- Cap or truncate findings in *either* renderer. (§13)
- Reconstruct a diff locally — no `git diff BASE...HEAD`. Input is a file, stdin, or a PR
  fetched through `gh` by `github_source`. (§14, §23)
- Reimplement GitHub auth or call `api.github.com` directly from `src/`. Wrap `gh`. (§23)
- Post anything back to a pull request. `--pr` reads; it does not write. (§1, §23)
- Add a second `subprocess.run` to `github_source`. One boundary, so tests mock one
  function and the no-network rule stays enforced rather than stated. (§23)
- Implement anything from §22 without asking.

## Conventions

- pydantic v2 syntax only. No `@validator`, `.parse_obj`, or `class Config`.
- One module per pipeline stage. Say so before creating a helper module.
- Internal-only fields are `_`-prefixed and stripped before output.

## Ask first

Adding a dependency. Adding a module. Changing an exit code or the schema. Anything from §22.

## Testing

- Unit tests never touch the network. Mocked LLM only.
- The contract test — every fixture validates against the current schema — is the highest-value
  test in the suite. Do not skip or xfail it to get CI green.
- New deterministic rule → new case in `test_role_scanner.py`, same commit.
- `clean_but_suspicious.diff` must produce zero Tier 1 hits. False-positive canary.
- `real_diffs/` counts are measured, not aspirational. A changed count is a real signal —
  find out what moved before updating `MANIFEST.json`. Four of the five produce zero
  deterministic findings, and keeping it that way is the point. (§25)
- Performance is guarded structurally, never by wall clock — assert the call count that was
  fixed, not a millisecond threshold. A timing assertion on a shared CI runner is a flaky
  test, and a flaky test gets ignored within a week. `make bench` is where the numbers live.

## Workflow

- Feature branches only. Never commit to `main`.
- One PR per milestone, with test evidence.
- SPEC.md is amended by PR alongside the code that resolved the question.

## Spec sections worth opening mid-task

§5 masking · §6 the 12 rules · §7 filtering and packing · §9 budget guards ·
§10 output schema · §11 line validation · §12 merge and confidence · §15 exit codes ·
§23 GitHub PR input · §24 terminal output · §25 real diffs