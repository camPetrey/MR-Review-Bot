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
```

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

Two things live outside the pipeline: `scripts/bench.py` (local timing harness, no network)
and `.github/workflows/` (§18). Neither is a stage; neither is imported by one.

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

## Do not

Each is a reasonable instinct the spec already rejected. If one looks right, argue with the
spec section — don't implement it.

- Hand-roll diff parsing or secret detection. Wrap `unidiff` and `detect-secrets`.
- Feed deterministic hits to the LLM as hints. Suppression list only. (§12)
- Add retries, fallback models, or error recovery around the API call.
- Let the LLM report `hardcoded_secrets`. Deterministic-only. (§5)
- Cap or truncate findings in the renderer. (§13)
- Shell out to `git`. Input is a file path or stdin. (§14)
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
- Performance is guarded structurally, never by wall clock — assert the call count that was
  fixed, not a millisecond threshold. A timing assertion on a shared CI runner is a flaky
  test, and a flaky test gets ignored within a week. `make bench` is where the numbers live.

## Workflow

- Feature branches only. Never commit to `main`.
- One PR per milestone, with test evidence.
- SPEC.md is amended by PR alongside the code that resolved the question.

## Spec sections worth opening mid-task

§5 masking · §6 the 12 rules · §7 filtering and packing · §9 budget guards ·
§10 output schema · §11 line validation · §12 merge and confidence · §15 exit codes