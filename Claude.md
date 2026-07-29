# Security PR Review Bot

CLI tool: unified Git diff in, schema-validated security findings out. Python 3.12, Anthropic API.

`SPEC.md` is the source of truth for what and why. This file is how to work here.
Do not restate spec decisions here — cite the section.

<!-- Seeded by hand day 0. Grow by the second-mistake rule. Do not re-run /init. -->

## Commands

```
make test        # pytest, no network
make lint        # ruff
make smoke       # ONE real API call. Manual only. Never in CI.
```

<!-- Aspirational until M1 lands the Makefile. Make true or delete by end of day 2. -->

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

## Workflow

- Feature branches only. Never commit to `main`.
- One PR per milestone, with test evidence.
- SPEC.md is amended by PR alongside the code that resolved the question.

## Spec sections worth opening mid-task

§5 masking · §6 the 12 rules · §7 filtering and packing · §9 budget guards ·
§10 output schema · §11 line validation · §12 merge and confidence · §15 exit codes