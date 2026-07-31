# Security PR Review Bot — Specification

**Platform:** GitHub Repo but for Gitlab

---

## 1. Purpose and scope

A CLI tool that reads a unified Git diff, identifies suspicious code changes, and produces reviewer-ready comments.

**In scope:** diff parsing, deterministic pre-screening, secret masking, LLM security review, schema-validated JSON output, Markdown rendering, GitHub Actions CI.

**Out of scope:** web UI, posting comments to GitHub PRs via API, repository-wide scanning, taint analysis, cross-PR state.

**Non-negotiable framing:** the tool assists human reviewers. It does not gate merges and does not replace security review.

---

## 2. Fixed technical decisions

| Decision | Choice | Source |
|---|---|---|
| Language | Python 3.12 | Brief |
| LLM provider | Anthropic API | Brief |
| Review model | `claude-sonnet-5`, effort `medium` | This spec (§9) |
| Summary model | `claude-haiku-4-5-20251001` | This spec (§9) |
| Interface | CLI only | Brief |
| Diff parser | `unidiff` (PyPI) | Brief |
| Secret masker | `detect-secrets` (Yelp), wrapped | Brief |
| Schema validation | `pydantic` v2 | Brief |
| Sample diffs | 5 hand-written, ~30 lines each | Brief |
| LLM error handling | Log and fail visibly, no auto-repair | Brief |
| Budget ceiling | $20 total | Brief |

---

## 3. Threat model

The diff is **untrusted, attacker-controlled input**. A pull request author can write arbitrary content into code, comments, and strings, and that content flows into an LLM prompt.

Three consequences drive the design:

1. **Secrets must never leave the process.** Masking happens before anything reaches the network.
2. **Prompt injection is an expected input, not an edge case.** The diff is wrapped as data, scanned for injection patterns, and any hit is reported as a finding in its own right — an injection attempt in a PR is a security event worth surfacing to a reviewer.
3. **LLM output is untrusted too.** Every finding is validated against the parsed diff before it can render. The model cannot cause the tool to cite a line that does not exist.

---

## 4. Pipeline

```
diff
  -> diff_parser        parse files, hunks, added lines, post-file line numbers
  -> secret_masker      typed masking, pre-network
  -> role_scanner       deterministic rules + injection patterns
  -> prompt_builder     filter, pack, build byte-stable prompt
  -> llm_client         budget guard, Anthropic call, caching
  -> schema             pydantic validation, line validation, merge, dedupe
  -> renderer           Markdown from JSON
  -> output
```

### Module responsibilities

| File | Owns |
|---|---|
| `cli.py` | Argument parsing, stdin/file input, exit codes, orchestration |
| `diff_parser.py` | `unidiff` wrapper; produces files, hunks, added lines with post-file line numbers |
| `secret_masker.py` | `detect-secrets` wrapper; typed placeholder substitution |
| `role_scanner.py` | All deterministic rules (§6) and prompt-injection pattern detection |
| `prompt_builder.py` | File filtering, bin-packing, suppression list, byte-stable prompt assembly |
| `llm_client.py` | Anthropic SDK calls, prompt caching, budget pre-flight, `--cache`, `--record` |
| `schema.py` | Pydantic models, line validation, finding merge, dedupe, confidence promotion |
| `renderer.py` | JSON → Markdown |

**[DEVIATION]** The brief's repo layout omits `prompt_builder.py` while its own pipeline diagram contains a "prompt builder" box, and the brief states "each box in the data flow maps to one file under `src/`." Adding the file resolves the brief against itself. Filtering, packing, and suppression-list construction are non-trivial logic that would otherwise bloat `llm_client.py` and become hard to unit test.

---

## 5. Masking

Runs before any network call, on the parsed diff.

- Wrap `detect-secrets`; do not reimplement detection.
- Emit **typed** placeholders: `[MASKED_AWS_KEY]`, `[MASKED_PRIVATE_KEY]`, `[MASKED_DB_URL]`, `[MASKED_TOKEN]`, `[MASKED_KEY]`.
- Attach a path signal to each masked finding: `test` if the file path matches `tests/`, `test_*`, `conftest.py`, `fixtures/`, `*_test.*`; otherwise `src`.
- Substitution is in-place within the line, preserving line numbers and diff alignment.

**[DEVIATION]** The brief's prompting section names `[MASKED_KEY]` and `[MASKED_TOKEN]`. Typed placeholders are a superset, consistent with the brief's intent. Rationale: an untyped `[MASKED]` gives the model nothing to reason about and produces uniform high-severity findings on test fixtures. The type and path signal carry enough context for useful severity assignment without carrying the value.

### Resolving the masking / `hardcoded_secrets` tension

The brief requires masking before the LLM step *and* lists `hardcoded_secrets` as an LLM review category with a required `evidence` field. These conflict: a masked value cannot be evidenced without unmasking it.

**Resolution:** `hardcoded_secrets` is a **deterministic-only** category. The masker emits the finding directly. The LLM never reports this category and is instructed not to.

- `evidence` reads: `` `AWS_ACCESS_KEY` assigned a literal value at line 42 (masked as [MASKED_AWS_KEY]) ``
- `severity`: `high` for `src` paths, `low` for `test` paths
- `confidence`: taken from the `detect-secrets` verdict
- `recommendation`: always includes rotation, because the tool cannot verify whether the credential is live

**Accepted limitation:** the tool cannot distinguish a live production key from a test fixture beyond the path heuristic. That judgment requires the value, and the value is destroyed by design. Documented in README.

---

## 6. Deterministic detection layer

Two tiers, because a false-positive deterministic hit that suppresses LLM review would silently blind the tool on that line.

### Tier 1 — High precision (suppresses LLM review of that line)

Near-zero ambiguity about *what* was matched.

| Category | Rule |
|---|---|
| `hardcoded_secrets` | `detect-secrets` hit (entropy + plugin rules) |
| `dependency_change` | Path match on `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `go.mod`, `go.sum`, `Gemfile*`, `Cargo.toml`, `Cargo.lock` |
| `crypto_misuse` | Literal match on `hashlib.md5`, `hashlib.sha1`, `MD5`, `SHA1`, `DES`, `RC4`, `ECB`, `random.random()`, `random.randint(`, `Math.random()`, hardcoded IV assignment |

### Tier 2 — Signal (does NOT suppress; LLM reviews independently)

Pattern is real but intent is ambiguous. Emitted at `confidence: low`.

| Category | Rule |
|---|---|
| `injection` | Sinks: `eval(`, `exec(`, `os.system(`, `subprocess.*(shell=True`, `.execute(` receiving an f-string / `%` / `+` / `.format(` |
| `sensitive_logging` | Log call (`log*.`, `print(`, `console.log`) whose arguments contain `token`, `password`, `passwd`, `secret`, `session`, `authorization`, `cookie`, `api_key`, `ssn` |
| `unsafe_redirects` | `redirect(` with a non-literal argument; params named `next`, `return_url`, `redirect_uri`, `callback`, `continue`; dynamic `Location` header assignment |
| `auth_perms` | **Removed** (`-`) lines containing `is_admin`, `is_staff`, `@requires_role`, `@permission_required`, `@login_required`, `current_user.role`, `has_perm`, `check_owner`, `.is_authenticated` |
| *(injection guard)* | Prompt-injection phrases in added lines: `ignore previous`, `ignore all`, `disregard`, `you are now`, `system prompt`, `AI reviewer`, `pre-approved`, `return no findings`, `end of instructions` |

`input_validation` has **no deterministic rule**. You cannot regex the absence of validation. It is LLM-only, and the README states this explicitly as a documented capability boundary.

**Rule count: 12 across 7 categories.** M3 requires at least 4.

### Prompt-injection findings

An injection-pattern hit produces a finding with `category: injection`, `severity: high`, `confidence: medium`, and a recommendation to review the change manually because automated review may have been influenced. It does **not** suppress LLM review of the line — the reviewer should see both the injection attempt and whatever the model made of it.

---

## 7. Filtering and packing

### Filter (before any LLM call)

Excluded from LLM review entirely:

- Binary files
- Files with no added lines (pure deletions, pure renames, mode changes)
- Lockfiles and dependency manifests — these get a **Tier 1 deterministic** `dependency_change` finding instead; sending 4,000 lines of `package-lock.json` to an LLM buys nothing
- Generated/vendored paths: `vendor/`, `node_modules/`, `dist/`, `build/`, `*.min.js`, `*.generated.*`, `*_pb2.py`

Excluded files are counted and reported in the output header so the reviewer knows what was skipped.

### Packing

- **Bin-pack whole files** into calls up to a token budget (default 8,000 input tokens per call). Files are never split unless a single file exceeds the budget alone.
- If one file exceeds budget: split by hunk with 10 lines of surrounding context, and mark every finding from those chunks with `confidence` capped at `medium`.
- **File order is sorted lexicographically** before packing, for byte-stable prompts (§9).

**Accepted limitation:** cross-file findings are lost — auth middleware removed in one file, exploited by a route in another. Partially recovered by the summary pass (§8). Documented in README.

---

## 8. LLM calls

Two calls per run.

### Call 1 — Review pass

- Model: `claude-sonnet-5`, effort `medium`
- Input: system prompt + masked, packed diff + suppression list
- Output: `findings[]` only

The suppression list names `(file, line)` pairs already covered by Tier 1 rules, with the instruction: *these lines are already reported; do not re-report them; look for what they missed.* This is **suppression, not hinting** — the model is told to stay away, not invited to confirm. Tier 2 hits are **not** in the suppression list.

### Call 2 — Summary pass

- Model: `claude-haiku-4-5-20251001`
- Input: file list + accumulated findings only. **Never the diff.**
- Output: `summary`, `overall_risk`, `pr_comment`

Pure summarization, which is Haiku's strength, and it recovers the cross-file narrative lost to per-file packing at negligible cost.

### Determinism

- **~~Temperature 0.~~ Not available. [AMENDED M4]** The intent was right — this is an accuracy task, not a generation task — but `claude-sonnet-5` removed the sampling parameters. `temperature`, `top_p`, and `top_k` are rejected with a 400 rather than defaulted, so no request may carry them. The intended behaviour is the model's only behaviour, and this section's own next bullet already identified the larger lever, which is unaffected. Asserted in `test_llm_client.py::test_no_sampling_parameters_are_sent` so it cannot regress via `--model`.
- **Byte-stable prompt construction** — now the *only* lever, and always the larger one. Prompt bytes must not drift between runs:
  - Sort file lists lexicographically
  - Sort deterministic findings by `(file, line, category)` before serialization
  - No timestamps, run IDs, or UUIDs anywhere in the prompt (they belong in the *output*)
  - Serialize with `json.dumps(..., sort_keys=True)`
- **Prompt caching** on the system prompt. It is byte-identical across every call by construction; cache reads bill at 0.1x input, writes at 1.25x.
  - **[AMENDED M4]** The minimum cacheable prefix on `claude-sonnet-5` is **1024 tokens, not 512** (512 is Opus 5's figure). A ~800-token system prompt would therefore never have cached — silently, with no error, just `cache_creation_input_tokens: 0` — and the cost model above assumes it does. The review system prompt is written past that threshold and `test_prompt_builder.py::test_system_prompt_clears_the_cache_minimum` fails if it drops back under.

**Residual variance is accepted and documented.** Temperature 0 is not a determinism guarantee — floating-point non-associativity in batched inference and provider-side model updates mean roughly 90% run-to-run stability, not 100%.

Rejected: run-twice-and-intersect. It doubles cost and cuts recall, trading true positives for the appearance of consistency.

### Model selection 

| **Sonnet 5 (medium)** | **$10.68** | **Selected** |

Sonnet 5 is $2/$10 per MTok through 2026-08-31; standard $3/$15 resumes 2026-09-01. The project completes before that date. **Pin the model ID and note the date in README.**

Three reasons beyond cost:

**Estimated total spend: $8–12 of the $20 ceiling**, leaving margin for M4 tuning re-runs.

---

## 9. Budget controls

Lives in `llm_client.py`.

- **Pre-flight token estimate** before every call. Abort loudly if a single call exceeds `--max-input-tokens` (default 8,000) or a run exceeds `--max-run-cost` (default $0.50).
- **`--dry-run`**: build and print the prompt, estimate token count and cost, send nothing.
- **Log `usage` per call** — input, output, cache read/write tokens — to stderr.

No persisted cross-run total. Cross-run state is a file-locking problem this project does not need, and the realistic failure is one runaway diff, not slow drift.

---

## 10. Output schema

JSON is the source of truth. Markdown is rendered from it. Schema is exactly as the brief specifies:

```json
{
  "summary": "Short overall security review summary",
  "overall_risk": "low | medium | high",
  "findings": [
    {
      "file": "src/review/login.py",
      "line": 42,
      "category": "auth_perms | input_validation | injection | hardcoded_secrets | sensitive_logging | unsafe_redirects | dependency_change | crypto_misuse",
      "severity": "low | medium | high",
      "confidence": "low | medium | high",
      "evidence": "Quote or paraphrase of the changed lines or context",
      "risk": "Why this matters",
      "recommendation": "Specific fix or PR question"
    }
  ],
  "pr_comment": "Concise comment suitable for a PR discussion",
  "no_findings_reason": "Optional explanation when no security findings"
}
```

**Internal-only fields**, stripped before output, used for tuning analysis:

- `_source`: `deterministic` | `llm` | `both`
- `_rule_id`: which Tier 1/2 rule fired
- `line: null` permitted internally for file-level findings (§11)

---

## 11. Line-number validation

**Requirement: a line number that does not exist in the diff must never reach the reviewer.** This is a correctness guarantee, enforced structurally.

`diff_parser.py` produces, per file, the exact set of post-file line numbers for added lines. `schema.py` validates every LLM finding against that set.

| Case | Action |
|---|---|
| `line` is in the added-line set for that `file` | Accept |
| `line` is not in the set, `file` is valid | **Degrade to file-level**: set `line: null`, render as "file-level finding", increment `unmappable_count` |
| `file` is not in the diff | Reject entirely, increment `hallucinated_file_count` |

Both counters are emitted to stderr on every run and included in the CI job output.

**[AMENDED M4] This table governs LLM findings only.** Deterministic findings are not validated against the added-line set, and must not be: the `auth_perms` rule's evidence is a line that no longer exists, so `role_scanner` anchors it to the nearest surviving post-image line — usually the context line the removed check used to guard. That is a real destination for the reviewer and the most useful one available. The guarantee this section exists to make still holds, and is the stronger reading of it: **no finding renders a line number absent from the post-image lines the diff shows.** Added-set membership is the tighter rule applied to the model, because a model citing a line it was never shown is a hallucination, whereas an anchor is a deliberate, tested placement. Asserted over every emitted finding in `test_cli.py::test_no_line_number_renders_that_is_not_in_the_diff`.

**`unmappable_count` is a tuning metric, not an accepted condition.** The target is zero. If M4 tuning cannot drive it below ~5% of findings, the prompt is wrong — the fix is prompt work (echoing the valid line numbers into the prompt alongside each line of diff), not tolerance.

---

## 12. Finding merge and confidence

Deterministic findings go **straight into `findings[]`, bypassing the LLM entirely.** If the API call fails, times out, or returns malformed JSON, deterministic findings are still produced. The highest-confidence signal never depends on a network call.

Rejected: feeding deterministic hits to the LLM as hints. Three reasons — it anchors the model into confirming bad regex matches, it couples the strongest signal to a network call, and it makes `role_scanner.py` untestable in isolation, which the brief's testing requirements demand.

**Merge rules**, applied in `schema.py`:

1. Dedupe on `(file, line, category)`.
2. On conflict, the deterministic finding's `category`, `file`, and `line` win.
3. **Agreement promotes confidence.** If a Tier 2 deterministic hit and an independent LLM finding land on the same `(file, line, category)`, set `confidence: high` and `_source: both`. Two independent detectors concurring is real evidence.
4. On merge, keep the LLM's `risk` and `recommendation` (better prose) and the deterministic `evidence` (verifiable).

---

## 13. Rendering

`renderer.py`, JSON → Markdown.

- **No cap on findings.** Hiding a real finding to save screen space is the worse failure. Noise is fixed by tuning the rules, not by truncation.
- **Group by file** (per M5), sorted lexicographically.
- **Within each file, sort by severity** (high → low), then confidence (high → low), then line number.
- **Severity-count header** before the body: `3 high · 7 medium · 2 low across 4 files` — so the reviewer triages before scrolling.
- **Skipped-file note**: `12 files excluded from LLM review (lockfiles, binary, generated)`.
- File-level findings (`line: null`) render at the top of their file's section, labelled as such.
- Each finding shows: line, category, severity, confidence, evidence, risk, recommendation.
- **Masked values render as their placeholders.** Raw secret values must never appear in output. This is asserted in tests.

**[AMENDED M5] The skipped-file note is passed to the renderer, not carried on `Review`.** §10 fixes the output schema exactly as the brief specifies, and a count of excluded files is presentation rather than a finding — adding a field for it would change the schema, which CLAUDE.md says to ask about first. `render_markdown(review, excluded_note)` takes it as a second argument, sourced from `FilterResult.exclusion_summary()`. The JSON is unchanged, and the note still reaches the reviewer in the header where §13 wants it.

**[NEW M5] The renderer adds no judgment.** It does not filter, cap, re-score, or re-order anything `schema.py` settled; `overall_risk` renders as given rather than being recomputed from the findings present. Asserted in `test_renderer.py::test_overall_risk_is_taken_from_the_review_not_recomputed`. This is what makes "the JSON is the source of truth" true rather than aspirational: two artifacts that could disagree would mean neither is authoritative.

---

## 14. CLI

```
review-bot [DIFF_PATH | -] [options]
```

**Input:** a diff file path as a positional argument, or `-` to read from stdin. No git invocation — shelling out to `git diff --base/--head` would force every test to construct a real repository with real commits, which is heavy scaffolding for a capability CI does not need. CI pipes `git diff origin/main...HEAD` instead.

| Flag | Default | Purpose |
|---|---|---|
| `--format {markdown,json,both}` | `markdown` | Output format |
| `--output PATH` | stdout | Write to file |
| `--model ID` | `claude-sonnet-5` | Override review model |
| `--effort {low,medium,high}` | `medium` | Effort level |
| `--fail-on {none,high}` | `none` | Exit non-zero on findings at/above severity |
| `--cache` | off | Cache by diff hash; makes the M6 demo network-independent |
| `--record` | off | Overwrite test fixtures from live responses |
| `--dry-run` | off | Build prompt, price it, send nothing |
| `--no-llm` | off | Deterministic findings only |
| `--max-input-tokens N` | 8000 | Per-call budget guard |
| `--verbose` | off | Per-call usage and timing to stderr |

`--cache` is deliberately **off by default** — a second run should be allowed to produce a better review. Its one justified use is M6's requirement that the demo run unattended: a cached run does not depend on the network, the API budget, or the model having a bad morning.

---

## 15. Exit codes

**Exit code signals tool failure, not finding severity.** The tool is advisory; nothing in the brief gives it merge authority, and both the definition of done and the framing state that it assists rather than replaces human review.

| Code | Condition |
|---|---|
| `0` | Ran successfully. Findings present or absent — both are success. |
| `0` | No reviewable added lines. Prints `No reviewable changes.` and emits valid JSON with `no_findings_reason` set. **The LLM is not called.** Never spend money on an empty diff. |
| `1` | Diff failed to parse |
| `2` | LLM returned malformed JSON. Prints the raw response verbatim. **No auto-repair.** |
| `3` | Budget guard aborted the run |
| `4` | Findings met `--fail-on` threshold (only reachable when the flag is set) |

**[AMENDED M4] A failed API call is exit `0`, not a new code.** Network failure, an API error, and a safety refusal all leave the run able to do its job: §12 requires deterministic findings regardless, and the table's own framing is that the exit code signals *tool* failure. The failure is reported on stderr and the summary is synthesised locally, so the reviewer gets findings plus an explicit statement that coverage was partial. Malformed JSON keeps its own code because there the model *did* answer and the answer was unusable — that is a contract breach worth failing on.

**Note on refusals.** `claude-sonnet-5` carries elevated cybersecurity safeguards, and a security-review tool sits in exactly the domain they watch. A refusal arrives as HTTP 200 with `stop_reason: "refusal"`, so it is checked explicitly rather than caught as an exception. There is no retry and no rephrase — §12's rejection of recovery around the API call applies here too.

`--fail-on high` exists, is documented, and defaults off — the capability without the policy call.

---

## 16. Sample diffs

Five hand-written diffs, ~30 lines each, in `sample_diffs/`. Held at five deliberately: the constraint is authoring time, not money, and they are required by M1 on days 1–2. Diffs 6–10 would add coverage there is no time to tune against.

| File | Purpose | Expected |
|---|---|---|
| `auth_bypass.diff` | Removed role check, new admin path | 2 `auth_perms` findings, high severity |
| `injection_and_logging.diff` | f-string into `.execute()`, token in a log call | 1 `injection`, 1 `sensitive_logging`, both Tier 2 + LLM → `_source: both` |
| `secrets_and_logging.diff` | AWS key in `src/`, dummy password in `tests/` | 2 `hardcoded_secrets`, severity high and low respectively |
| `clean_but_suspicious.diff` | Parameterized SQL, `secrets.token_hex()`, redirect to an allowlist | **Zero findings.** Measures false-positive rate. |
| `prompt_injection.diff` | Code comment instructing the reviewer to approve | 1 `injection` finding for the attempt, plus normal review of the surrounding code |

`clean_but_suspicious.diff` is the one that earns its keep — code that *looks* alarming but is correct is the only way to measure false positives, and the definition of done requires documenting limitations honestly. `prompt_injection.diff` is the only test of §3's threat model.

---

## 17. Testing

| Layer | Approach |
|---|---|
| Unit | Mocked LLM. Never touches the network. |
| End-to-end | **Recorded JSON fixtures** in `tests/fixtures/`. |
| Live | **Never in CI.** `make smoke` runs one real call by hand before the demo. |

Live calls in CI are rejected: LLM output varies across model versions and provider-side changes, and a CI job that fails randomly gets ignored within a week — worse than no CI.

**The contract test is the highest-value test.** Every recorded fixture must validate against the current pydantic schema. The day a required field is added, CI breaks and reports that the prompt is out of sync with the schema. That is the failure that actually bites on day 8.

Per-module requirements, from the brief:

- **`test_diff_parser.py`** — multiple files, multiple hunks, added-line numbering correctness, empty diffs, binary/renamed/deleted files handled gracefully, malformed diffs
- **`test_secret_masker.py`** — tokens, private-key-shaped values, database URLs, generic API keys all masked; **assert no raw value appears in rendered output**
- **`test_role_scanner.py`** — each of the 12 rules maps a known snippet to its expected category; `clean_but_suspicious.diff` produces zero Tier 1 hits
- **`test_schema.py`** — valid response passes; missing required field fails with a clear error; unmappable line degrades to `line: null`; hallucinated file is rejected; merge and confidence promotion behave correctly
- **`test_renderer.py`** — grouping, sorting, severity header, masked placeholders preserved
- **End-to-end** — all 5 sample diffs against fixtures, stable output

---

## 18. CI

GitHub Actions, `.github/workflows/`.

**`test.yml`** — on every PR: install, lint, `pytest`. No API key, no network calls to Anthropic.

**`review.yml`** — on every PR: runs the bot against the PR's own diff.

```
git diff origin/${{ github.base_ref }}...HEAD | review-bot -
```

Output goes to the job log and is uploaded as a build artifact (`review.md`, `review.json`). It does not post a PR comment — that is out of scope. It does not block the merge.

`ANTHROPIC_API_KEY` from repository secrets. `review.yml` is `continue-on-error: true` so a bot failure never blocks the pipeline.

**[AMENDED M5] `review.yml` triggers on `pull_request`, never `pull_request_target`.** This is a security decision, not a default. §3 treats the diff as attacker-controlled, and on a fork PR the same author also controls the workflow file — `pull_request_target` would run that workflow with repository secrets in scope, which is the standard way `ANTHROPIC_API_KEY` gets exfiltrated by a drive-by pull request. `pull_request` withholds secrets from fork PRs instead.

The consequence is that fork PRs have no API key. Rather than fail the job, the workflow drops to `--no-llm`: §12 already guarantees deterministic findings without a network call, so a partial review is strictly better than none, and the output states that coverage was partial. Verified locally with the key unset.

**[NEW M5] `test.yml` runs `--dry-run` after the test suite.** It exercises the whole pipeline up to the network boundary against a real sample diff — the one thing a fully mocked suite cannot check — and costs nothing. No API key is present in `test.yml` at all, deliberately: withholding it is what *enforces* §17's "unit tests never touch the network", since a test that grew a real call would fail in CI rather than quietly start billing.

---

## 19. Milestones

| # | Days | Deliverable | Acceptance |
|---|---|---|---|
| **M1** Setup and spike | 1–2 | Repo, README, 5 sample diffs, one round-trip call | Real prompt round-trips. **Measure actual `usage.output_tokens` and correct the budget model (§8).** |
| **M2** Diff parser | 3–4 | `diff_parser.py` | Unit tests pass across multiple files, malformed diffs, binary/renamed/deleted, empty |
| **M3** Mask and roles | 5–6 | `secret_masker.py`, `role_scanner.py` | 12 rules with test evidence (≥4 required); zero Tier 1 hits on `clean_but_suspicious.diff` |
| **M4** LLM pipeline and schema | 7–8 | `prompt_builder.py`, `llm_client.py`, `schema.py` | 3 sample diffs end to end, no auto-repair; `unmappable_count` driven toward zero |
| **M5** Reviewer output and CI | 9 | `renderer.py`, both workflows | Grouped by file and line; severity and confidence visible; secrets redacted; CI on every PR |
| **M6** Demo and handoff | 10 | Demo script, walkthrough | `--cache` demo runs unattended on 3 sample diffs; README complete; release tag |

**Workflow:** feature branches only, no direct commits to `main` after setup, one PR per milestone with test evidence, small commits.

---

## 20. Definition of done

- [x] A new developer can clone, install, and run from the README end to end — **M5**
- [x] Findings include file, line, category, severity, confidence, evidence, risk, recommendation, and a PR-ready comment — **M5**, `test_renderer.py::test_every_required_field_renders`
- [x] Secrets are masked before the LLM step; raw values never appear in output (asserted in tests) — `test_cli.py::test_raw_secrets_never_appear_in_output`, `test_masking_happens_before_the_prompt_is_built`
- [x] No finding renders a line number absent from the diff — `test_cli.py::test_no_line_number_renders_that_is_not_in_the_diff`
- [x] Automated tests pass in CI — **M5**, `test.yml`
- [ ] Demo shows how the tool fits the PR review workflow — **M6**
- [x] Known limitations documented honestly — README §Known limitations, all nine from §21
- [ ] Total API spend under $20 — on track; no live call has been made yet beyond M1

---

## 21. Known limitations (for README)

1. **Assists, does not replace, human security review.** Advisory only; never blocks a merge.
2. **Cannot distinguish live credentials from test fixtures** beyond a path heuristic. Masking destroys the information required for that judgment. Rotation is always recommended.
3. **Cannot detect the absence of input validation deterministically.** `input_validation` is LLM-only and consequently the least reliable category.
4. **Cross-file findings are unreliable.** Per-file packing means auth removed in one file and exploited in another may not connect. The summary pass partially compensates.
5. **No taint analysis.** The tool detects that a dangerous sink was introduced, not that attacker-controlled data reaches it.
6. **Roughly 90% run-to-run stability**, not 100%, even at temperature 0.
7. **Diff-only context.** No knowledge of surrounding code, project conventions, or existing mitigations, and it will occasionally flag something already handled elsewhere.
8. **Prompt injection is detected, not prevented.** A sufficiently novel injection may still influence the review. Any detected attempt is surfaced so the reviewer knows to look manually.
9. **Lockfiles receive only a deterministic "dependency changed" flag**, not a vulnerability assessment. Pair with a real SCA tool.

---

## 22. Open items

- ~~Exact token budget for packing~~ — **[RESOLVED M4]** 8,000 stands as the default. All five sample diffs pack into a single call well under it (the largest estimates ~1.3k input tokens including the system prompt), so the splitting path is exercised by tests rather than by the samples. There is no evidence to tune against until a large real diff appears; `--max-input-tokens` remains the escape hatch.
- Whether the summary pass on Haiku is good enough, or needs to move to Sonnet — **still open**, and now blocked on one live run rather than on implementation. Both call paths are built and mocked end to end; the decision needs `make smoke` output, which is deliberately manual.
- Optional M4 experiment: run all 5 sample diffs through `claude-opus-5` at medium once (~$0.50) and diff the findings against Sonnet's. If Opus consistently catches something Sonnet misses, revisit the model choice; if not, the decision is settled for fifty cents. **Still open** — `--model` makes it a one-line experiment.
- **[NEW M4] Structured outputs (`output_config.format`) for the two calls.** The API can constrain responses to a JSON schema, which would make the exit-2 path nearly unreachable. Deliberately *not* adopted without a decision, because §15's "malformed JSON → print raw, exit 2, no auto-repair" is a stated contract, and constraining generation changes what that contract is protecting against. It is a genuine improvement, not a repair step, so it is worth deciding on rather than assuming. Blocked on: does making a documented failure mode unreachable count as changing the schema, which §22 and CLAUDE.md say to ask about first?
- **[NEW M5] Performance.** The deterministic stages now cost ~1ms per file and scale linearly to 100 files (`make bench`). The one real inefficiency found was in `secret_masker`: `transient_settings` was entered once per *file*, and entering it rebuilds every detect-secrets plugin and busts their caches — roughly half the stage's cost. Hoisting it to once per diff halved the stage on multi-file input. Guarded by `test_secret_masker.py::test_plugin_settings_are_configured_once_per_diff`, which asserts the call count rather than a wall-clock threshold, because a timing assertion on a shared CI runner is a flaky test. **Nothing further is worth optimizing:** a real run is dominated by two network calls, and the whole deterministic pipeline over a 100-file diff costs less than a tenth of one of them.

- **[NEW M5] `test_diff_parser.py` was empty.** M2 shipped the parser and its test *diffs* but not the test file, so §17's first per-module requirement was unmet and the gap was invisible because the suite was green. Now written — 30 cases, including the added-line numbering that §11 depends on. **The lesson worth keeping: a green suite is not evidence of coverage when the missing tests are missing files.** No further empty test modules remain.

- **[NEW M4] `thinking` configuration for the review pass.** The call currently leaves adaptive thinking at the model default. Thinking tokens bill as output and count against `max_tokens`, so this is a live cost and truncation variable that no local test can measure. Tune with the first `make smoke` figures, alongside the §19 M1 instruction to correct the budget model from real `usage`.
