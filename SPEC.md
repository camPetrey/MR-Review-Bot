# Security PR Review Bot — Specification

**Platform:** GitHub — hosting, CI, and pull-request input (§23).

**[AMENDED M7]** This line previously read "GitHub Repo but for Gitlab", which described
neither the repository nor the tool. GitHub is the platform throughout: the repo, the
Actions workflows (§18), and — as of M7 — the pull requests the tool reads directly (§23).
Nothing in the pipeline is GitLab-specific and nothing ever was; the diff format is the
only interface either platform would present, and it is the same one.

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
| Terminal rendering | `rich` | This spec (§24) |
| Pull-request input | `gh` CLI, wrapped | This spec (§23) |
| Sample diffs | 5 hand-written, ~30 lines each | Brief |
| Real diffs | 5 merged public GitHub PRs | This spec (§25) |
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
diff  (a file, stdin, or a GitHub PR via github_source — §23)
  -> diff_parser        parse files, hunks, added lines, post-file line numbers
  -> secret_masker      typed masking, pre-network
  -> role_scanner       deterministic rules + injection patterns
  -> prompt_builder     filter, pack, build byte-stable prompt
  -> llm_client         budget guard, Anthropic call, caching
  -> schema             pydantic validation, line validation, merge, dedupe
  -> renderer           Markdown from JSON
     terminal           styled terminal report from the same JSON (§24)
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
| `terminal.py` | JSON → styled terminal report (§24) |
| `github_source.py` | `gh` CLI wrapper: PR reference parsing, diff and metadata fetch (§23) |

**[NEW M7] Two of these are not pipeline stages, and the distinction matters.**
`github_source.py` is an *input adapter* in front of stage 1: it produces the same diff text
a file or stdin would have, and nothing downstream can tell the difference. `terminal.py` is
a *second projection* of stage 7's input, a sibling of `renderer.py` rather than a stage
after it. Both attach at an existing boundary instead of lengthening the pipeline, which is
what keeps CLAUDE.md's "one module per pipeline stage" rule intact at nine modules — the
pipeline is still seven stages long.

**[DEVIATION]** The brief's repo layout omits `prompt_builder.py` while its own pipeline diagram contains a "prompt builder" box, and the brief states "each box in the data flow maps to one file under `src/`." Adding the file resolves the brief against itself. Filtering, packing, and suppression-list construction are non-trivial logic that would otherwise bloat `llm_client.py` and become hard to unit test.

---

## 5. Masking

Runs before any network call, on the parsed diff.

- Wrap `detect-secrets`; do not reimplement detection.
- Emit **typed** placeholders: `[MASKED_AWS_KEY]`, `[MASKED_PRIVATE_KEY]`, `[MASKED_DB_URL]`, `[MASKED_TOKEN]`, `[MASKED_KEY]`.
- Attach a path signal to each masked finding: `test` if the file path matches `tests/`, `test_*`, `conftest.py`, `fixtures/`, `*_test.*`; otherwise `src`.
- Substitution is in-place within the line, preserving line numbers and diff alignment.

**[AMENDED M6] Every line kind is masked; only added lines are reported.** Masking
originally covered added lines alone, on the reasoning that a secret on a removed or
context line was already in the repository. That reasoning is correct about *findings* and
wrong about *masking*: removed and context lines are quoted downstream — both render into
the review prompt, and the `auth_perms` rule quotes removed lines verbatim into evidence
that reaches the summary prompt and the report. The invariants "no raw diff content
reaches the API" and "raw secret values never appear in output" carry no line-kind
qualifier, so the masker now scans and substitutes on all three kinds. `hardcoded_secrets`
findings are still emitted for added lines only: a pre-existing secret is masked, not
reported, because this PR did not introduce it. Asserted end to end in
`test_cli.py::test_removed_line_secret_never_reaches_prompt_or_output`.

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

**[AMENDED M8] Every Tier 2 hit is now also a candidate, fed to the LLM by file/line/category/note and asked to be confirmed or rejected independently.** See §12 for the reasoning and §8 for the prompt mechanics.

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

**[FIXED M7] The packing budget reserves the system prompt.** `--max-input-tokens` limits
the whole request — which is what `llm_client.preflight` measures — but `pack` budgeted the
file blocks alone. A batch filled to 8,000 tokens of content then had a ~1,600-token system
prompt added to it and aborted at exit 3 *before sending anything*. `pack` now packs against
`content_budget(max_input_tokens)`, which subtracts the measured cost of an empty prompt.

Worth recording how it stayed hidden: every sample diff is ~1.3k tokens and never fills a
batch, and §22 said so explicitly while treating it as a reason the splitting path was
untested rather than as a reason the budget arithmetic was unverified. The two meanings of
"8,000" never had to agree, so nobody noticed they did not. `real_diffs/large_multi_file.diff`
(§25) is the first committed diff that fills a batch, and it failed on the first run.
Guarded by `test_prompt_builder.py::test_a_packed_batch_fits_the_input_budget_with_its_system_prompt`.

**Accepted limitation:** cross-file findings are lost — auth middleware removed in one file, exploited by a route in another. Partially recovered by the summary pass (§8). Documented in README.

---

## 8. LLM calls

Two calls per run.

### Call 1 — Review pass

- Model: `claude-sonnet-5`, effort `medium`
- Input: system prompt + masked, packed diff + suppression list + candidate list
- Output: `findings[]` only

The suppression list names `(file, line)` pairs already covered by Tier 1 rules, with the instruction: *these lines are already reported; do not re-report them; look for what they missed.* This is **suppression, not hinting** — the model is told to stay away, not invited to confirm.

**[AMENDED M8] The candidate list names `(file, line, category, note)` for every Tier 2 hit**, with the instruction: *confirm or reject each independently; the flag is not evidence.* Tier 1 stays suppression — a false positive there is certain, and revisiting it buys nothing. Tier 2 is the opposite case: real pattern, ambiguous intent, exactly the kind of thing a second opinion is for. See §12 for why this replaces the earlier "suppression list only" design.

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

**[AMENDED M8] Tier 2 hits are now fed to the LLM as a candidate list, reversing the earlier "suppression list only" rule.** The original rejection gave three reasons — anchoring the model into confirming bad regexes, coupling the strongest signal to a network call, and making `role_scanner.py` untestable in isolation. Revisited:

- **Coupling to the network** was never a Tier 2 concern in the first place — Tier 2 was already not suppressing, so it was already fully present in `findings[]` with no dependency on the LLM call succeeding. Candidacy is additive: it can promote a Tier 2 finding's confidence, but a call that never runs or fails leaves the finding exactly where it would have been anyway (§15's exit-0 path is unaffected).
- **`role_scanner.py` untestable in isolation** does not actually follow from feeding its output forward — the module still runs standalone, over a parsed diff, with no dependency on `prompt_builder` or the network; `test_role_scanner.py` asserts its output directly and always has. What would make it untestable in isolation is *reading the model's output back*, which this does not do.
- **Anchoring** is the one real risk, and the fix is in the instruction, not the topology: the model is told the flag is not evidence and to decide independently, mirroring how a competent second reviewer is told "someone flagged this — form your own opinion" rather than "someone flagged this, please agree." A candidate the model doesn't confirm changes nothing; it stays exactly the deterministic-only finding it would have been.

The result **is** what "agreement promotes confidence" (below) was always describing — a second, differently-shaped read of the same location. Making that a deliberate ask rather than an incidental overlap raises the odds the model's second read actually happens on lines a regex has already flagged as ambiguous, which is precisely where a second read is worth having.

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

**[AMENDED M7] There are now two renderers, and the rule below binds both.** `terminal.py`
(§24) is a second projection of the same `Review`. It imports `group_by_file` and
`severity_counts` from `renderer.py` rather than reimplementing them, so the two artifacts
cannot disagree about ordering or counts — asserted in
`test_terminal.py::test_both_renderers_agree_on_file_order_and_counts`.

**[NEW M5] The renderer adds no judgment.** It does not filter, cap, re-score, or re-order anything `schema.py` settled; `overall_risk` renders as given rather than being recomputed from the findings present. Asserted in `test_renderer.py::test_overall_risk_is_taken_from_the_review_not_recomputed`. This is what makes "the JSON is the source of truth" true rather than aspirational: two artifacts that could disagree would mean neither is authoritative.

---

## 14. CLI

```
review-bot [DIFF_PATH | - | PR_URL] [options]
```

**Input:** a diff file path as a positional argument, `-` to read from stdin, or — as of M7
— a GitHub pull request (§23). ~~No git invocation~~ — shelling out to `git diff --base/--head` would force every test to construct a real repository with real commits, which is heavy scaffolding for a capability CI does not need. CI pipes `git diff origin/main...HEAD` instead.

**[AMENDED M7] The no-subprocess rule was about reconstructing a diff locally, and it still
holds for that.** `--pr` shells out to `gh`, which reads as a straight reversal of the
sentence above and is not one. The rejected thing was `git diff BASE...HEAD`: it needs a
local checkout at the right commits, so every test would have to build a real repository —
the scaffolding is the entire objection, and it is unchanged. `gh pr diff` needs no checkout
and computes nothing locally; it fetches a diff the server already made. The test cost is
one mocked function (`github_source._run_gh`), which is *less* scaffolding than reading a
file, and §17's "unit tests never touch the network" is preserved by the same seam.

Rejected alternatives, both real options:

- **Call `api.github.com` directly** (stdlib `urllib`, `Accept: application/vnd.github.v3.diff`).
  Zero new dependencies and no external binary — genuinely tempting. Rejected because it
  means owning credential storage, token refresh, enterprise hosts, and SSO, all of which
  `gh` already solves and none of which this tool has any business reimplementing badly.
- **A `PyGithub` or `requests` dependency.** A library-sized answer to one HTTP GET, and it
  still leaves the credential problem where the previous option left it.

The cost of the choice, stated plainly: `gh` must be installed and authenticated, which is a
runtime dependency that `pip install` does not satisfy. The failure is loud and names the
fix (`github_source._explain_failure`), and every other input path works without it — CI
uses none of it, because §18 pipes the diff.

| Flag | Default | Purpose |
|---|---|---|
| `--pr REF` | — | Review a GitHub pull request. URL, `owner/repo#123`, or bare `123` (§23) |
| `--format {auto,terminal,markdown,json,both}` | `auto` | Output format. `auto` = terminal on a TTY, Markdown when piped (§24) |
| `--no-color` | off | Disable colour. `NO_COLOR` is honoured regardless |
| `--output PATH` | stdout | Write to file |
| `--model ID` | `claude-sonnet-5` | Override review model |
| `--effort {low,medium,high}` | `medium` | Effort level |
| `--fail-on {none,high}` | `none` | Exit non-zero on findings at/above severity |
| `--summary-model ID` | `claude-haiku-4-5-20251001` | Override summary model |
| `--cache` | off | Cache by diff hash; makes the M6 demo network-independent |
| `--cache-dir PATH` | `.review_bot_cache` | Where `--cache` reads and writes |
| `--record` | off | Overwrite test fixtures from live responses |
| `--dry-run` | off | Build prompt, price it, send nothing |
| `--no-llm` | off | Deterministic findings only |
| `--max-input-tokens N` | 8000 | Per-call budget guard |
| `--max-run-cost N` | 0.50 | Per-run budget guard, in dollars |
| `--verbose` | off | Per-call usage and timing to stderr |

`--cache` is deliberately **off by default** — a second run should be allowed to produce a better review. Its one justified use is M6's requirement that the demo run unattended: a cached run does not depend on the network, the API budget, or the model having a bad morning.

**[AMENDED M6] The cache key is the prompt bytes, not the diff hash, and the demo cache is committed.** Keying on the prompt is the diff hash refined: the prompt is a pure function of the diff, and keying on it also separates the two calls of §8 and each batch of §7, and invalidates when `--model` or `--effort` changes — all of which a diff hash would collide. `.review_bot_cache/` is checked in rather than ignored, because "runs unattended" in §19 means *on a fresh clone with no key configured*; a cache the demo has to build first is a cache the demo does not have.

**[NEW M6] The demo aborts on a cache miss rather than degrading.** §12 keeps deterministic findings alive when a call fails, so a cold-cache demo would still exit 0 and still print a review — a *partial* review, presented as the full one. That is right for the tool and wrong for a demo, so `scripts/demo.sh` greps the `--verbose` log for cache hits and fails loudly instead. The distinction worth keeping: graceful degradation is a property of the tool, not of everything built on it.

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

**[AMENDED M7] Five real diffs sit alongside these in `real_diffs/`, and do a different
job (§25).** These five stay exactly as they are: they are what the rules were tuned
against, and retuning against real PRs would cost the M3 rule evidence and the
false-positive canary for nothing.

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

**[NEW M6] Both workflow files were committed empty in M1 and stayed empty until M5.** `review.yml` and `test.yml` existed as zero-byte placeholders in every commit from the initial one through M4. GitHub cannot parse an empty workflow, so every push to every branch produced an *invalid workflow file* startup failure — a run with no jobs, no logs, and a failure email. Twenty consecutive failed runs, none of which had anything to do with the code. `main` still carries the empty files, because M5 is the first commit with real ones and it has not merged yet; this milestone's merge is what fixes it.

Two things worth keeping from it. **A CI failure with zero jobs is a parse failure, not a test failure** — the run's `name` showing as the file path instead of the workflow's `name:` is the tell, and no amount of reading the code would have found it. And **`continue-on-error` is why the noise was one workflow's worth and not two**: `review.yml`'s job-level `continue-on-error: true` means a genuine bot failure resolves the run as success and sends no mail, so once the files parse, the only workflow that can page anyone is `test.yml` — which is exactly the one that should.

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
| **M7** GitHub input and terminal output | — | `github_source.py`, `terminal.py`, `real_diffs/` | `--pr` reviews a real PR; styled report on a TTY with Markdown preserved when piped; real diffs in CI (§23, §24, §25) |

**Workflow:** feature branches only, no direct commits to `main` after setup, one PR per milestone with test evidence, small commits.

---

## 20. Definition of done

- [x] A new developer can clone, install, and run from the README end to end — **M5**
- [x] Findings include file, line, category, severity, confidence, evidence, risk, recommendation, and a PR-ready comment — **M5**, `test_renderer.py::test_every_required_field_renders`
- [x] Secrets are masked before the LLM step; raw values never appear in output (asserted in tests) — `test_cli.py::test_raw_secrets_never_appear_in_output`, `test_masking_happens_before_the_prompt_is_built`
- [x] No finding renders a line number absent from the diff — `test_cli.py::test_no_line_number_renders_that_is_not_in_the_diff`
- [x] Automated tests pass in CI — **M5**, `test.yml`
- [x] Demo shows how the tool fits the PR review workflow — **M6**, `make demo` / README §Demo
- [x] Known limitations documented honestly — README §Known limitations, all nine from §21
- [x] Total API spend under $20 — **M6**, $0.035 across all five sample diffs (ten calls). The budget guards were never the binding constraint; see §22.

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
10. **[NEW M7] `--pr` requires `gh` installed and authenticated.** `pip install` does not
    provide it. Every other input path — a file, stdin, CI's pipe — works without it (§23).
11. **[NEW M7] `--pr` reads a pull request; it does not write to one.** Posting review
    comments back to the PR remains out of scope (§1). The output is a terminal report, a
    Markdown file, or JSON.
## 22. Open items

- **[NEW M7] The packing budget did not include the system prompt, and no test could have
  caught it.** Resolved in §7. The lesson is about the corpus, not the arithmetic: the entry
  below closed "what token budget for packing?" by observing that all five samples fit in one
  call well under 8,000 — which is true, and is exactly why the number was never tested. A
  budget that nothing approaches is a budget nothing verifies. The first real diff large
  enough to fill a batch failed immediately, at exit 3, before sending a request. **This is
  the argument for `real_diffs/` (§25) stated as a defect rather than as a principle.**

- ~~Exact token budget for packing~~ — **[RESOLVED M4]** 8,000 stands as the default. All five sample diffs pack into a single call well under it (the largest estimates ~1.3k input tokens including the system prompt), so the splitting path is exercised by tests rather than by the samples. There is no evidence to tune against until a large real diff appears; `--max-input-tokens` remains the escape hatch.
- ~~Whether the summary pass on Haiku is good enough, or needs to move to Sonnet~~ — **[RESOLVED M6]** Haiku stays. See the resolved entry below for the evidence.
- Optional M4 experiment: run all 5 sample diffs through `claude-opus-5` at medium once (~$0.50) and diff the findings against Sonnet's. If Opus consistently catches something Sonnet misses, revisit the model choice; if not, the decision is settled for fifty cents. **Still open** — `--model` makes it a one-line experiment.
- **[NEW M4] Structured outputs (`output_config.format`) for the two calls.** The API can constrain responses to a JSON schema, which would make the exit-2 path nearly unreachable. Deliberately *not* adopted without a decision, because §15's "malformed JSON → print raw, exit 2, no auto-repair" is a stated contract, and constraining generation changes what that contract is protecting against. It is a genuine improvement, not a repair step, so it is worth deciding on rather than assuming. Blocked on: does making a documented failure mode unreachable count as changing the schema, which §22 and CLAUDE.md say to ask about first?
- **[NEW M5] Performance.** The deterministic stages now cost ~1ms per file and scale linearly to 100 files (`make bench`). The one real inefficiency found was in `secret_masker`: `transient_settings` was entered once per *file*, and entering it rebuilds every detect-secrets plugin and busts their caches — roughly half the stage's cost. Hoisting it to once per diff halved the stage on multi-file input. Guarded by `test_secret_masker.py::test_plugin_settings_are_configured_once_per_diff`, which asserts the call count rather than a wall-clock threshold, because a timing assertion on a shared CI runner is a flaky test. **Nothing further is worth optimizing:** a real run is dominated by two network calls, and the whole deterministic pipeline over a 100-file diff costs less than a tenth of one of them.

- **[NEW M6] The release tag from §19 is deliberately not cut.** A tag should point at merged `main`, and `main` does not yet contain M5 or M6 — it is still carrying the empty workflow files described in §18. Tag once this milestone merges; versioning is otherwise unowned by this spec.

- **[RESOLVED M6] The budget model is correct but wildly conservative, and that is now a measured number.** §9 prices a call at its *full* `max_tokens`, so `--dry-run` quotes ~$0.0945 per sample diff. Across all five, real runs cost **$0.0037–$0.0131**, total **$0.035** — the estimate overshoots by 7–25×, because review responses used 104–424 output tokens against a 8,000-token ceiling and summaries 97–360 against 2,000.

  **The worst-case model stays.** A guard that can under-estimate cannot guard: `preflight` runs *before* the request, where the real output length is unknowable, and the only safe assumption is the ceiling. But the overshoot has a consequence worth stating, because it is not obvious from the code: `--max-run-cost` is spent in *estimated* dollars, so the default $0.50 trips after ~10 review calls even though ten real calls would cost well under a dollar. On a diff large enough to pack into that many batches (§7), the guard fires on a run that was never going to be expensive. `--max-run-cost` is the documented escape hatch; the number to raise it to is now knowable rather than guessed.

- **[RESOLVED M6] Prompt caching works on call 1 and is inert on call 2.** The review system prompt cached exactly as §8 predicted — 2,065 tokens written on the first call of the session and **read on all four subsequent ones**, across different diffs. That is the byte-stability claim confirmed empirically rather than argued: had any of the "no timestamps, no UUIDs, sorted lists" rules leaked, the reads would have been zero.

  The summary call reports `cache_read=0 cache_write=0` every time. Its system prompt is a module constant like the other, but it is **below the minimum cacheable prefix** for `claude-haiku-4-5-20251001`, so the `cache_control` block on it does nothing. Harmless — it costs neither tokens nor correctness — but it is dead configuration, and worth knowing before someone reads a zero as a bug.

- **[RESOLVED M6] Haiku is good enough for the summary pass.** The open question below asked for one live run. On all five diffs the summaries were accurate and specific rather than generic — the `auth_bypass` summary names both changed files, both removed checks, and the newly added route, and correctly connects them into one privilege-escalation window. Call 2 never sees the diff (§8); it summarises validated findings, which is a task Haiku does well. **No reason to move it to Sonnet.** Revisit only if summaries start contradicting the findings they summarise.

- **[NEW M6] §11's counters came back zero on live data.** `unmappable_count=0` and `hallucinated_file_count=0` on all five diffs. M4's acceptance criterion was "driven toward zero" and it is there — but note what this does *not* prove: five hand-written 30-line diffs are the easy case for line mapping. The counters exist because the hard case is a real PR, and §18 puts them in the CI job output for exactly that reason.

- **[NEW M6] The confidence merge of §12 is visible in the live `auth_bypass` review.** Three findings, three different confidences, each earned a different way: the removed `is_admin` check came back **high** (both layers found it), the removed `@login_required` **low** (deterministic only — the rule sees a decorator disappear and cannot tell whether it moved), and the new `admin_raw` route **medium** (LLM only, no rule for it). That spread is the whole design working end to end, and it is the strongest single piece of evidence M6 produced.

- **[NEW M6] The two models frame their JSON differently, and the fixtures now prove the parser handles it.** Sonnet returns bare JSON on the review call; Haiku wraps the summary in a ```` ```json ```` fence. `_strip_code_fence` already handled this and §15 already justified it as a *framing* fix rather than an auto-repair — but until M6 the only fenced input the suite had ever seen was one a test wrote for itself. `tests/fixtures/summary-auth_bypass.json` is now a real fenced Haiku response, so the highest-value test in the suite validates that path against something the API actually sent. **This also closes the M5 loop below:** `--record` wrote exactly the two fixture names the contract test reads, which is the `_record_stem` fix demonstrated rather than asserted.

- **[NEW M6] `clean_but_suspicious.diff` produced zero findings on a live run, not just zero Tier 1 hits.** §17 only asks the canary to stay quiet through the deterministic layer. It also stayed quiet through the model, which is the harder half — the file is written to look alarming. One run is not a false-positive rate, but it is the right sign.

- **[NEW M5] `--record` never overwrote the fixtures it claimed to.** The call labels were
  `review-{batch index}` and `summary`, so `make record` wrote `review-0.json` and
  `summary.json` while `tests/fixtures/` — keyed by sample diff — kept validating the
  original `review-auth_bypass.json` and `summary-auth_bypass.json`. The contract test
  stayed green throughout, because it validates whatever files are present and both sets
  were valid. Labels are now derived from the diff filename (`_record_stem`), so the
  written names match the fixture names exactly, and
  `test_cli.py::test_record_writes_fixture_names_derived_from_the_diff` fails if they drift
  apart again. **Same lesson as the empty test module below, one level further out: a green
  contract test proves the fixtures are well-formed, not that they are the ones a live run
  would produce.**

- **[NEW M5] `test_diff_parser.py` was empty.** M2 shipped the parser and its test *diffs* but not the test file, so §17's first per-module requirement was unmet and the gap was invisible because the suite was green. Now written — 30 cases, including the added-line numbering that §11 depends on. **The lesson worth keeping: a green suite is not evidence of coverage when the missing tests are missing files.** No further empty test modules remain.

- **[NEW M4, UPDATED M6] `thinking` configuration for the review pass.** The call leaves adaptive thinking at the model default. Thinking tokens bill as output and count against `max_tokens`, so this was flagged as a live cost and truncation risk. **M6's figures retire the truncation half of that worry and leave the tuning half open.** Review responses used 104–424 output tokens against an 8,000-token ceiling — thinking included, since `usage.output_tokens` does not break it out — so nothing came close to truncating and `REVIEW_MAX_TOKENS` needs no change. What is still unknown is how much of that was thinking, which is what an `effort` sweep would answer. Not worth doing against five easy diffs; do it when there is a large real diff to sweep against.

---


---

## 23. GitHub pull-request input

**[NEW M7]** `review-bot --pr owner/repo#123` fetches a PR's diff and reviews it. The
positional argument accepts the same thing, so a pasted URL works with no flag at all.

Accepted forms:

| Form | Where |
|---|---|
| `https://github.com/owner/repo/pull/123` (with `/files`, `#comment`, query strings) | positional or `--pr` |
| `owner/repo#123`, `owner/repo/pull/123` | positional or `--pr` |
| `123`, `#123` — resolved against the working directory's remotes by `gh` | **`--pr` only** |

**The bare forms are `--pr`-only, and that asymmetry is deliberate.** `123` is a valid
filename; a URL and `owner/repo#123` cannot be mistaken for a real path. Using `--pr` is the
user stating that the argument is a pull request, which is the only thing that makes a bare
number unambiguous. An existing file always wins over a PR-shaped name regardless.
Asserted in `test_github_source.py::test_diff_paths_are_never_mistaken_for_pull_requests`.

**Metadata never reaches a prompt.** `gh pr view` is called for the title, author, and
branches, which decorate the report header (§24) and nothing else. The field list
deliberately excludes the PR **body**: §3 treats everything the PR author writes as
attacker-controlled, and the body is the largest block of author-written prose there is,
with no review value the diff does not already carry. Asserted in
`test_github_source.py::test_fetch_pr_info_never_requests_the_pr_body`.

**Metadata failure is not run failure.** The diff is required and its failure exits 1, like
an unreadable file. The metadata call is best-effort and returns None on any error — the
review already arrived, and losing a title is not a reason to discard it.

**One subprocess boundary.** `github_source._run_gh` is the only `subprocess.run` in the
module, which is what lets the entire test file mock one function and keeps §17's
no-network rule enforced rather than merely stated. Asserted structurally in
`test_github_source.py::test_run_gh_is_the_only_subprocess_call`, in the same spirit as
§22's call-count guard: assert the property that was fixed, not a timing.

**Not adopted:** posting the review back as a PR comment. Still out of scope per §1, and
the argument there has not changed — writing to a PR is a permissions and idempotency
problem (which comment, edit or append, what happens on a force-push) that a tool with no
cross-PR state cannot answer well.

---

## 24. Terminal output

**[NEW M7]** The default output on a terminal is a styled report built with `rich`:
severity badges, a full-height colour bar down each finding, confidence meters, and the
findings grouped by file exactly as §13 orders them.

**`--format auto` (the new default) resolves on `stdout.isatty()`** — terminal for a human,
Markdown for anything else. This is what keeps the change backward compatible: §18's
workflows, `> review.md`, and `| less` all still receive the Markdown they always did, and
no existing invocation changes behaviour. `--format markdown` forces it either way.

**Rich markup is the hazard this module is written around.** Rich parses `[...]` in a plain
string as a style tag, so an evidence string carrying `[MASKED_AWS_KEY]` renders as *nothing
at all* — no error, no warning, just a gap where the proof that masking worked used to be.
That would break invariant 7 in the one direction tests would not otherwise catch, since
nothing raises and no secret leaks; the placeholder simply vanishes. Every string sourced
from the diff or the model is therefore wrapped in `rich.text.Text`, which disables the
parse. Asserted for all five §5 placeholders in
`test_terminal.py::test_masked_placeholders_survive_rich_markup`.

**The report is built before the diagnostics are printed.** `--verbose` writes counters and
timings to stderr, and the terminal report goes to stdout; on one terminal they interleave.
`prepare_terminal` returns a closure so `cli.py` can time the render, flush stderr, and then
print — which is also the only ordering where the timings report can include the render
stage it is timing.

**[NEW] The diagnostics are styled on the same rule, one level down.** They were eight
unbroken lines of `key=value` above the report, which is a shape with no entry point: a
reader looking for the run's cost had to read the whole block to find it, and the same
numbers appeared twice — once live per call, once in a closing summary. `render_diagnostics`
now branches on `stderr.is_terminal`:

- **A terminal** gets a labelled block — `calls`, `checks`, `time`, `scope` — with the call
  accounting in an aligned table, the run total under the column it totals, and the timings
  as total → api/local split → per-stage detail. Zeroed counters are dimmed and only a
  non-zero one takes colour, so a healthy run costs nothing to skip past. The live per-call
  line shrinks to label, model, elapsed, and cost: its job is to prove a ten-second wait is
  still alive, and the token detail behind it is now reported once, at the end.
- **Anything else** — a pipe, a file, CI — gets the original `key=value` lines unchanged.
  That is not a fallback. §11 puts `unmappable_count` and `hallucinated_file_count` in the
  CI job output, and what makes them useful there is that they survive a log search; a
  number sitting under a column heading does not.

The two streams are checked independently, because they genuinely differ:
`review-bot diff > out.md` leaves stdout a file and stderr a terminal, and that run should
still get the readable form of its own diagnostics.

`terminal.py` owns the layout and `cli.py` owns the content, passed across as
`RunDiagnostics` rather than as pre-formatted lines. That split is what lets one run print
either form without `cli.py` knowing which happened.

**Rejected:** hand-rolled ANSI. It is one dependency against wrapping, width detection,
`NO_COLOR`, non-TTY degradation, and East-Asian character widths, all of which `rich` has
already got right and none of which is this project's problem to solve.

---

## 25. Real pull-request diffs

**[NEW M7]** `real_diffs/` holds five merged public GitHub PRs, committed verbatim, with
provenance in `real_diffs/MANIFEST.json` and `make refresh-real-diffs` to re-fetch them.
They complement `sample_diffs/` (§16) rather than replacing it.

The five samples are hand-written to make each rule fire, and the rules were tuned against
them. That makes them a poor witness for input nobody wrote for the tool: each is ~30 lines,
one hunk, one concern, and every one is *supposed* to produce findings. The real diffs cover
what that shape cannot reach.

| Diff | Source | Exercises |
|---|---|---|
| `dependency_bump.diff` | pallets/werkzeug#2080 | Every file filtered; Tier 1 only; **no API call at all** (invariant 6) |
| `large_multi_file.diff` | encode/httpx#2879 | 11 files, ~13k tokens — **the first committed diff that splits into more than one batch** (§7) |
| `debugger_pin_fix.diff` | pallets/werkzeug#3078 | A real security fix in PIN-auth code, with zero deterministic hits |
| `redirect_history.diff` | psf/requests#7328 | Real redirect handling that `unsafe_redirects` must stay quiet on |
| `docs_removal.diff` | pallets/flask#5695 | Pure deletion, no added lines — §15's exit-0 path |

**Most real PRs produce zero deterministic findings, and that is the expected number.** The
manifest records the measured count per diff and `test_real_diffs.py` asserts it, so a rule
that starts firing on ordinary code fails CI. This is `clean_but_suspicious.diff`'s job
generalised: that file proves the rules stay quiet on code *written* to look alarming, and
these prove they stay quiet on code written without the tool in mind at all.

**The most valuable finding in the directory is a false positive.** `large_multi_file.diff`
produces two `hardcoded_secrets` hits on `docs/advanced.md`, where the changed lines are
documentation examples showing `http://user:pass@proxy` URLs. `detect-secrets` is right that
the text is credential-shaped and wrong that it matters, and §5's path heuristic scores
`docs/` as `src` and calls it **high** severity. It is asserted, not fixed: §21's limitation
2 says the tool cannot distinguish a live credential from an example without the value, and
the value is destroyed by design. A rule change that silences it has to delete a test that
says why it exists.

**Still open:** these five are all Python-ecosystem web libraries, so the corpus says
nothing about Go, Rust, or a large TypeScript monorepo. §22's note that there is no large
real diff to tune against is now half-resolved — there is one, and it is 900 lines, which is
still not the 5,000-line PR where the packing defaults would actually be tested.

---

