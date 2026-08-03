.PHONY: test lint bench dry-run demo smoke record record-cache refresh-real-diffs review-pr \
        diffs diff1 diff2 diff3 diff4 diff5 \
        sample1 sample2 sample3 sample4 sample5

# Every target runs the venv's binaries, so none of them require an activated shell. The
# fallback to a bare name is for CI and for anyone who installed the package globally: if
# `.venv/` is not there, `review-bot` off PATH is the right thing to run.
BIN := $(shell [ -x .venv/bin/review-bot ] && echo .venv/bin/)

# The three network targets need ANTHROPIC_API_KEY. It lives in a gitignored `.env` rather
# than a shell profile, and nothing in `src/` reads that file — §14 keeps the tool's input
# to a diff, and a CLI that silently sources dotfiles is a surprise, not a feature. So the
# loading belongs here, in the tooling, where `make smoke` is already the documented way to
# make a live call.
#
# A missing `.env` is deliberately not an error: the key may already be exported (that is
# how CI supplies it), and `llm_client._sdk()` reports an absent key clearly either way.
LOAD_ENV = set -a; [ -f .env ] && . ./.env; set +a;

test:
	$(BIN)pytest

lint:
	$(BIN)ruff check .

# Times the deterministic stages against synthetic diffs of growing size. No network.
# Watch the per-file column: flat is correct, rising means a stage is paying fixed setup
# cost once per file instead of once per run.
bench:
	$(BIN)python scripts/bench.py

# No network. Builds and prices every prompt, sends nothing (SPEC.md §9).
# Safe to run anywhere, including CI.
dry-run:
	$(BIN)review-bot sample_diffs/auth_bypass.diff --dry-run

# ONE real API call pair. Manual only. Never in CI (SPEC.md §17).
# Needs ANTHROPIC_API_KEY. Until M4 this target was a --dry-run placeholder; the review
# and summary calls now exist, so it makes the call it always claimed to.
smoke:
	$(LOAD_ENV) $(BIN)review-bot sample_diffs/auth_bypass.diff --verbose

# Overwrite the recorded fixtures from live responses (§14 --record, §17).
# Separate from `smoke` so a routine smoke test cannot silently rewrite the fixtures the
# contract test validates against.
record:
	$(LOAD_ENV) $(BIN)review-bot sample_diffs/auth_bypass.diff --record tests/fixtures --verbose

# The M6 demo (§19). Replays the committed response cache over three sample diffs.
# No key, no network, no spend — safe to run anywhere, including on a fresh clone.
demo:
	bash scripts/demo.sh

# Rebuild the demo's response cache from live responses. Manual only, like `smoke`.
# One call pair per sample diff. Needs ANTHROPIC_API_KEY. Kept separate from `record`
# because that target owns the test fixtures and this one owns the demo (§17, §19).
record-cache:
	@$(LOAD_ENV) for d in sample_diffs/*.diff; do \
		echo "== $$d"; \
		$(BIN)review-bot "$$d" --cache --verbose >/dev/null || exit 1; \
	done

# Re-fetch real_diffs/ from GitHub. Manual only — the diffs are committed so the suite runs
# offline (SPEC.md §17, §25), and this is the one thing in the repo that reaches github.com.
# Needs no API key and no `gh`: these are public PRs, and an unauthenticated diff fetch is
# rate-limited rather than forbidden. Provenance lives in real_diffs/MANIFEST.json, which is
# also what this reads — so a new diff is added there first, and picked up here.
#
# Re-fetching can change the numbers: `test_real_diffs.py` asserts the measured
# deterministic-finding count per diff, and a force-push to a source PR would move it. That
# is a real signal, not a flake — check what changed before updating the manifest.
refresh-real-diffs:
	$(BIN)python scripts/refresh_real_diffs.py

# Review a real GitHub pull request. Makes live API calls — manual only, like `smoke`.
#
#   make review-pr PR=psf/requests#7328
#   make review-pr PR=https://github.com/psf/requests/pull/7328
#
# Loads .env for both keys this needs: ANTHROPIC_API_KEY for the review, and GH_TOKEN if
# you authenticate `gh` that way instead of `gh auth login`. `gh` reads GH_TOKEN from the
# environment on its own, which is why nothing in src/ has to know about the file (§14).
#
# The single quotes around $(PR) are for the bare `#123` form only. A `#` mid-word — as in
# `owner/repo#123` — is not a comment in any shell, but one at the start of a word is, in
# both bash and non-interactive zsh. Quoting covers both and costs nothing.
review-pr:
	@test -n "$(PR)" || { echo "usage: make review-pr PR=owner/repo#123"; exit 2; }
	@$(LOAD_ENV) $(BIN)review-bot --pr '$(PR)' --verbose

# One live review of one committed real diff (§25). Live API calls, like `smoke`.
#
#   make diff2
#
# These read the committed files, not github.com — the diffs in `real_diffs/` are byte-identical
# to what `--pr` would fetch, so this is the same pipeline with the network hop removed and no
# `gh` required. Use `make review-pr PR=...` when the point is to exercise `github_source`.
#
# The numbering is MANIFEST.json order, so it stays stable as long as the manifest does.
# `make diffs` prints the mapping rather than making you remember it.
DIFF1 = real_diffs/dependency_bump.diff
DIFF2 = real_diffs/large_multi_file.diff
DIFF3 = real_diffs/debugger_pin_fix.diff
DIFF4 = real_diffs/redirect_history.diff
DIFF5 = real_diffs/docs_removal.diff

# The hand-written diffs (§17). Each one is built so a specific rule fires, which is what
# makes them the ones to run when the point is to *see findings* rather than to see the tool
# survive input nobody wrote for it. `sample1` is the demonstration case: the LLM pass finding
# a logic flaw no deterministic rule could describe.
#
# `real_diffs/` is the opposite witness and mostly comes back quiet on purpose (§25) — four of
# the five produce zero deterministic findings. A quiet `make diff3` is the tool working.
SAMPLE1 = sample_diffs/auth_bypass.diff
SAMPLE2 = sample_diffs/secrets_and_logging.diff
SAMPLE3 = sample_diffs/injection_and_logging.diff
SAMPLE4 = sample_diffs/prompt_injection.diff
SAMPLE5 = sample_diffs/clean_but_suspicious.diff

diffs:
	@echo "REAL merged PRs (§25) — mostly quiet on purpose:"
	@echo "  make diff1    $(DIFF1)   dependency bump — every file filtered, no API call (§7)"
	@echo "  make diff2    $(DIFF2)   11 files, packs into 2+ review calls (§7)"
	@echo "  make diff3    $(DIFF3)   debugger PIN auth fix — real code, zero deterministic hits"
	@echo "  make diff4    $(DIFF4)   redirect handling — false-positive check"
	@echo "  make diff5    $(DIFF5)   pure deletion — exit 0, no API call (§15)"
	@echo ""
	@echo "HAND-WRITTEN (§17) — these reach the LLM and report findings:"
	@echo "  make sample1  $(SAMPLE1)   LLM finds a logic flaw no regex could"
	@echo "  make sample2  $(SAMPLE2)   deterministic secret + masking that survives to output"
	@echo "  make sample3  $(SAMPLE3)   injection and logging"
	@echo "  make sample4  $(SAMPLE4)   prompt injection"
	@echo "  make sample5  $(SAMPLE5)   false-positive canary — must come back quiet"

diff1:
	$(LOAD_ENV) $(BIN)review-bot $(DIFF1) --verbose

diff2:
	$(LOAD_ENV) $(BIN)review-bot $(DIFF2) --verbose

diff3:
	$(LOAD_ENV) $(BIN)review-bot $(DIFF3) --verbose

diff4:
	$(LOAD_ENV) $(BIN)review-bot $(DIFF4) --verbose

diff5:
	$(LOAD_ENV) $(BIN)review-bot $(DIFF5) --verbose

sample1:
	$(LOAD_ENV) $(BIN)review-bot $(SAMPLE1) --verbose

sample2:
	$(LOAD_ENV) $(BIN)review-bot $(SAMPLE2) --verbose

sample3:
	$(LOAD_ENV) $(BIN)review-bot $(SAMPLE3) --verbose

sample4:
	$(LOAD_ENV) $(BIN)review-bot $(SAMPLE4) --verbose

sample5:
	$(LOAD_ENV) $(BIN)review-bot $(SAMPLE5) --verbose
