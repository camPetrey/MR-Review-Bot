.PHONY: test lint bench dry-run demo smoke record record-cache

test:
	pytest

lint:
	ruff check .

# Times the deterministic stages against synthetic diffs of growing size. No network.
# Watch the per-file column: flat is correct, rising means a stage is paying fixed setup
# cost once per file instead of once per run.
bench:
	python scripts/bench.py

# No network. Builds and prices every prompt, sends nothing (SPEC.md §9).
# Safe to run anywhere, including CI.
dry-run:
	review-bot sample_diffs/auth_bypass.diff --dry-run

# ONE real API call pair. Manual only. Never in CI (SPEC.md §17).
# Needs ANTHROPIC_API_KEY. Until M4 this target was a --dry-run placeholder; the review
# and summary calls now exist, so it makes the call it always claimed to.
smoke:
	review-bot sample_diffs/auth_bypass.diff --verbose

# Overwrite the recorded fixtures from live responses (§14 --record, §17).
# Separate from `smoke` so a routine smoke test cannot silently rewrite the fixtures the
# contract test validates against.
record:
	review-bot sample_diffs/auth_bypass.diff --record tests/fixtures --verbose

# The M6 demo (§19). Replays the committed response cache over three sample diffs.
# No key, no network, no spend — safe to run anywhere, including on a fresh clone.
demo:
	bash scripts/demo.sh

# Rebuild the demo's response cache from live responses. Manual only, like `smoke`.
# One call pair per sample diff. Needs ANTHROPIC_API_KEY. Kept separate from `record`
# because that target owns the test fixtures and this one owns the demo (§17, §19).
record-cache:
	@for d in sample_diffs/*.diff; do \
		echo "== $$d"; \
		review-bot "$$d" --cache --verbose >/dev/null || exit 1; \
	done
