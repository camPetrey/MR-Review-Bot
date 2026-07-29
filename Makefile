.PHONY: test lint smoke

test:
	pytest

lint:
	ruff check .

smoke:
	review-bot sample_diffs/auth_bypass.diff --dry-run
