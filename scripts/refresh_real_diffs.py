"""Re-fetch `real_diffs/` from GitHub (SPEC.md §25). Manual only — `make refresh-real-diffs`.

Not a pipeline stage and not imported by one, like `scripts/bench.py`. The diffs are
committed precisely so the test suite runs offline (§17), and this is the only thing in the
repository that reaches github.com.

`MANIFEST.json` is the input as well as the documentation: a new diff is added there first
and picked up here, which is what stops the directory from growing files whose provenance
nobody recorded.

Deliberately unauthenticated stdlib `urllib` rather than `gh`. These are public PRs, so an
anonymous diff fetch is rate-limited rather than forbidden, and a maintenance script should
not need the runtime dependency that `--pr` needs — `github_source.py` is the module under
test for that path, and this is not a test.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

REAL_DIFFS = Path(__file__).resolve().parent.parent / "real_diffs"
TIMEOUT = 30


def main() -> int:
    manifest = json.loads((REAL_DIFFS / "MANIFEST.json").read_text())

    failures = 0
    for entry in manifest["diffs"]:
        url = f"https://api.github.com/repos/{entry['repo']}/pulls/{entry['pr']}"
        request = urllib.request.Request(
            url, headers={"Accept": "application/vnd.github.v3.diff"}
        )
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                (REAL_DIFFS / entry["file"]).write_bytes(response.read())
        except (urllib.error.URLError, OSError) as exc:
            print(f"  FAILED {entry['file']:26} {entry['repo']}#{entry['pr']}: {exc}")
            failures += 1
            continue
        print(f"  {entry['file']:26} <- {entry['repo']}#{entry['pr']}")

    if failures:
        return 1

    print(
        "\nRun `make test`. `test_real_diffs.py` asserts the measured deterministic-finding\n"
        "count per diff, so a count that moved is a real signal — a force-push to a source PR,\n"
        "or a rule that changed. Find out which before updating MANIFEST.json."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
