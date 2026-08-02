"""Local pipeline benchmark. No network, no API key, no cost.

Times the deterministic stages — parse, mask, scan, filter/pack — against synthetic diffs
of growing size. Those are the only stages worth benchmarking: the two LLM calls dominate
any real run by two or three orders of magnitude, and their cost is network latency, which
a local benchmark cannot measure and `--verbose` already reports per run (§9).

The number to watch is the per-file column. Flat is correct; a rising per-file cost means a
stage has acquired fixed setup work that is being paid once per file instead of once per
run. That is exactly the bug the masker had.

    make bench
"""

from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from review_bot.diff_parser import parse_diff
from review_bot.prompt_builder import filter_files, pack
from review_bot.role_scanner import scan_diff
from review_bot.secret_masker import mask_diff

REPEATS = 5
FILE_COUNTS = (1, 5, 20, 100)

#: One file's worth of diff, carrying a hit for several rules at once so no stage is
#: benchmarked against input it would trivially skip.
_TEMPLATE = """diff --git a/src/app/mod{i}.py b/src/app/mod{i}.py
index 1111111..2222222 100644
--- a/src/app/mod{i}.py
+++ b/src/app/mod{i}.py
@@ -1,4 +1,8 @@
 import hashlib
-@requires_role("admin")
 def handler{i}(request, uid):
+    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
+    digest = hashlib.md5(uid.encode()).hexdigest()
+    cursor.execute(f"SELECT * FROM users WHERE id = {{uid}}")
+    log.info("session token: %s", request.session_token)
+    return redirect(request.GET.get("next"))
     return None
"""


def synthetic_diff(file_count: int) -> str:
    return "".join(_TEMPLATE.format(i=i) for i in range(file_count))


def time_it(fn, repeats: int = REPEATS) -> float:
    """Best-of-N seconds. The minimum, not the mean: the noise on a shared machine is
    always additive, so the fastest run is the one least polluted by it."""
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)
    return min(samples)


def main() -> int:
    print(f"pipeline benchmark — deterministic stages only, best of {REPEATS}\n")
    columns = ("files", "parse", "mask", "scan", "pack", "total", "per file")
    header = " ".join(f"{c:>9}" for c in columns)
    print(header)
    print("-" * len(header))

    per_file_costs = []
    for count in FILE_COUNTS:
        text = synthetic_diff(count)

        # Each stage gets a freshly parsed diff, and the parse is subtracted back out:
        # masking rewrites line content in place, so timing it twice over one object would
        # measure a second pass over already-masked lines.
        parse_s = time_it(lambda t=text: parse_diff(t))
        mask_s = time_it(lambda t=text: mask_diff(parse_diff(t))) - parse_s
        scan_s = time_it(lambda t=text: scan_diff(parse_diff(t))) - parse_s
        def pack_stage(t=text):
            return pack(filter_files(parse_diff(t)).reviewable, 8000)

        pack_s = time_it(pack_stage) - parse_s

        total = parse_s + mask_s + scan_s + pack_s
        per_file = total / count
        per_file_costs.append(per_file)

        cells = (count, _ms(parse_s), _ms(mask_s), _ms(scan_s), _ms(pack_s), _ms(total),
                 _ms(per_file))
        print(" ".join(f"{c:>9}" for c in cells))

    drift = max(per_file_costs) / min(per_file_costs)
    print(f"\nper-file cost spread: {drift:.1f}x across {FILE_COUNTS[0]}–{FILE_COUNTS[-1]} files")
    print(f"median per-file cost: {_ms(statistics.median(per_file_costs))}")
    return 0


def _ms(seconds: float) -> str:
    return f"{seconds * 1000:.2f}ms"


if __name__ == "__main__":
    raise SystemExit(main())
