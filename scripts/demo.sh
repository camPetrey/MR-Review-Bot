#!/usr/bin/env bash
#
# The M6 demo (SPEC.md §19). Runs the reviewer over three sample diffs and prints what a
# human reviewer would see on the pull request.
#
# **It runs unattended and costs nothing.** Every response is served from the committed
# `--cache` (§14), so there is no API key, no network call, and no spend — which is what
# makes this safe to run in front of an audience or on a machine that has never been
# configured. The cache is keyed by prompt bytes, and prompts are byte-stable (§8), so the
# same diffs replay the same review every time.
#
# A cold cache would silently degrade to deterministic-only findings (§12 keeps those alive
# whatever happens to the network), which is correct behaviour for the tool and a bad demo:
# the audience would be shown a partial review presented as a full one. So each run is
# checked for cache hits and the script aborts loudly instead.
#
# Regenerate the cache with `make record-cache` after changing a prompt or a sample diff.

set -euo pipefail

cd "$(dirname "$0")/.."

BOT=${REVIEW_BOT:-review-bot}
CACHE_DIR=${CACHE_DIR:-.review_bot_cache}

# Three diffs, chosen because together they are the whole argument for the tool:
#   auth_bypass          — the LLM pass finding a logic flaw no regex could describe
#   secrets_and_logging  — the deterministic layer, and masking that survives into output
#   clean_but_suspicious — the false-positive canary (§17), which must come back quiet
DIFFS=(auth_bypass secrets_and_logging clean_but_suspicious)

NOTE_auth_bypass="A permission check is removed behind a query parameter. Nothing here is a
pattern match — the finding requires reading what the branch actually does, which is the
half of the review the deterministic rules cannot do."

NOTE_secrets_and_logging="A credential and a logging change. The deterministic layer owns
both (§5, §6): they are found without a network call, and the secret is masked before the
prompt is built, so no raw value can reach the API or the output below."

NOTE_clean_but_suspicious="Code that reads alarming and is fine. This is the canary from
§17 — a reviewer who is paged for this stops reading the reviewer, so a quiet result here
is a feature under test, not a boring case."

rule() { printf '%s\n' "────────────────────────────────────────────────────────────────────────"; }

if [ ! -d "$CACHE_DIR" ]; then
    echo "error: no response cache at $CACHE_DIR." >&2
    echo "The demo replays recorded responses and never calls the API. Run" >&2
    echo "\`make record-cache\` with ANTHROPIC_API_KEY set to rebuild it." >&2
    exit 1
fi

cat <<'INTRO'

  Security PR Review Bot — demo

  A unified diff goes in; schema-validated findings and a PR-ready comment come out.
  Advisory only: it assists the reviewer and never gates the merge.

  Every review below is replayed from the recorded response cache. No API key is set,
  no request is sent, and the run costs nothing.

INTRO

for diff in "${DIFFS[@]}"; do
    note_var="NOTE_${diff}"
    rule
    echo "  sample_diffs/${diff}.diff"
    rule
    echo
    echo "${!note_var}"
    echo
    echo "\$ git diff origin/main...HEAD | review-bot - --cache"
    echo

    # Both streams are buffered, not streamed: the cache-hit check below has to run before
    # anything is shown, or a degraded review is already on screen by the time the script
    # says not to trust it. stderr is kept rather than discarded because the cache-hit log
    # and the §11 tuning counters are part of what the demo is demonstrating.
    out=$(mktemp)
    log=$(mktemp)
    status=0
    "$BOT" "sample_diffs/${diff}.diff" \
        --cache --cache-dir "$CACHE_DIR" --verbose >"$out" 2>"$log" || status=$?

    if ! grep -q 'cache hit' "$log"; then
        echo "error: ${diff} produced no cache hit, so this review is not the recorded one." >&2
        echo "Rebuild the cache with \`make record-cache\` before demoing." >&2
        sed 's/^/  /' "$log" >&2
        rm -f "$out" "$log"
        exit 1
    fi

    if [ "$status" -ne 0 ]; then
        echo "error: review-bot exited $status on ${diff}" >&2
        sed 's/^/  /' "$log" >&2
        rm -f "$out" "$log"
        exit "$status"
    fi

    cat "$out"
    echo
    echo "  --- run log (stderr) ---"
    sed 's/^/  /' "$log"
    rm -f "$out" "$log"
    echo
done

rule
cat <<'OUTRO'

  Where this sits in the review workflow

    git diff origin/main...HEAD | review-bot - --format both --output review.md

  That is the same command `.github/workflows/review.yml` runs on every pull request
  (§18). The job is advisory: it uploads review.md and review.json as build artifacts
  and writes the Markdown to the job summary. It never posts a comment and never blocks
  a merge — the exit code says whether the *tool* worked, not how bad the findings were.

  A fork PR gets no API key, so the workflow drops to --no-llm and still produces the
  deterministic findings. Partial coverage, stated as partial, beats no review.

OUTRO
