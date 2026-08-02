"""Secret masking (pipeline stage 2, SPEC.md §5).

Runs on the parsed diff **before** anything reaches the network. Two jobs: rewrite
`DiffLine.content` in place so raw values become typed placeholders (preserving line
numbers and diff alignment), and emit the `hardcoded_secrets` findings directly. That
category is deterministic-only — the LLM never reports it, because a masked value cannot
be evidenced without unmasking it.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass

from detect_secrets.core import scan
from detect_secrets.settings import transient_settings

from .diff_parser import DiffLine, ParsedDiff, ParsedFile
from .schema import Confidence, Finding

RULE_ID = "secrets.detect_secrets"

#: Explicit plugin set. Pinned rather than inherited from `default_settings()` so a
#: detect-secrets upgrade cannot silently change what Tier 1 suppresses (§6).
_PLUGINS = [
    {"name": "AWSKeyDetector"},
    {"name": "AzureStorageKeyDetector"},
    {"name": "BasicAuthDetector"},
    {"name": "GitHubTokenDetector"},
    {"name": "JwtTokenDetector"},
    {"name": "KeywordDetector"},
    {"name": "PrivateKeyDetector"},
    {"name": "SlackDetector"},
    {"name": "StripeDetector"},
    {"name": "Base64HighEntropyString", "limit": 4.5},
    {"name": "HexHighEntropyString", "limit": 3.0},
]

#: detect-secrets type -> typed placeholder (§5).
_PLACEHOLDER_BY_TYPE = {
    "AWS Access Key": "[MASKED_AWS_KEY]",
    "Azure Storage Account access key": "[MASKED_KEY]",
    "Basic Auth Credentials": "[MASKED_DB_URL]",
    "GitHub Token": "[MASKED_TOKEN]",
    "JSON Web Token": "[MASKED_TOKEN]",
    "Private Key": "[MASKED_PRIVATE_KEY]",
    "Slack Token": "[MASKED_TOKEN]",
    "Stripe Access Key": "[MASKED_TOKEN]",
    "Secret Keyword": "[MASKED_KEY]",
    "Base64 High Entropy String": "[MASKED_KEY]",
    "Hex High Entropy String": "[MASKED_KEY]",
}

#: Lower number wins when several detectors fire on one line. Named detectors know what
#: they matched; entropy only knows the string looked random.
_TYPE_PRIORITY = {
    "Private Key": 0,
    "AWS Access Key": 1,
    "GitHub Token": 1,
    "Slack Token": 1,
    "Stripe Access Key": 1,
    "JSON Web Token": 1,
    "Azure Storage Account access key": 1,
    "Basic Auth Credentials": 2,
    "Secret Keyword": 3,
    "Base64 High Entropy String": 4,
    "Hex High Entropy String": 4,
}

#: `detect-secrets` verification is not enabled (it would require network calls against
#: live credentials), so `is_verified` is always False. Confidence therefore comes from
#: how specific the detector is — a documented reading of "the detect-secrets verdict" (§5).
_CONFIDENCE_BY_TYPE: dict[str, Confidence] = {
    "Private Key": "high",
    "AWS Access Key": "high",
    "GitHub Token": "high",
    "Slack Token": "high",
    "Stripe Access Key": "high",
    "JSON Web Token": "high",
    "Azure Storage Account access key": "high",
    "Basic Auth Credentials": "high",
    "Secret Keyword": "medium",
    "Base64 High Entropy String": "medium",
    "Hex High Entropy String": "medium",
}

#: Token-shaped variable names promote a generic keyword hit to `[MASKED_TOKEN]`.
_TOKEN_NAME_RE = re.compile(r"token|jwt|bearer|session|auth", re.IGNORECASE)
_DB_URL_RE = re.compile(
    r"\b(postgres|postgresql|mysql|mongodb|redis|amqp)(\+\w+)?://", re.IGNORECASE
)

#: Path signal per §5.
_TEST_PATH_RE = re.compile(
    r"(^|/)tests?/|(^|/)test_[^/]*$|(^|/)conftest\.py$|(^|/)fixtures/|_test\.[^/.]+$"
)

_ASSIGNMENT_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.\[\]\"']*)\s*[:=]\s*")
_QUOTED_RE = re.compile(r"(['\"`])(?:\\.|(?!\1).)*\1")


@dataclass
class MaskResult:
    """What the masker did, for the stages downstream."""

    findings: list[Finding]
    masked_line_count: int


def path_signal(path: str) -> str:
    """`test` if the path looks like test scaffolding, else `src` (§5)."""
    return "test" if _TEST_PATH_RE.search(path) else "src"


def mask_diff(diff: ParsedDiff) -> MaskResult:
    """Mask every line in `diff` in place and return the `hardcoded_secrets` findings.

    Every line kind is masked — added, removed, and context — because all three are quoted
    downstream: added lines by the prompt and the rules' evidence, removed and context
    lines by the prompt and the `auth_perms` rule. Invariants 1 and 7 are unconditional,
    so no line kind may carry a raw value past this stage.

    *Findings* are emitted for added lines only. A secret on a removed or context line was
    already in the repository and is not something this PR introduced; it is masked, not
    reported.
    """
    findings: list[Finding] = []
    masked = 0

    # Both context managers are entered once per *diff*, not once per file. Entering
    # `transient_settings` rebuilds every plugin object and busts detect-secrets' internal
    # caches, which profiles at roughly half of this stage's cost — paying that 40 times on
    # a 40-file diff is pure waste, since the settings are identical every time. Scoping is
    # unchanged: the block still closes before `mask_diff` returns, so no global state
    # leaks out of the stage.
    with transient_settings({"plugins_used": _PLUGINS}), tempfile.TemporaryDirectory() as tmpdir:
        for parsed_file in diff.files:
            file_findings, file_masked = _mask_file(parsed_file, tmpdir)
            findings.extend(file_findings)
            masked += file_masked

    findings.sort(key=lambda f: f.sort_key())
    return MaskResult(findings=findings, masked_line_count=masked)


def _mask_file(parsed_file: ParsedFile, tmpdir: str) -> tuple[list[Finding], int]:
    lines = [ln for hunk in parsed_file.hunks for ln in hunk.lines]
    if parsed_file.is_binary or not lines:
        return [], 0

    hits = _scan(parsed_file.path, [ln.content for ln in lines], tmpdir)
    signal = path_signal(parsed_file.path)

    findings: list[Finding] = []
    for index, secret_type in sorted(hits.items()):
        line = lines[index]
        placeholder = _placeholder_for(secret_type, line.content)
        line.content = _mask_line(line.content, placeholder, secret_type)
        if line.is_added:
            findings.append(_finding(parsed_file.path, line, secret_type, placeholder, signal))
    return findings, len(hits)


def _scan(path: str, contents: list[str], tmpdir: str) -> dict[int, str]:
    """Scan added-line contents; return `{index into contents: winning detector type}`.

    Uses `scan_file`, not `scan_line`, which is why the lines are written to a temp file
    first: `scan_line` runs with `enable_eager_search=True`, bypassing the entropy plugins'
    limit so that every word comes back a secret — `SELECT`, `FROM`, and `users` included.
    That is the adhoc "is this pasted string a secret" path, not a code scanner, and it
    would put Tier 1 hits all over `clean_but_suspicious.diff`. `scan_file` applies the
    real limits and filters.

    detect-secrets reports 1-based line numbers against the temp file, which map straight
    back onto `contents` by index. `tmpdir` and the plugin settings are owned by
    `mask_diff`, which enters both once for the whole diff.
    """
    if not contents:
        return {}

    # Keep the original basename so extension-driven filters behave as they would on the
    # real file, but nest it under a digest of the full path: `mask_diff` now shares one
    # temp directory across every file, and `src/a/config.py` and `src/b/config.py` would
    # otherwise overwrite each other's scan input.
    scan_dir = os.path.join(tmpdir, hashlib.sha256(path.encode()).hexdigest()[:16])
    os.makedirs(scan_dir, exist_ok=True)
    scan_path = os.path.join(scan_dir, os.path.basename(path) or "snippet.txt")
    with open(scan_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(contents) + "\n")
    potential = list(scan.scan_file(scan_path))

    best: dict[int, str] = {}
    for secret in potential:
        if secret.line_number is None:
            continue
        index = secret.line_number - 1
        if not 0 <= index < len(contents):
            continue
        current = best.get(index)
        if current is None or _rank(secret.type) < _rank(current):
            best[index] = secret.type
    return best


def _rank(secret_type: str) -> int:
    return _TYPE_PRIORITY.get(secret_type, 5)


def _placeholder_for(secret_type: str, content: str) -> str:
    """Typed placeholder, refined by what the line looks like for the generic detectors."""
    if secret_type in ("Secret Keyword", "Base64 High Entropy String", "Hex High Entropy String"):
        if _DB_URL_RE.search(content):
            return "[MASKED_DB_URL]"
        name = _assigned_name(content)
        if name and _TOKEN_NAME_RE.search(name):
            return "[MASKED_TOKEN]"
    return _PLACEHOLDER_BY_TYPE.get(secret_type, "[MASKED_KEY]")


def _mask_line(content: str, placeholder: str, secret_type: str) -> str:
    """Replace the credential on `content` with `placeholder`.

    The whole enclosing literal goes, not the value the detector reported, because several
    detectors report a *truncated* one — `GitHubTokenDetector` returns `ghp` for
    `ghp_16C7e42F...`, `StripeDetector` drops the last few characters. Substituting only
    what was reported would leave the rest of the credential in the prompt, breaking
    invariant 7. Where there is no literal, the value after the assignment operator goes.

    A private key line is replaced wholesale: PEM bodies are unquoted, span many lines, and
    there is no safe substring to keep.
    """
    if secret_type == "Private Key" and not _QUOTED_RE.search(content):
        indent = content[: len(content) - len(content.lstrip())]
        return f"{indent}{placeholder}"

    quoted = list(_QUOTED_RE.finditer(content))
    if quoted:
        # Mask every literal on the line. Masking only the one the detector pointed at
        # would leave a second credential on a two-assignment line untouched.
        result = content
        for match in reversed(quoted):
            quote = match.group(1)
            masked = f"{quote}{placeholder}{quote}"
            result = result[: match.start()] + masked + result[match.end() :]
        return result

    return _mask_bare_token(content, placeholder)


def _mask_bare_token(content: str, placeholder: str) -> str:
    """No string literal on the line — replace the value after the assignment operator."""
    match = _ASSIGNMENT_RE.search(content)
    if match:
        return content[: match.end()] + placeholder
    indent = content[: len(content) - len(content.lstrip())]
    return f"{indent}{placeholder}"


def _article(word: str) -> str:
    """"A"/"An" for the detector name that opens the risk sentence.

    The detector names are a fixed, known set (`_PLACEHOLDER_BY_TYPE`), so the vowel test is
    sufficient — no name in it starts with a silent or consonant-sounding vowel.
    """
    return "An" if word[:1].upper() in "AEIOU" else "A"


def _assigned_name(content: str) -> str | None:
    match = _ASSIGNMENT_RE.search(content)
    return match.group(1) if match else None


def _finding(path: str, line: DiffLine, secret_type: str, placeholder: str, signal: str) -> Finding:
    name = _assigned_name(line.content) or "a literal"
    where = f"line {line.line_no}" if line.line_no is not None else "an added line"
    return Finding(
        file=path,
        line=line.line_no,
        category="hardcoded_secrets",
        # A credential committed under a test path is still a leak, but the blast radius is
        # usually a fixture. §5 fixes the split at high/low on the path signal alone.
        severity="high" if signal == "src" else "low",
        confidence=_CONFIDENCE_BY_TYPE.get(secret_type, "medium"),
        evidence=f"`{name}` assigned a literal value at {where} (masked as {placeholder})",
        risk=(
            f"{_article(secret_type)} {secret_type} literal was added under a {signal} path. "
            "Anything committed to history should be treated as disclosed to everyone with "
            "repository access, including via forks and clones."
        ),
        recommendation=(
            "Move the value to an environment variable or secret store, and rotate the "
            "credential — the tool masks the value before review and so cannot confirm "
            "whether it is live."
        ),
        source = "deterministic", # type: ignore
        rule_id = RULE_ID, # type: ignore
    )
