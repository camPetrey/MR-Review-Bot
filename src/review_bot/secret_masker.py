"""Secret masking (pipeline stage 2).

Runs on the parsed diff **before** anything reaches the network (SPEC.md §5). Two jobs:

1. Rewrite `DiffLine.content` in place so raw secret values are replaced by typed
   placeholders. Substitution preserves line numbers and diff alignment.
2. Emit the `hardcoded_secrets` findings directly. That category is deterministic-only —
   the LLM never reports it, because a masked value cannot be evidenced without
   unmasking it (§5).

## Why `scan_file` and not `scan_line`

`detect_secrets.core.scan.scan_line` runs with `enable_eager_search=True`, which bypasses
the entropy plugins' limit and flags every word on the line — `SELECT`, `FROM`, and
`users` all come back as high-entropy strings. That is the adhoc "is this pasted string a
secret" path, not a code scanner, and it would put Tier 1 hits all over
`clean_but_suspicious.diff`. `scan_file` applies the real limits and filters, so the added
lines are written to a temp file (keeping the original basename, so extension-based
filters still apply) and scanned there.

## Why the whole literal is masked, not the matched value

Several detectors return a *truncated* value: `GitHubTokenDetector` reports `ghp` for
`ghp_16C7e42F...`, and `StripeDetector` drops the last few characters. Substituting just
the reported value would leave the rest of the credential in the prompt, breaking the
"raw secret values never appear in output" invariant. So a flagged line has its enclosing
string literal replaced whole; where there is no literal, the value after the assignment
operator goes.
"""

from __future__ import annotations

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
    """Mask every added line in `diff` in place and return the `hardcoded_secrets` findings.

    Only added lines are scanned. A secret on a context or removed line was already in the
    repository and is not something this PR introduced.
    """
    findings: list[Finding] = []
    masked = 0
    for parsed_file in diff.files:
        file_findings, file_masked = _mask_file(parsed_file)
        findings.extend(file_findings)
        masked += file_masked
    findings.sort(key=lambda f: f.sort_key())
    return MaskResult(findings=findings, masked_line_count=masked)


def _mask_file(parsed_file: ParsedFile) -> tuple[list[Finding], int]:
    added = parsed_file.added_lines
    if parsed_file.is_binary or not added:
        return [], 0

    hits = _scan(parsed_file.path, [ln.content for ln in added])
    signal = path_signal(parsed_file.path)

    findings: list[Finding] = []
    for index, secret_type in sorted(hits.items()):
        line = added[index]
        placeholder = _placeholder_for(secret_type, line.content)
        line.content = _mask_line(line.content, placeholder, secret_type)
        findings.append(_finding(parsed_file.path, line, secret_type, placeholder, signal))
    return findings, len(hits)


def _scan(path: str, contents: list[str]) -> dict[int, str]:
    """Scan added-line contents; return `{index into contents: winning detector type}`.

    detect-secrets reports 1-based line numbers against the temp file, which map straight
    back onto `contents` by index.
    """
    if not contents:
        return {}

    with tempfile.TemporaryDirectory() as tmpdir:
        # Keep the original basename so extension-driven filters behave as they would on
        # the real file.
        scan_path = os.path.join(tmpdir, os.path.basename(path) or "snippet.txt")
        with open(scan_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(contents) + "\n")
        with transient_settings({"plugins_used": _PLUGINS}):
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
            result = result[: match.start()] + f"{quote}{placeholder}{quote}" + result[match.end() :]
        return result

    return _mask_bare_token(content, placeholder)


def _mask_bare_token(content: str, placeholder: str) -> str:
    """No string literal on the line — replace the value after the assignment operator."""
    match = _ASSIGNMENT_RE.search(content)
    if match:
        return content[: match.end()] + placeholder
    indent = content[: len(content) - len(content.lstrip())]
    return f"{indent}{placeholder}"


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
            f"A {secret_type} literal was added under a {signal} path. Anything committed to "
            "history should be treated as disclosed to everyone with repository access, "
            "including via forks and clones."
        ),
        recommendation=(
            "Move the value to an environment variable or secret store, and rotate the "
            "credential — the tool masks the value before review and so cannot confirm "
            "whether it is live."
        ),
        source="deterministic",
        rule_id=RULE_ID,
    )
