"""Deterministic rules (pipeline stage 3).

Every non-secret deterministic rule lives here (SPEC.md §6). `hardcoded_secrets` is the
one category this module does not own — `secret_masker` emits it directly, because the
value is destroyed before this stage runs.

Two tiers, and the difference matters:

* **Tier 1** is high precision and *suppresses* LLM review of that `(file, line)`. A false
  positive here silently blinds the tool on that line, so these rules match only things
  whose identity is unambiguous.
* **Tier 2** is signal with ambiguous intent. It is emitted at `confidence: low` and does
  **not** suppress — the model reviews the line independently, and §12 promotes both to
  `high` if they agree.

Deterministic findings go straight into `findings[]` and never depend on a network call
(§12). Tier 2 hits are deliberately *not* fed to the model as hints.

## Ordering with the masker

This stage runs after `secret_masker`, so added lines may contain `[MASKED_*]`
placeholders. Keyword rules strip those before matching: the word `token` inside
`[MASKED_TOKEN]` is an artifact of masking, not evidence that the line logs a token, and
the masker has already reported that line.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .diff_parser import DiffLine, Hunk, ParsedDiff, ParsedFile
from .schema import Category, Confidence, Finding, Severity

# --------------------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(r"\[MASKED_[A-Z_]*\]")

#: §7 / §6 Tier 1 — dependency manifests and lockfiles.
_DEPENDENCY_BASENAMES = frozenset(
    {
        "pyproject.toml",
        "poetry.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "go.mod",
        "go.sum",
        "cargo.toml",
        "cargo.lock",
    }
)
_DEPENDENCY_PATTERNS = (
    re.compile(r"(^|/)requirements[^/]*\.txt$", re.IGNORECASE),
    # §6 writes this as the glob `requirements*.txt`, which misses the equally common
    # `requirements/base.txt` split-by-environment layout. Same concern, so same rule.
    re.compile(r"(^|/)requirements/[^/]+\.txt$", re.IGNORECASE),
    re.compile(r"(^|/)Gemfile[^/]*$"),
)

_WEAK_HASH_RE = re.compile(r"\bhashlib\.(md5|sha1)\b|\b(MD5|SHA1)\b")
_WEAK_CIPHER_RE = re.compile(r"\b(DES|RC4|ECB)\b|MODE_ECB")
_WEAK_RANDOM_RE = re.compile(r"\brandom\.random\(|\brandom\.randint\(|\bMath\.random\(")
_HARDCODED_IV_RE = re.compile(r"\b(iv|IV|nonce|NONCE)\s*=\s*b?['\"]")

_CODE_EXEC_RE = re.compile(r"(?<![\w.])(eval|exec)\s*\(|\bos\.system\s*\(|\bos\.popen\s*\(")
_SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True")
_EXECUTE_RE = re.compile(r"\.execute\w*\s*\(|\bcursor\.execute\b")
#: Dynamic string construction. `%s` inside a literal is a *parameterised* placeholder and
#: must not match — that is exactly what `clean_but_suspicious.diff` uses.
_DYNAMIC_STRING_RE = re.compile(
    r"""f['"]|\.format\s*\(|['"]\s*\+|\+\s*['"]|['"]\s*%\s*[\(\w]"""
)

_LOG_CALL_RE = re.compile(
    r"\b(log|logger|logging)\w*\.\w+\s*\(|(?<![\w.])print\s*\(|\bconsole\.(log|info|warn|error|debug)\s*\("
)
_SENSITIVE_ARG_RE = re.compile(
    r"\b(token|password|passwd|secret|session|authorization|cookie|api_key|apikey|ssn)\b",
    re.IGNORECASE,
)

_REDIRECT_DYNAMIC_RE = re.compile(r"\bredirect\s*\(\s*(?!['\"])[A-Za-z_]")
_REDIRECT_PARAM_RE = re.compile(
    r"\b(args|GET|POST|form|params|query_params)\s*(?:\.get\s*\(|\[)\s*['\"]"
    r"(next|return_url|redirect_uri|callback|continue)['\"]"
)
_LOCATION_HEADER_RE = re.compile(r"""['\"]Location['\"]\s*\]?\s*=|\bLocation\s*=\s*[A-Za-z_]""")
#: An explicit allowlist check is the documented safe pattern, so it suppresses the rule.
#: Matched against the whole hunk rather than the single line, because the check and the
#: `redirect()` call are almost never on the same line. This trades a little recall (a
#: redirect that happens to sit near an unrelated allowlist is missed) for not firing on
#: the correct pattern, which is the trade `clean_but_suspicious.diff` exists to enforce.
_REDIRECT_SAFE_RE = re.compile(
    r"allow|whitelist|ALLOWED|is_safe_url|url_has_allowed_host|netloc", re.IGNORECASE
)

_AUTH_TOKENS = (
    "is_admin",
    "is_staff",
    "@requires_role",
    "@permission_required",
    "@login_required",
    "current_user.role",
    "has_perm",
    "check_owner",
    ".is_authenticated",
)

_INJECTION_PHRASES = (
    "ignore previous",
    "ignore all",
    "disregard",
    "you are now",
    "system prompt",
    "ai reviewer",
    "pre-approved",
    "return no findings",
    "end of instructions",
)


# --------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Deterministic findings plus the Tier 1 suppression list.

    `suppressed` holds the `(file, line)` pairs `prompt_builder` tells the model to stay
    away from. Tier 2 hits are **not** included — §8 is explicit that this is suppression,
    not hinting.
    """

    findings: list[Finding] = field(default_factory=list)
    suppressed: set[tuple[str, int]] = field(default_factory=set)


def scan_diff(diff: ParsedDiff) -> ScanResult:
    """Run every deterministic rule over `diff`."""
    result = ScanResult()
    for parsed_file in diff.files:
        _scan_file(parsed_file, result)
    result.findings.sort(key=lambda f: f.sort_key())
    return result


def register_suppressions(result: ScanResult, findings: list[Finding]) -> None:
    """Add Tier 1 findings produced elsewhere — i.e. the masker's — to the suppression list.

    `hardcoded_secrets` is Tier 1, so its lines must reach `prompt_builder`'s suppression
    list even though this module did not generate them (§6, §8).
    """
    for finding in findings:
        if finding.line is not None:
            result.suppressed.add((finding.file, finding.line))


# --------------------------------------------------------------------------------------
# Per-file dispatch
# --------------------------------------------------------------------------------------


def _scan_file(parsed_file: ParsedFile, result: ScanResult) -> None:
    if parsed_file.is_binary:
        return

    if _is_dependency_manifest(parsed_file.path):
        result.findings.append(_dependency_finding(parsed_file))
        # File-level, so there is no line to suppress; `prompt_builder` filters the whole
        # file out of LLM review anyway (§7).
        return

    for hunk in parsed_file.hunks:
        redirect_guarded = any(
            _REDIRECT_SAFE_RE.search(_strip_placeholders(ln.content)) for ln in hunk.lines
        )
        for index, line in enumerate(hunk.lines):
            if line.is_added:
                _scan_added_line(parsed_file, line, result, redirect_guarded=redirect_guarded)
            elif line.is_removed:
                _scan_removed_line(parsed_file, hunk, index, line, result)


def _scan_added_line(
    parsed_file: ParsedFile, line: DiffLine, result: ScanResult, *, redirect_guarded: bool
) -> None:
    path = parsed_file.path
    content = line.content
    bare = _strip_placeholders(content)

    # ---- Tier 1 -----------------------------------------------------------------------
    for rule_id, pattern, detail in (
        ("crypto.weak_hash", _WEAK_HASH_RE, "a broken hash function (MD5/SHA1)"),
        ("crypto.weak_cipher", _WEAK_CIPHER_RE, "a broken cipher or mode (DES/RC4/ECB)"),
        ("crypto.weak_random", _WEAK_RANDOM_RE, "a non-cryptographic random source"),
        ("crypto.hardcoded_iv", _HARDCODED_IV_RE, "a hardcoded IV/nonce"),
    ):
        if pattern.search(bare):
            result.findings.append(
                _finding(
                    path,
                    line,
                    category="crypto_misuse",
                    severity="high" if rule_id != "crypto.weak_random" else "medium",
                    confidence="high",
                    rule_id=rule_id,
                    evidence=f"Added line uses {detail}: `{content.strip()}`",
                    risk=_CRYPTO_RISK[rule_id],
                    recommendation=_CRYPTO_FIX[rule_id],
                )
            )
            if line.line_no is not None:
                result.suppressed.add((path, line.line_no))

    # ---- Tier 2 -----------------------------------------------------------------------
    if _CODE_EXEC_RE.search(bare):
        result.findings.append(
            _finding(
                path,
                line,
                category="injection",
                severity="high",
                confidence="low",
                rule_id="injection.code_exec",
                evidence=f"Added line introduces a code-execution sink: `{content.strip()}`",
                risk=(
                    "If any part of the argument is attacker-influenced, this is arbitrary "
                    "code or command execution. The tool does no taint analysis, so it "
                    "cannot tell whether it is."
                ),
                recommendation=(
                    "Replace with a non-executing equivalent (`json.loads`, `ast.literal_eval`, "
                    "`subprocess.run` with an argument list). If the sink is required, state "
                    "in the PR where the argument comes from."
                ),
            )
        )

    if _SHELL_TRUE_RE.search(bare):
        result.findings.append(
            _finding(
                path,
                line,
                category="injection",
                severity="high",
                confidence="low",
                rule_id="injection.shell_true",
                evidence=f"Added line passes `shell=True`: `{content.strip()}`",
                risk=(
                    "`shell=True` sends the command through a shell, so any interpolated "
                    "value can inject further commands via `;`, `|`, or backticks."
                ),
                recommendation=(
                    "Pass the command as a list of arguments and drop `shell=True`."
                ),
            )
        )

    if _EXECUTE_RE.search(bare) and _DYNAMIC_STRING_RE.search(bare):
        result.findings.append(
            _finding(
                path,
                line,
                category="injection",
                severity="high",
                confidence="low",
                rule_id="injection.sql_string_build",
                evidence=f"Query built by string construction then executed: `{content.strip()}`",
                risk=(
                    "A query assembled with interpolation or concatenation is SQL injection "
                    "if any component is user-controlled."
                ),
                recommendation=(
                    "Use a parameterised query — pass placeholders in the SQL and the values "
                    "as the second argument to `execute`."
                ),
            )
        )

    if _LOG_CALL_RE.search(bare) and _SENSITIVE_ARG_RE.search(bare):
        matched = sorted({m.group(0).lower() for m in _SENSITIVE_ARG_RE.finditer(bare)})
        result.findings.append(
            _finding(
                path,
                line,
                category="sensitive_logging",
                severity="medium",
                confidence="low",
                rule_id="logging.sensitive_args",
                evidence=(
                    f"Log call references {', '.join(f'`{m}`' for m in matched)}: "
                    f"`{content.strip()}`"
                ),
                risk=(
                    "Logs are routinely shipped to third-party aggregators and retained far "
                    "longer than the credential's useful life, and they are often readable by "
                    "a much wider group than the application's data."
                ),
                recommendation=(
                    "Log a non-reversible identifier instead of the value, or redact the field "
                    "at the logger."
                ),
            )
        )

    if not redirect_guarded and (
        _REDIRECT_DYNAMIC_RE.search(bare)
        or _REDIRECT_PARAM_RE.search(bare)
        or _LOCATION_HEADER_RE.search(bare)
    ):
        result.findings.append(
            _finding(
                path,
                line,
                category="unsafe_redirects",
                severity="medium",
                confidence="low",
                rule_id="redirect.unsafe",
                evidence=f"Redirect target is not a literal: `{content.strip()}`",
                risk=(
                    "An externally controlled redirect target is an open redirect, used to "
                    "lend a trusted domain's credibility to a phishing page and to leak "
                    "tokens held in the URL."
                ),
                recommendation=(
                    "Validate the target against an allowlist of paths, or accept only "
                    "same-origin relative URLs."
                ),
            )
        )

    lowered = bare.lower()
    hit_phrases = [phrase for phrase in _INJECTION_PHRASES if phrase in lowered]
    if hit_phrases:
        result.findings.append(
            _finding(
                path,
                line,
                category="injection",
                # §6: high severity, medium confidence — an injection attempt in a PR is a
                # security event in its own right.
                severity="high",
                confidence="medium",
                rule_id="prompt_injection.phrases",
                evidence=(
                    f"Added line contains prompt-injection phrasing "
                    f"({', '.join(repr(p) for p in hit_phrases)}): `{content.strip()}`"
                ),
                risk=(
                    "The diff is attacker-controlled input that flows into an LLM prompt. "
                    "Text addressed at the reviewing model is an attempt to suppress or "
                    "steer this review, and is itself a reason to distrust the change."
                ),
                recommendation=(
                    "Review this change manually and treat the automated findings for this "
                    "file as unreliable. Ask the author why instruction-shaped text was added."
                ),
            )
        )


def _scan_removed_line(
    parsed_file: ParsedFile, hunk: Hunk, index: int, line: DiffLine, result: ScanResult
) -> None:
    """Tier 2 `auth_perms` — the one rule that reads removed lines (§6)."""
    content = line.content
    matched = [token for token in _AUTH_TOKENS if token in content]
    if not matched:
        return

    anchor = _anchor_line_no(hunk, index)
    where = f"removed at old line {line.source_line_no}"
    result.findings.append(
        Finding(
            file=parsed_file.path,
            # Removed lines have no post-image line number. The anchor is the nearest
            # surviving line so the reviewer can navigate; None degrades to a file-level
            # finding (§11).
            line=anchor,
            category="auth_perms",
            severity="high",
            confidence="low",
            evidence=(
                f"Authorisation check {', '.join(f'`{m}`' for m in matched)} was "
                f"{where}: `{content.strip()}`"
            ),
            risk=(
                "Removing an authorisation check widens who can reach the surrounding code. "
                "If the check was load-bearing, this is a privilege-escalation path."
            ),
            recommendation=(
                "Confirm in the PR that the check moved somewhere else — middleware, a "
                "decorator, or the caller — rather than being dropped."
            ),
            source="deterministic",
            rule_id="auth.removed_check",
        )
    )


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def _strip_placeholders(content: str) -> str:
    return _PLACEHOLDER_RE.sub("", content)


def _is_dependency_manifest(path: str) -> bool:
    basename = path.rsplit("/", 1)[-1]
    if basename.lower() in _DEPENDENCY_BASENAMES:
        return True
    return any(pattern.search(path) for pattern in _DEPENDENCY_PATTERNS)


def _anchor_line_no(hunk: Hunk, index: int) -> int | None:
    """Nearest post-image line number around `index`, searching forward then back."""
    for candidate in hunk.lines[index + 1 :]:
        if candidate.line_no is not None:
            return candidate.line_no
    for candidate in reversed(hunk.lines[:index]):
        if candidate.line_no is not None:
            return candidate.line_no
    return None


def _dependency_finding(parsed_file: ParsedFile) -> Finding:
    return Finding(
        file=parsed_file.path,
        # File-level: a manifest change is about the file, and §7 keeps these out of the
        # LLM entirely rather than shipping 4,000 lines of lockfile.
        line=None,
        category="dependency_change",
        severity="medium",
        confidence="high",
        evidence=f"Dependency manifest `{parsed_file.path}` was modified in this change",
        risk=(
            "A dependency change alters code that runs with the application's full "
            "privileges. This tool flags the change only; it does not assess the packages."
        ),
        recommendation=(
            "Review the added and upgraded packages against a software-composition-analysis "
            "tool, and confirm each new dependency is intended."
        ),
        source="deterministic",
        rule_id="dependency.manifest_path",
    )


_CRYPTO_RISK = {
    "crypto.weak_hash": (
        "MD5 and SHA1 are collision-broken. They are unsafe for signatures, integrity "
        "checks, and password storage."
    ),
    "crypto.weak_cipher": (
        "DES and RC4 are broken ciphers, and ECB mode leaks plaintext structure because "
        "identical blocks encrypt identically."
    ),
    "crypto.weak_random": (
        "`random` is a Mersenne Twister, not a CSPRNG. Its output is predictable from a "
        "short observed sequence, so it must not generate tokens, keys, or IDs."
    ),
    "crypto.hardcoded_iv": (
        "A fixed IV or nonce makes encryption deterministic, leaking whether two plaintexts "
        "match, and with counter modes it is a catastrophic key-recovery failure."
    ),
}

_CRYPTO_FIX = {
    "crypto.weak_hash": (
        "Use SHA-256 or better for integrity, and a password hash (argon2, bcrypt, scrypt) "
        "for credentials. If this is a non-security checksum, say so in the PR."
    ),
    "crypto.weak_cipher": "Use AES-GCM or ChaCha20-Poly1305 — an authenticated cipher.",
    "crypto.weak_random": "Use the `secrets` module (or `crypto.randomBytes` in Node).",
    "crypto.hardcoded_iv": "Generate a fresh random IV/nonce per message and store it alongside the ciphertext.",
}


def _finding(
    path: str,
    line: DiffLine,
    *,
    category: Category,
    severity: Severity,
    confidence: Confidence,
    rule_id: str,
    evidence: str,
    risk: str,
    recommendation: str,
) -> Finding:
    return Finding(
        file=path,
        line=line.line_no,
        category=category,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        risk=risk,
        recommendation=recommendation,
        source="deterministic",
        rule_id=rule_id,
    )
