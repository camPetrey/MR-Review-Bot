"""Deterministic rules (pipeline stage 3, SPEC.md §6).

Every non-secret deterministic rule lives here. `hardcoded_secrets` is the one category
this module does not own — `secret_masker` emits it directly, because the value is
destroyed before this stage runs.

Two tiers, and the difference is the whole design:

* **Tier 1** is high precision and *suppresses* LLM review of that `(file, line)`. A false
  positive here silently blinds the tool on that line, so these rules match only things
  whose identity is unambiguous.
* **Tier 2** is signal with ambiguous intent. Emitted at `confidence: low`, it does **not**
  suppress — the model reviews the line independently, and §12 promotes both to `high` if
  they agree.

Most rules are rows in `_ADDED_LINE_RULES`; adding one is a row plus a case in
`test_role_scanner.py`. The two that cannot be rows read something other than a single
added line: `auth_perms` reads *removed* lines, and `dependency_change` is file-level.
"""

from __future__ import annotations

import re
from collections.abc import Callable
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
    r"\b(log|logger|logging)\w*\.\w+\s*\(|(?<![\w.])print\s*\("
    r"|\bconsole\.(log|info|warn|error|debug)\s*\("
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
#: The `guard` for `redirect.unsafe` — see that row for why.
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
# The rule table (§6)
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Rule:
    """One deterministic rule over a single added line."""

    rule_id: str
    category: Category
    severity: Severity
    confidence: Confidence
    tier: int
    """1 suppresses LLM review of the matched line; 2 does not (§6)."""
    detect: Callable[[str], str | None]
    """Returns the evidence prefix on a hit, or None. Takes the placeholder-stripped line."""
    risk: str
    recommendation: str
    guard: re.Pattern[str] | None = None
    """If this matches anywhere in the hunk, the rule is skipped — a documented safe
    pattern nearby means the match is expected rather than suspicious."""


def _matches(*patterns: re.Pattern[str], detail: str) -> Callable[[str], str | None]:
    """Fires when any pattern hits — several spellings of one concern."""
    return lambda bare: detail if any(p.search(bare) for p in patterns) else None


def _matches_all(*patterns: re.Pattern[str], detail: str) -> Callable[[str], str | None]:
    """Fires only when every pattern hits — each alone is innocuous."""
    return lambda bare: detail if all(p.search(bare) for p in patterns) else None


def _detect_sensitive_log(bare: str) -> str | None:
    """Naming the matched keywords is what makes this finding actionable, so the evidence
    is built from the match rather than being a fixed string."""
    if not _LOG_CALL_RE.search(bare):
        return None
    matched = sorted({m.group(0).lower() for m in _SENSITIVE_ARG_RE.finditer(bare)})
    if not matched:
        return None
    return f"Log call references {', '.join(f'`{m}`' for m in matched)}"


def _detect_injection_phrases(bare: str) -> str | None:
    lowered = bare.lower()
    hits = [phrase for phrase in _INJECTION_PHRASES if phrase in lowered]
    if not hits:
        return None
    return f"Added line contains prompt-injection phrasing ({', '.join(repr(p) for p in hits)})"


#: One row per rule of §6. Order is preserved in the emitted findings, and matters only
#: among the crypto rules: they share a category, so two firing on one line collapse to one
#: finding at merge time (§12) and the first row wins.
_ADDED_LINE_RULES: tuple[_Rule, ...] = (
    # ---- Tier 1: unambiguous identity, suppresses LLM review of the line ---------------
    _Rule(
        rule_id="crypto.weak_hash",
        category="crypto_misuse",
        severity="high",
        confidence="high",
        tier=1,
        detect=_matches(_WEAK_HASH_RE, detail="Added line uses a broken hash function (MD5/SHA1)"),
        risk=(
            "MD5 and SHA1 are collision-broken. They are unsafe for signatures, integrity "
            "checks, and password storage."
        ),
        recommendation=(
            "Use SHA-256 or better for integrity, and a password hash (argon2, bcrypt, scrypt) "
            "for credentials. If this is a non-security checksum, say so in the PR."
        ),
    ),
    _Rule(
        rule_id="crypto.weak_cipher",
        category="crypto_misuse",
        severity="high",
        confidence="high",
        tier=1,
        detect=_matches(
            _WEAK_CIPHER_RE, detail="Added line uses a broken cipher or mode (DES/RC4/ECB)"
        ),
        risk=(
            "DES and RC4 are broken ciphers, and ECB mode leaks plaintext structure because "
            "identical blocks encrypt identically."
        ),
        recommendation="Use AES-GCM or ChaCha20-Poly1305 — an authenticated cipher.",
    ),
    _Rule(
        rule_id="crypto.weak_random",
        category="crypto_misuse",
        # Lower than the other crypto rules: a non-cryptographic RNG is only a finding if
        # the value it produces is security-bearing, and the line alone does not say.
        severity="medium",
        confidence="high",
        tier=1,
        detect=_matches(
            _WEAK_RANDOM_RE, detail="Added line uses a non-cryptographic random source"
        ),
        risk=(
            "`random` is a Mersenne Twister, not a CSPRNG. Its output is predictable from a "
            "short observed sequence, so it must not generate tokens, keys, or IDs."
        ),
        recommendation="Use the `secrets` module (or `crypto.randomBytes` in Node).",
    ),
    _Rule(
        rule_id="crypto.hardcoded_iv",
        category="crypto_misuse",
        severity="high",
        confidence="high",
        tier=1,
        detect=_matches(_HARDCODED_IV_RE, detail="Added line uses a hardcoded IV/nonce"),
        risk=(
            "A fixed IV or nonce makes encryption deterministic, leaking whether two plaintexts "
            "match, and with counter modes it is a catastrophic key-recovery failure."
        ),
        recommendation=(
            "Generate a fresh random IV/nonce per message and store it alongside the ciphertext."
        ),
    ),
    # ---- Tier 2: real pattern, ambiguous intent. Does not suppress --------------------
    _Rule(
        rule_id="injection.code_exec",
        category="injection",
        severity="high",
        confidence="low",
        tier=2,
        detect=_matches(_CODE_EXEC_RE, detail="Added line introduces a code-execution sink"),
        risk=(
            "If any part of the argument is attacker-influenced, this is arbitrary code or "
            "command execution. The tool does no taint analysis, so it cannot tell whether "
            "it is."
        ),
        recommendation=(
            "Replace with a non-executing equivalent (`json.loads`, `ast.literal_eval`, "
            "`subprocess.run` with an argument list). If the sink is required, state in the "
            "PR where the argument comes from."
        ),
    ),
    _Rule(
        rule_id="injection.shell_true",
        category="injection",
        severity="high",
        confidence="low",
        tier=2,
        detect=_matches(_SHELL_TRUE_RE, detail="Added line passes `shell=True`"),
        risk=(
            "`shell=True` sends the command through a shell, so any interpolated value can "
            "inject further commands via `;`, `|`, or backticks."
        ),
        recommendation="Pass the command as a list of arguments and drop `shell=True`.",
    ),
    _Rule(
        rule_id="injection.sql_string_build",
        category="injection",
        severity="high",
        confidence="low",
        tier=2,
        # Both halves are required: executing is fine, and building a string is fine. It is
        # building the string *into* the execute call that makes it a finding.
        detect=_matches_all(
            _EXECUTE_RE,
            _DYNAMIC_STRING_RE,
            detail="Query built by string construction then executed",
        ),
        risk=(
            "A query assembled with interpolation or concatenation is SQL injection if any "
            "component is user-controlled."
        ),
        recommendation=(
            "Use a parameterised query — pass placeholders in the SQL and the values as the "
            "second argument to `execute`."
        ),
    ),
    _Rule(
        rule_id="logging.sensitive_args",
        category="sensitive_logging",
        severity="medium",
        confidence="low",
        tier=2,
        detect=_detect_sensitive_log,
        risk=(
            "Logs are routinely shipped to third-party aggregators and retained far longer "
            "than the credential's useful life, and they are often readable by a much wider "
            "group than the application's data."
        ),
        recommendation=(
            "Log a non-reversible identifier instead of the value, or redact the field at "
            "the logger."
        ),
    ),
    _Rule(
        rule_id="redirect.unsafe",
        category="unsafe_redirects",
        severity="medium",
        confidence="low",
        tier=2,
        detect=_matches(
            _REDIRECT_DYNAMIC_RE,
            _REDIRECT_PARAM_RE,
            _LOCATION_HEADER_RE,
            detail="Redirect target is not a literal",
        ),
        # An explicit allowlist check is the documented safe pattern. Trading a little
        # recall (a redirect near an unrelated allowlist is missed) for not firing on the
        # correct pattern is the trade `clean_but_suspicious.diff` exists to enforce.
        guard=_REDIRECT_SAFE_RE,
        risk=(
            "An externally controlled redirect target is an open redirect, used to lend a "
            "trusted domain's credibility to a phishing page and to leak tokens held in "
            "the URL."
        ),
        recommendation=(
            "Validate the target against an allowlist of paths, or accept only same-origin "
            "relative URLs."
        ),
    ),
    _Rule(
        rule_id="prompt_injection.phrases",
        category="injection",
        # §6: high severity, medium confidence — an injection attempt in a PR is a security
        # event in its own right. Tier 2, so the reviewer sees both the attempt and
        # whatever the model made of the surrounding code.
        severity="high",
        confidence="medium",
        tier=2,
        detect=_detect_injection_phrases,
        risk=(
            "The diff is attacker-controlled input that flows into an LLM prompt. Text "
            "addressed at the reviewing model is an attempt to suppress or steer this "
            "review, and is itself a reason to distrust the change."
        ),
        recommendation=(
            "Review this change manually and treat the automated findings for this file as "
            "unreliable. Ask the author why instruction-shaped text was added."
        ),
    ),
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

    if is_dependency_manifest(parsed_file.path):
        result.findings.append(_dependency_finding(parsed_file))
        # File-level, so there is no line to suppress; `prompt_builder` filters the whole
        # file out of LLM review anyway (§7).
        return

    for hunk in parsed_file.hunks:
        # A rule's `guard` is matched against the whole hunk, not the single line, because
        # the safe pattern it looks for (an allowlist check) and the risky call are almost
        # never on the same line.
        hunk_text = "\n".join(_strip_placeholders(ln.content) for ln in hunk.lines)
        for index, line in enumerate(hunk.lines):
            if line.is_added:
                _scan_added_line(parsed_file, line, hunk_text, result)
            elif line.is_removed:
                _scan_removed_line(parsed_file, hunk, index, line, result)


def _scan_added_line(
    parsed_file: ParsedFile, line: DiffLine, hunk_text: str, result: ScanResult
) -> None:
    # Placeholders are stripped before matching: the word `token` inside `[MASKED_TOKEN]`
    # is an artifact of this stage running after `secret_masker`, not evidence that the
    # line logs a token — and the masker has already reported that line.
    bare = _strip_placeholders(line.content)

    for rule in _ADDED_LINE_RULES:
        if rule.guard is not None and rule.guard.search(hunk_text):
            continue
        detail = rule.detect(bare)
        if detail is None:
            continue

        result.findings.append(
            _finding(
                parsed_file.path,
                line,
                category=rule.category,
                severity=rule.severity,
                confidence=rule.confidence,
                rule_id=rule.rule_id,
                evidence=f"{detail}: `{line.content.strip()}`",
                risk=rule.risk,
                recommendation=rule.recommendation,
            )
        )
        # Only Tier 1 suppresses the model's review of this line (§6, §8).
        if rule.tier == 1 and line.line_no is not None:
            result.suppressed.add((parsed_file.path, line.line_no))


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


def is_dependency_manifest(path: str) -> bool:
    """True for the dependency manifests and lockfiles of §6 Tier 1.

    Public because `prompt_builder` needs the same predicate to filter these files out of
    LLM review (§7). The rule belongs to this module — the filter is a consequence of the
    rule, not a second definition of it.
    """
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
