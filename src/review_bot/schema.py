"""Output schema (pipeline stage 6).

This module owns the pydantic models for the whole tool (SPEC.md §4). M3 needs only the
models themselves, because `secret_masker` and `role_scanner` both emit `Finding`s.

**Not yet implemented — M4 work:** line validation (§11), finding merge, dedupe, and
confidence promotion (§12). The models are deliberately here and not in a new module so
those additions land on the file that already owns them.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["low", "medium", "high"]
Confidence = Literal["low", "medium", "high"]
Category = Literal[
    "auth_perms",
    "input_validation",
    "injection",
    "hardcoded_secrets",
    "sensitive_logging",
    "unsafe_redirects",
    "dependency_change",
    "crypto_misuse",
]
Source = Literal["deterministic", "llm", "both"]

#: Categories the LLM is allowed to report. `hardcoded_secrets` is deterministic-only —
#: a masked value cannot be evidenced without unmasking it (§5).
LLM_CATEGORIES: frozenset[str] = frozenset(
    {
        "auth_perms",
        "input_validation",
        "injection",
        "sensitive_logging",
        "unsafe_redirects",
        "dependency_change",
        "crypto_misuse",
    }
)


class Finding(BaseModel):
    """One security finding.

    `source` and `rule_id` are internal-only tuning fields. They serialize under their
    `_`-prefixed aliases and are stripped from user-facing output by `public_dict()`.
    """

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    file: str
    line: int | None = None
    """Post-file line number, or None for a file-level finding (§11)."""
    category: Category
    severity: Severity
    confidence: Confidence
    evidence: str
    risk: str
    recommendation: str

    source: Source = Field(default="deterministic", alias="_source")
    rule_id: str | None = Field(default=None, alias="_rule_id")

    def public_dict(self) -> dict:
        """The finding as it reaches the reviewer, with internal fields stripped (§10)."""
        return self.model_dump(exclude={"source", "rule_id"})

    def dedupe_key(self) -> tuple[str, int | None, str]:
        """Dedupe identity per §12.1."""
        return (self.file, self.line, self.category)

    def sort_key(self) -> tuple[str, int, str]:
        """Byte-stable ordering for prompt serialization: `(file, line, category)` (§8)."""
        return (self.file, -1 if self.line is None else self.line, self.category)


class Review(BaseModel):
    """The full run output. JSON is the source of truth; Markdown renders from it (§10)."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    overall_risk: Severity
    findings: list[Finding] = Field(default_factory=list)
    pr_comment: str
    no_findings_reason: str | None = None

    def public_dict(self) -> dict:
        return {
            "summary": self.summary,
            "overall_risk": self.overall_risk,
            "findings": [f.public_dict() for f in self.findings],
            "pr_comment": self.pr_comment,
            "no_findings_reason": self.no_findings_reason,
        }
