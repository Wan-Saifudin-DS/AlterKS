"""Core data models for AlterKS."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

# PEP 508 / PyPI: package names consist of ASCII letters, digits, -, _, .
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")
# Version: digits, dots, pre/post/dev markers, local — no spaces or flags
_SAFE_VERSION_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9._+-]*[A-Za-z0-9])?$"
)


def validate_package_name(name: str) -> str:
    """Validate and return *name*, or raise ``ValueError``.

    Rejects strings that could be interpreted as command-line flags or
    contain shell metacharacters.
    """
    if not name or not _SAFE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid package name: {name!r}. "
            "Names must contain only ASCII letters, digits, '.', '-', or '_'."
        )
    return name


def validate_package_version(version: str) -> str:
    """Validate and return *version*, or raise ``ValueError``.

    Rejects strings that could be interpreted as command-line flags or
    contain shell metacharacters.
    """
    if not version or not _SAFE_VERSION_RE.match(version):
        raise ValueError(
            f"Invalid package version: {version!r}. "
            "Versions must contain only ASCII letters, digits, '.', '-', '+', or '_'."
        )
    return version


def normalise_name(name: str) -> str:
    """PEP 503 package-name normalisation.

    Replaces runs of ``-``, ``_``, or ``.`` with a single ``-`` and
    lowercases the result so that ``My_Package``, ``my.package``, and
    ``my-package`` all compare equal.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


class PolicyAction(enum.Enum):
    """Action to take when a risky or vulnerable package is detected."""

    BLOCK = "block"
    QUARANTINE = "quarantine"
    ALERT = "alert"
    ALLOW = "allow"


class Severity(enum.Enum):
    """Vulnerability severity levels, ordered from most to least severe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: str) -> Severity:
        """Parse a severity string (case-insensitive) into a Severity enum.

        Falls back to UNKNOWN for unrecognised values.
        """
        try:
            return cls(value.lower())
        except ValueError:
            return cls.UNKNOWN

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.UNKNOWN,
        ]
        return order.index(self) > order.index(other)

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self == other or self < other

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return not self <= other

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return not self < other


@dataclass(frozen=True)
class Vulnerability:
    """A single known vulnerability affecting a package."""

    id: str
    summary: str = ""
    severity: Severity = Severity.UNKNOWN
    fix_versions: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    details: str = ""
    published: Optional[datetime] = None
    modified: Optional[datetime] = None

    @property
    def has_fix(self) -> bool:
        return len(self.fix_versions) > 0


@dataclass
class RiskFactor:
    """A single heuristic risk signal contributing to the overall risk score."""

    name: str
    score: float  # 0.0 – 1.0 (normalised)
    weight: float  # weight in composite calculation
    reason: str = ""
    file_path: Optional[str] = None
    line_range: Optional[str] = None

    @property
    def weighted_score(self) -> float:
        return self.score * self.weight


@dataclass
class PackageRisk:
    """Heuristic risk assessment for a package based on PyPI metadata."""

    name: str
    version: str
    risk_score: float = 0.0  # composite 0–100
    risk_factors: list[RiskFactor] = field(default_factory=list)

    @property
    def is_risky(self) -> bool:
        return self.risk_score > 0.0


@dataclass
class ScanResult:
    """Combined scan result for a single package: vulnerabilities + heuristic risk."""

    name: str
    version: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    risk: Optional[PackageRisk] = None
    action: PolicyAction = PolicyAction.ALLOW
    reason: str = ""

    @property
    def max_severity(self) -> Severity:
        """Return the highest severity across all vulnerabilities."""
        if not self.vulnerabilities:
            return Severity.UNKNOWN
        return max(self.vulnerabilities, key=lambda v: v.severity).severity

    @property
    def is_vulnerable(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def risk_score(self) -> float:
        return self.risk.risk_score if self.risk else 0.0

    @property
    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities)
