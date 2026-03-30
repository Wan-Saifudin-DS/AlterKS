"""AlterKS policy configuration loader.

Reads ``[tool.alterks]`` from a project's ``pyproject.toml`` and produces an
:class:`AlterKSConfig` instance with validated, merged defaults.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[no-redef]

from alterks.models import PolicyAction, Severity

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_SEVERITY_ACTIONS: Dict[str, str] = {
    "critical": "block",
    "high": "block",
    "medium": "alert",
    "low": "allow",
}

DEFAULT_HEURISTIC_WEIGHTS: Dict[str, float] = {
    "typosquatting": 0.30,
    "package_age": 0.20,
    "maintainer_count": 0.15,
    "release_pattern": 0.15,
    "metadata_quality": 0.20,
}

DEFAULT_RISK_THRESHOLD: float = 60.0


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------
@dataclass
class AlterKSConfig:
    """Validated AlterKS policy configuration."""

    severity_actions: Dict[Severity, PolicyAction] = field(default_factory=dict)
    risk_threshold: float = DEFAULT_RISK_THRESHOLD
    allowlist: list[str] = field(default_factory=list)
    blocklist: list[str] = field(default_factory=list)
    heuristic_weights: Dict[str, float] = field(default_factory=dict)
    fail_closed: bool = False

    def __post_init__(self) -> None:
        if not self.severity_actions:
            self.severity_actions = _parse_severity_actions(DEFAULT_SEVERITY_ACTIONS)
        if not self.heuristic_weights:
            self.heuristic_weights = dict(DEFAULT_HEURISTIC_WEIGHTS)

    # -- query helpers -------------------------------------------------------

    def action_for_severity(self, severity: Severity) -> PolicyAction:
        """Return the configured action for a given severity level."""
        return self.severity_actions.get(severity, PolicyAction.ALLOW)

    def is_allowed(self, package_name: str) -> bool:
        """Check if a package is unconditionally allowed."""
        return _normalise(package_name) in {_normalise(p) for p in self.allowlist}

    def is_blocked(self, package_name: str) -> bool:
        """Check if a package is unconditionally blocked."""
        return _normalise(package_name) in {_normalise(p) for p in self.blocklist}

    def exceeds_risk_threshold(self, risk_score: float) -> bool:
        """Return True if the risk score exceeds the configured threshold."""
        return risk_score >= self.risk_threshold


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(
    pyproject_path: Optional[Path] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> AlterKSConfig:
    """Load AlterKS config from ``pyproject.toml``.

    Parameters
    ----------
    pyproject_path:
        Explicit path to a ``pyproject.toml``. When *None*, searches
        the current directory and its parents.
    overrides:
        Extra key/value pairs that take precedence over the file.

    Returns
    -------
    AlterKSConfig
        Fully resolved configuration with defaults applied.
    """
    raw: Dict[str, Any] = {}

    if pyproject_path is None:
        pyproject_path = _find_pyproject()

    if pyproject_path is not None:
        raw = _read_tool_section(pyproject_path)

    if overrides:
        raw.update(overrides)

    return _build_config(raw)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_pyproject() -> Optional[Path]:
    """Walk from CWD upward looking for ``pyproject.toml``."""
    current = Path.cwd().resolve()
    for directory in (current, *current.parents):
        candidate = directory / "pyproject.toml"
        if candidate.is_file():
            return candidate
    return None


def _read_tool_section(path: Path) -> Dict[str, Any]:
    """Read ``[tool.alterks]`` from a TOML file."""
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    return data.get("tool", {}).get("alterks", {})


def _build_config(raw: Dict[str, Any]) -> AlterKSConfig:
    """Build an :class:`AlterKSConfig` from a raw dict."""
    severity_actions = _parse_severity_actions(
        raw.get("severity_actions", DEFAULT_SEVERITY_ACTIONS)
    )

    risk_threshold = float(raw.get("risk_threshold", DEFAULT_RISK_THRESHOLD))

    allowlist = [str(p) for p in raw.get("allowlist", [])]
    blocklist = [str(p) for p in raw.get("blocklist", [])]

    raw_weights = raw.get("heuristic_weights", DEFAULT_HEURISTIC_WEIGHTS)
    heuristic_weights = {str(k): float(v) for k, v in raw_weights.items()}

    return AlterKSConfig(
        severity_actions=severity_actions,
        risk_threshold=risk_threshold,
        allowlist=allowlist,
        blocklist=blocklist,
        heuristic_weights=heuristic_weights,
        fail_closed=bool(raw.get("fail_closed", False)),
    )


def _parse_severity_actions(mapping: Dict[str, str]) -> Dict[Severity, PolicyAction]:
    """Convert string-keyed severity→action mapping to typed enums."""
    result: Dict[Severity, PolicyAction] = {}
    for sev_str, act_str in mapping.items():
        severity = Severity.from_str(sev_str)
        try:
            action = PolicyAction(act_str.lower())
        except ValueError:
            action = PolicyAction.ALLOW
        result[severity] = action
    return result


def _normalise(name: str) -> str:
    """Normalise a PyPI package name for comparison (PEP 503)."""
    import re
    return re.sub(r"[-_.]+", "-", name).lower()
