"""Pip install wrapper — resolve a package from PyPI, scan it, and decide.

Provides the ``resolve_and_scan`` function used by ``alterks install`` and
a ``generate_constraints`` helper that outputs a pip constraint file blocking
known-bad versions.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Tuple

from packaging.requirements import InvalidRequirement, Requirement

from alterks.config import AlterKSConfig, load_config
from alterks.heuristics import compute_risk
from alterks.models import PackageRisk, PolicyAction, ScanResult, validate_package_name, validate_package_version
from alterks.scanner import Scanner
from alterks.sources.pypi import PyPIClient, PyPIError

logger = logging.getLogger(__name__)


def resolve_and_scan(
    spec: str,
    config: Optional[AlterKSConfig] = None,
) -> Optional[ScanResult]:
    """Resolve a pip-style package spec and scan it.

    Parameters
    ----------
    spec:
        Package specification (e.g. ``requests==2.31.0`` or ``requests``).
    config:
        AlterKS configuration.  When *None*, the default is loaded.

    Returns
    -------
    ScanResult or None
        The scan result with vulnerability + heuristic info, or *None* if
        the package could not be resolved on PyPI.
    """
    config = config or load_config()
    name, version = _parse_spec(spec)

    # Resolve latest version from PyPI if not pinned
    pypi = PyPIClient()
    try:
        metadata = pypi.get_metadata(name)
    except PyPIError as exc:
        logger.error("Failed to resolve %s on PyPI: %s", name, exc)
        return None

    if version is None:
        version = metadata.version
        logger.info("Resolved %s to version %s", name, version)

    # Vulnerability scan via OSV
    scanner = Scanner(config=config)
    result = scanner.scan_package(name, version)

    # Heuristic risk assessment
    try:
        risk = compute_risk(name, version, metadata, config)
        result.risk = risk
    except Exception as exc:
        logger.warning("Heuristic scoring failed for %s: %s", name, exc)

    return result


def generate_constraints(
    config: Optional[AlterKSConfig] = None,
) -> str:
    """Generate a pip constraints file that blocks vulnerable packages.

    Scans the current environment and emits ``pkg!=bad_version`` lines
    for every package version that would be blocked by the current policy.

    Returns the constraint file content as a string.
    """
    config = config or load_config()
    scanner = Scanner(config=config)
    results = scanner.scan_environment()

    lines: List[str] = [
        "# AlterKS auto-generated constraints",
        "# Blocks package versions with known vulnerabilities",
        "",
    ]

    for r in sorted(results, key=lambda x: x.name):
        if r.action in (PolicyAction.BLOCK, PolicyAction.QUARANTINE):
            lines.append(f"{r.name}!={r.version}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_spec(spec: str) -> Tuple[str, Optional[str]]:
    """Parse a pip-style spec into ``(name, version_or_None)``.

    Uses :class:`packaging.requirements.Requirement` for rigorous parsing,
    preventing argument injection via crafted version strings.

    Raises
    ------
    ValueError
        If the spec is not a valid PEP 508 requirement or the parsed
        name/version fails safety validation.
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("Empty package spec.")

    try:
        req = Requirement(spec)
    except InvalidRequirement as exc:
        raise ValueError(f"Invalid package spec: {spec!r} ({exc})") from exc

    name = validate_package_name(req.name)

    # Extract pinned version from == specifier if present
    version: Optional[str] = None
    for specifier in req.specifier:
        if specifier.operator == "==":
            version = validate_package_version(specifier.version)
            break

    return name, version
