"""Scan orchestrator — ties vulnerability sources and config into scan results.

Provides functions to scan:
- A single package by name + version
- An entire installed Python environment
- A requirements file (``requirements.txt`` or ``pyproject.toml`` deps)
"""

from __future__ import annotations

import importlib.metadata
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from packaging.requirements import Requirement

from alterks.config import AlterKSConfig, load_config
from alterks.models import PolicyAction, ScanResult, Severity, Vulnerability
from alterks.sources.osv import OSVClient

logger = logging.getLogger(__name__)


class Scanner:
    """High-level scanning orchestrator.

    Parameters
    ----------
    config:
        Policy configuration.  When *None* the default config is loaded from
        the nearest ``pyproject.toml``.
    osv_client:
        Pre-built OSV client.  When *None* a default is created.
    """

    def __init__(
        self,
        config: Optional[AlterKSConfig] = None,
        osv_client: Optional[OSVClient] = None,
    ) -> None:
        self.config = config or load_config()
        self.osv = osv_client or OSVClient()

    # -- Public API ----------------------------------------------------------

    def scan_package(self, name: str, version: str) -> ScanResult:
        """Scan a single package for vulnerabilities.

        Returns a :class:`ScanResult` with the appropriate policy action
        already resolved.
        """
        # Short-circuit on allowlist / blocklist
        if self.config.is_allowed(name):
            return ScanResult(
                name=name,
                version=version,
                action=PolicyAction.ALLOW,
                reason="Package is on the allowlist",
            )

        if self.config.is_blocked(name):
            return ScanResult(
                name=name,
                version=version,
                action=PolicyAction.BLOCK,
                reason="Package is on the blocklist",
            )

        # Query OSV for vulnerabilities
        try:
            vulns = self.osv.query_package(name, version)
        except Exception as exc:
            logger.error("OSV query failed for %s==%s: %s", name, version, exc)
            vulns = []

        action, reason = self._resolve_action(name, version, vulns)

        return ScanResult(
            name=name,
            version=version,
            vulnerabilities=vulns,
            action=action,
            reason=reason,
        )

    def scan_environment(self) -> List[ScanResult]:
        """Scan all packages installed in the current Python environment."""
        packages = _get_installed_packages()
        if not packages:
            logger.info("No installed packages found")
            return []

        return self._scan_packages(packages)

    def scan_requirements(self, path: Path) -> List[ScanResult]:
        """Scan packages listed in a requirements file.

        Supports ``requirements.txt`` format.  Only pinned versions
        (``pkg==X.Y.Z``) are scanned; unpinned deps are skipped with a
        warning.
        """
        packages = _parse_requirements_file(path)
        if not packages:
            logger.info("No scannable packages found in %s", path)
            return []

        return self._scan_packages(packages)

    # -- Internals -----------------------------------------------------------

    def _scan_packages(
        self, packages: Sequence[Tuple[str, str]]
    ) -> List[ScanResult]:
        """Batch-scan a list of (name, version) tuples via OSV."""
        results: List[ScanResult] = []

        # Separate allowlisted/blocklisted from those needing OSV scan
        to_query: List[Tuple[str, str]] = []
        for name, version in packages:
            if self.config.is_allowed(name):
                results.append(ScanResult(
                    name=name,
                    version=version,
                    action=PolicyAction.ALLOW,
                    reason="Package is on the allowlist",
                ))
            elif self.config.is_blocked(name):
                results.append(ScanResult(
                    name=name,
                    version=version,
                    action=PolicyAction.BLOCK,
                    reason="Package is on the blocklist",
                ))
            else:
                to_query.append((name, version))

        if not to_query:
            return results

        # Batch query OSV
        try:
            batch_vulns = self.osv.query_batch(to_query)
        except Exception as exc:
            logger.error("OSV batch query failed: %s", exc)
            batch_vulns = {pkg: [] for pkg in to_query}

        for name, version in to_query:
            vulns = batch_vulns.get((name, version), [])
            action, reason = self._resolve_action(name, version, vulns)
            results.append(ScanResult(
                name=name,
                version=version,
                vulnerabilities=vulns,
                action=action,
                reason=reason,
            ))

        return results

    def _resolve_action(
        self,
        name: str,
        version: str,
        vulns: List[Vulnerability],
    ) -> Tuple[PolicyAction, str]:
        """Determine the policy action for a package based on its vulnerabilities."""
        if not vulns:
            return PolicyAction.ALLOW, "No known vulnerabilities"

        # Find the highest severity across all vulns
        max_severity = Severity.UNKNOWN
        for v in vulns:
            if v.severity > max_severity:
                max_severity = v.severity

        action = self.config.action_for_severity(max_severity)

        vuln_ids = ", ".join(v.id for v in vulns[:5])
        suffix = f" (+{len(vulns) - 5} more)" if len(vulns) > 5 else ""
        reason = (
            f"{len(vulns)} vulnerabilit{'y' if len(vulns) == 1 else 'ies'} found "
            f"(max severity: {max_severity.value}): {vuln_ids}{suffix}"
        )

        return action, reason


# ---------------------------------------------------------------------------
# Environment introspection
# ---------------------------------------------------------------------------

def _get_installed_packages() -> List[Tuple[str, str]]:
    """Return ``(name, version)`` for every installed package."""
    packages: List[Tuple[str, str]] = []
    for dist in importlib.metadata.distributions():
        name = dist.metadata.get("Name")
        version = dist.metadata.get("Version")
        if name and version:
            packages.append((name, version))
    return sorted(set(packages))


# ---------------------------------------------------------------------------
# Requirements file parsing
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"(^|\s)#.*$")
_OPTIONS_RE = re.compile(r"^-[a-zA-Z]|^--[a-z]")


def _parse_requirements_file(path: Path) -> List[Tuple[str, str]]:
    """Parse a ``requirements.txt`` and return pinned ``(name, version)`` pairs.

    Lines that are not pinned (e.g. ``requests>=2.0``) are logged as warnings
    and skipped, since we need an exact version for the OSV query.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Requirements file not found: {path}")

    packages: List[Tuple[str, str]] = []
    text = path.read_text(encoding="utf-8")

    for raw_line in text.splitlines():
        line = _COMMENT_RE.sub("", raw_line).strip()
        if not line:
            continue
        # Skip pip options (e.g. -i, --index-url, -r)
        if _OPTIONS_RE.match(line):
            continue

        try:
            req = Requirement(line)
        except Exception:
            logger.warning("Could not parse requirement line: %s", raw_line.strip())
            continue

        # Extract pinned version from specifiers like "==1.2.3"
        pinned_version = _extract_pinned_version(req)
        if pinned_version:
            packages.append((req.name, pinned_version))
        else:
            logger.warning(
                "Skipping unpinned requirement %s (only ==X.Y.Z is scannable)",
                req.name,
            )

    return packages


def _extract_pinned_version(req: Requirement) -> Optional[str]:
    """Return the pinned version if the requirement has exactly ``==X.Y.Z``."""
    for spec in req.specifier:
        if spec.operator == "==":
            return spec.version
    return None
