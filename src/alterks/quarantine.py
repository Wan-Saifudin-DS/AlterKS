"""Quarantine manager — isolate suspicious packages in per-package venvs.

Quarantined packages are installed into their own virtual environment under
``~/.alterks/quarantine/<normalised-name>/`` so they cannot affect the main
Python environment.  A JSON manifest at ``~/.alterks/quarantine.json`` tracks
all quarantined packages and their metadata.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import venv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from alterks.models import validate_package_name, validate_package_version

logger = logging.getLogger(__name__)

DEFAULT_QUARANTINE_DIR = Path.home() / ".alterks" / "quarantine"
DEFAULT_MANIFEST_PATH = Path.home() / ".alterks" / "quarantine.json"


class QuarantineReleaseBlocked(Exception):
    """Raised when a quarantined package still fails its re-scan on release."""


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

@dataclass
class QuarantineEntry:
    """Record for a single quarantined package."""

    name: str
    version: str
    reason: str
    venv_path: str
    quarantined_at: str = ""
    vulnerability_ids: List[str] = field(default_factory=list)
    risk_score: float = 0.0

    def __post_init__(self) -> None:
        if not self.quarantined_at:
            self.quarantined_at = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Manifest I/O
# ---------------------------------------------------------------------------

def _load_manifest(path: Path) -> Dict[str, dict]:
    """Load the quarantine manifest (package-name → entry dict)."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not load quarantine manifest %s: %s", path, exc)
    return {}


def _save_manifest(manifest: Dict[str, dict], path: Path) -> None:
    """Persist the quarantine manifest to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(manifest, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


def _normalise_name(name: str) -> str:
    """PEP 503 normalisation for quarantine keys."""
    import re
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# QuarantineManager
# ---------------------------------------------------------------------------

class QuarantineManager:
    """Manage quarantined Python packages.

    Parameters
    ----------
    quarantine_dir:
        Root directory for quarantine venvs.
    manifest_path:
        Path to ``quarantine.json`` manifest file.
    """

    def __init__(
        self,
        quarantine_dir: Path = DEFAULT_QUARANTINE_DIR,
        manifest_path: Path = DEFAULT_MANIFEST_PATH,
    ) -> None:
        self.quarantine_dir = quarantine_dir
        self.manifest_path = manifest_path

    # -- Public API ----------------------------------------------------------

    def quarantine_package(
        self,
        name: str,
        version: str,
        reason: str,
        vulnerability_ids: Optional[List[str]] = None,
        risk_score: float = 0.0,
    ) -> QuarantineEntry:
        """Install a package into an isolated quarantine venv.

        Creates a fresh virtual environment, installs the package there,
        and records an entry in the manifest.
        """
        # Validate inputs before any subprocess usage
        validate_package_name(name)
        validate_package_version(version)

        key = _normalise_name(name)
        venv_path = self.quarantine_dir / key

        # Create isolated venv
        logger.info("Creating quarantine venv at %s", venv_path)
        venv_path.mkdir(parents=True, exist_ok=True)
        venv.create(str(venv_path), with_pip=True, clear=True)

        # Install the package into the quarantine venv
        pip_exe = self._find_pip(venv_path)
        self._install_package(pip_exe, name, version)

        entry = QuarantineEntry(
            name=name,
            version=version,
            reason=reason,
            venv_path=str(venv_path),
            vulnerability_ids=vulnerability_ids or [],
            risk_score=risk_score,
        )

        # Update manifest
        manifest = _load_manifest(self.manifest_path)
        manifest[key] = asdict(entry)
        _save_manifest(manifest, self.manifest_path)

        logger.info("Quarantined %s==%s at %s", name, version, venv_path)
        return entry

    def list_quarantined(self) -> List[QuarantineEntry]:
        """List all quarantined packages."""
        manifest = _load_manifest(self.manifest_path)
        entries: List[QuarantineEntry] = []
        for data in manifest.values():
            try:
                entries.append(QuarantineEntry(**data))
            except TypeError:
                logger.warning("Skipping malformed quarantine entry: %s", data)
        return entries

    def inspect_quarantined(self, name: str) -> Optional[QuarantineEntry]:
        """Return details of a quarantined package, or None if not found."""
        key = _normalise_name(name)
        manifest = _load_manifest(self.manifest_path)
        data = manifest.get(key)
        if data is None:
            return None
        try:
            return QuarantineEntry(**data)
        except TypeError:
            return None

    def release_quarantined(self, name: str, *, force: bool = False) -> bool:
        """Release a quarantined package — install it into the current env.

        Before installing, the package is re-scanned for vulnerabilities.
        If it still has issues the release is refused unless *force* is True.

        Removes the quarantine venv and manifest entry.  Returns True if
        the package was found and released, False otherwise.

        Raises
        ------
        QuarantineReleaseBlocked
            When the re-scan still flags the package and *force* is False.
        """
        key = _normalise_name(name)
        manifest = _load_manifest(self.manifest_path)
        data = manifest.get(key)
        if data is None:
            logger.warning("Package %s is not quarantined", name)
            return False

        entry = QuarantineEntry(**data)

        # --- Re-scan before releasing ---
        from alterks.config import load_config
        from alterks.models import PolicyAction
        from alterks.scanner import Scanner

        config = load_config()
        scanner = Scanner(config=config)
        result = scanner.scan_package(entry.name, entry.version)

        if result.action in (PolicyAction.BLOCK, PolicyAction.QUARANTINE):
            if not force:
                raise QuarantineReleaseBlocked(
                    f"{entry.name}=={entry.version} still flagged "
                    f"({result.action.value}): {result.reason}"
                )
            logger.warning(
                "Force-releasing %s==%s despite scan result: %s",
                entry.name, entry.version, result.reason,
            )

        # Install into the current environment
        logger.info("Releasing %s==%s into current environment", entry.name, entry.version)
        validate_package_name(entry.name)
        validate_package_version(entry.version)
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--", f"{entry.name}=={entry.version}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as exc:
            logger.error("Failed to install %s==%s: %s", entry.name, entry.version, exc)
            return False

        # Clean up quarantine venv
        venv_path = Path(entry.venv_path)
        if venv_path.exists():
            _remove_dir(venv_path)

        # Remove from manifest
        del manifest[key]
        _save_manifest(manifest, self.manifest_path)

        logger.info("Released %s==%s from quarantine", entry.name, entry.version)
        return True

    def remove_quarantined(self, name: str) -> bool:
        """Remove a quarantined package without installing it.

        Deletes the quarantine venv and manifest entry.
        """
        key = _normalise_name(name)
        manifest = _load_manifest(self.manifest_path)
        if key not in manifest:
            return False

        data = manifest[key]
        venv_path = Path(data.get("venv_path", ""))
        if venv_path.exists():
            _remove_dir(venv_path)

        del manifest[key]
        _save_manifest(manifest, self.manifest_path)

        logger.info("Removed quarantined package %s", name)
        return True

    # -- Internals -----------------------------------------------------------

    @staticmethod
    def _find_pip(venv_path: Path) -> Path:
        """Locate pip inside a virtual environment."""
        if sys.platform == "win32":
            pip = venv_path / "Scripts" / "pip.exe"
        else:
            pip = venv_path / "bin" / "pip"
        if not pip.exists():
            # Fallback — use python -m pip
            return venv_path / ("Scripts" if sys.platform == "win32" else "bin") / "python"
        return pip

    @staticmethod
    def _install_package(pip_exe: Path, name: str, version: str) -> None:
        """Install a package into a quarantine venv via pip."""
        validate_package_name(name)
        validate_package_version(version)
        cmd: list[str]
        if pip_exe.name.startswith("python"):
            cmd = [str(pip_exe), "-m", "pip", "install", "--", f"{name}=={version}"]
        else:
            cmd = [str(pip_exe), "install", "--", f"{name}=={version}"]

        try:
            subprocess.check_call(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as exc:
            logger.error(
                "Failed to install %s==%s in quarantine: %s", name, version, exc,
            )
            raise


def _remove_dir(path: Path) -> None:
    """Recursively remove a directory tree."""
    import shutil
    try:
        shutil.rmtree(path)
    except OSError as exc:
        logger.warning("Failed to remove %s: %s", path, exc)
