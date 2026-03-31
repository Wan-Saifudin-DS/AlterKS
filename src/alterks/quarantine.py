"""Quarantine manager — isolate suspicious packages in per-package venvs.

Quarantined packages are installed into their own virtual environment under
``~/.alterks/quarantine/<normalised-name>/`` so they cannot affect the main
Python environment.  A JSON manifest at ``~/.alterks/quarantine.json`` tracks
all quarantined packages and their metadata.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
import venv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from alterks.models import validate_package_name, validate_package_version, normalise_name

logger = logging.getLogger(__name__)

DEFAULT_QUARANTINE_DIR = Path.home() / ".alterks" / "quarantine"
DEFAULT_MANIFEST_PATH = Path.home() / ".alterks" / "quarantine.json"


class QuarantineReleaseBlocked(Exception):
    """Raised when a quarantined package still fails its re-scan on release."""


class ManifestValidationError(Exception):
    """Raised when a quarantine manifest entry fails validation."""


# ---------------------------------------------------------------------------
# Manifest entry whitelist
# ---------------------------------------------------------------------------

_MANIFEST_ENTRY_FIELDS = frozenset({
    "name", "version", "reason", "venv_path",
    "quarantined_at", "vulnerability_ids", "risk_score",
})


def _validate_manifest_entry(data: dict, quarantine_dir: Path) -> dict:
    """Validate a manifest entry dict before instantiation.

    Raises :class:`ManifestValidationError` if *data* contains unknown
    keys, invalid types, or a ``venv_path`` outside the quarantine
    directory.
    """
    if not isinstance(data, dict):
        raise ManifestValidationError("Entry is not a dict")

    # Reject unexpected keys
    unknown = set(data.keys()) - _MANIFEST_ENTRY_FIELDS
    if unknown:
        raise ManifestValidationError(f"Unknown keys in manifest entry: {unknown}")

    # Required string fields
    for key in ("name", "version", "reason", "venv_path"):
        if key not in data or not isinstance(data[key], str):
            raise ManifestValidationError(f"Missing or non-string field: {key!r}")

    # Validate name and version against safe regexes
    try:
        validate_package_name(data["name"])
        validate_package_version(data["version"])
    except ValueError as exc:
        raise ManifestValidationError(str(exc)) from exc

    # Validate venv_path is safely contained under quarantine_dir
    try:
        venv = Path(data["venv_path"]).resolve()
        qdir = quarantine_dir.resolve()
        if not venv.is_relative_to(qdir):
            raise ManifestValidationError(
                f"venv_path {data['venv_path']!r} is outside quarantine dir"
            )
    except (OSError, ValueError) as exc:
        raise ManifestValidationError(f"Invalid venv_path: {exc}") from exc

    # Optional field type checks
    if "quarantined_at" in data and not isinstance(data["quarantined_at"], str):
        raise ManifestValidationError("quarantined_at must be a string")

    if "vulnerability_ids" in data:
        ids = data["vulnerability_ids"]
        if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
            raise ManifestValidationError("vulnerability_ids must be a list of strings")

    if "risk_score" in data:
        if not isinstance(data["risk_score"], (int, float)):
            raise ManifestValidationError("risk_score must be a number")

    return data


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
    """Persist the quarantine manifest atomically.

    Writes to a temporary file in the same directory, then replaces the
    target with ``os.replace()`` — atomic on the same filesystem.  This
    prevents partial writes from corrupting the manifest.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(manifest, indent=2, default=str) + "\n"
    # Write to temp file in the same dir so os.replace is atomic
    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent), prefix=".quarantine_", suffix=".tmp",
    )
    try:
        os.write(fd, content.encode("utf-8"))
        os.close(fd)
        fd = -1  # mark as closed
        os.replace(tmp, str(path))
    except BaseException:
        if fd >= 0:
            os.close(fd)
        # Clean up the temp file on failure
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class LockAcquisitionError(Exception):
    """Raised when the manifest lock cannot be acquired within the timeout."""


class _ManifestLock:
    """Cross-platform file lock for the quarantine manifest with timeout.

    Uses ``fcntl.flock()`` on Unix and ``msvcrt.locking()`` on Windows,
    both in **non-blocking** mode with a retry loop to enforce a timeout.

    If the lock cannot be acquired within *timeout* seconds, raises
    :class:`LockAcquisitionError` instead of blocking forever.

    The owning process ID is written into the lock file so that stale
    locks (left behind by a crashed process) can be detected and removed.

    Designed for use as a context manager::

        with _ManifestLock(manifest_path):
            manifest = _load_manifest(manifest_path)
            ...
            _save_manifest(manifest, manifest_path)
    """

    DEFAULT_TIMEOUT: float = 30.0  # seconds
    _RETRY_INTERVAL: float = 0.2   # seconds between non-blocking retries

    def __init__(
        self,
        manifest_path: Path,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._lock_path = manifest_path.with_suffix(".lock")
        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._timeout = timeout
        self._fd: int = -1

    def __enter__(self) -> "_ManifestLock":
        deadline = time.monotonic() + self._timeout

        self._fd = os.open(
            str(self._lock_path),
            os.O_CREAT | os.O_RDWR,
        )

        try:
            while True:
                if self._try_lock():
                    # Lock acquired — record our PID for stale-lock detection
                    self._write_pid()
                    return self

                if time.monotonic() >= deadline:
                    # Timeout — check if the lock is stale before giving up
                    if self._is_stale():
                        logger.warning(
                            "Stale lock detected (owner PID no longer running). "
                            "Resetting lock file %s",
                            self._lock_path,
                        )
                        self._force_reset()
                        # Try once more after reset
                        if self._try_lock():
                            self._write_pid()
                            return self

                    os.close(self._fd)
                    self._fd = -1
                    raise LockAcquisitionError(
                        f"Could not acquire manifest lock within "
                        f"{self._timeout}s. If no other AlterKS process is "
                        f"running, delete {self._lock_path} manually."
                    )

                time.sleep(self._RETRY_INTERVAL)
        except BaseException:
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1
            raise

    def __exit__(self, *exc_info: object) -> None:
        try:
            if sys.platform == "win32":
                import msvcrt
                try:
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            if self._fd >= 0:
                os.close(self._fd)
                self._fd = -1

    # -- Internals -----------------------------------------------------------

    def _try_lock(self) -> bool:
        """Attempt a non-blocking lock. Return True on success."""
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except (OSError, IOError):
            return False

    def _write_pid(self) -> None:
        """Write the current PID into the lock file for stale detection."""
        try:
            os.lseek(self._fd, 0, os.SEEK_SET)
            os.ftruncate(self._fd, 0)
            os.write(self._fd, str(os.getpid()).encode("ascii"))
        except OSError:
            pass  # best-effort

    def _read_owner_pid(self) -> int | None:
        """Read the PID from the lock file, or None if unavailable."""
        try:
            text = self._lock_path.read_text(encoding="ascii").strip()
            return int(text) if text else None
        except (OSError, ValueError):
            return None

    def _is_stale(self) -> bool:
        """Return True if the lock file's owner PID is no longer running."""
        pid = self._read_owner_pid()
        if pid is None:
            # No PID recorded — treat as stale if lock file is old enough
            return self._lock_file_is_old()
        return not _pid_is_alive(pid)

    def _lock_file_is_old(self) -> bool:
        """Return True if the lock file was last modified > timeout ago."""
        try:
            mtime = self._lock_path.stat().st_mtime
            return (time.time() - mtime) > self._timeout
        except OSError:
            return True

    def _force_reset(self) -> None:
        """Close and re-open the lock file descriptor after a stale lock."""
        if self._fd >= 0:
            os.close(self._fd)
        self._fd = os.open(
            str(self._lock_path),
            os.O_CREAT | os.O_RDWR,
        )


def _pid_is_alive(pid: int) -> bool:
    """Check if a process with *pid* is currently running."""
    if sys.platform == "win32":
        # On Windows, use ctypes OpenProcess
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(  # type: ignore[union-attr]
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid,
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[union-attr]
            return True
        return False
    else:
        # On Unix, os.kill(pid, 0) probes without sending a signal
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # Process exists but we don't own it — still alive
            return True


def _manifest_key(name: str, version: str) -> str:
    """Composite manifest key: ``normalised-name==version``."""
    return f"{normalise_name(name)}=={version}"


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

        key = _manifest_key(name, version)
        norm = normalise_name(name)
        venv_path = self.quarantine_dir / f"{norm}_{version}"

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

        # Update manifest (locked + atomic)
        with _ManifestLock(self.manifest_path):
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
                _validate_manifest_entry(data, self.quarantine_dir)
                entries.append(QuarantineEntry(**data))
            except (TypeError, ManifestValidationError) as exc:
                logger.warning("Skipping malformed quarantine entry: %s — %s", data, exc)
        return entries

    def inspect_quarantined(self, name: str, version: Optional[str] = None) -> Optional[QuarantineEntry]:
        """Return details of a quarantined package, or None if not found.

        When *version* is given, looks up the exact ``name==version``
        entry.  When omitted, returns the first entry matching *name*.
        """
        manifest = _load_manifest(self.manifest_path)

        if version is not None:
            key = _manifest_key(name, version)
            data = manifest.get(key)
            if data is None:
                return None
            try:
                _validate_manifest_entry(data, self.quarantine_dir)
                return QuarantineEntry(**data)
            except (TypeError, ManifestValidationError) as exc:
                logger.warning("Malformed quarantine entry for %s: %s", key, exc)
                return None

        # No version — find first entry matching the normalised name
        norm = normalise_name(name)
        for data in manifest.values():
            try:
                _validate_manifest_entry(data, self.quarantine_dir)
                if normalise_name(data.get("name", "")) == norm:
                    return QuarantineEntry(**data)
            except (TypeError, ManifestValidationError) as exc:
                logger.warning("Malformed quarantine entry: %s", exc)
        return None

    def release_quarantined(self, name: str, version: Optional[str] = None, *, force: bool = False) -> bool:
        """Release a quarantined package — install it into the current env.

        Before installing, the package is re-scanned for vulnerabilities.
        If it still has issues the release is refused unless *force* is True.

        When *version* is given, releases that exact entry.  When omitted,
        releases the first entry matching *name*.

        Removes the quarantine venv and manifest entry.  Returns True if
        the package was found and released, False otherwise.

        Raises
        ------
        QuarantineReleaseBlocked
            When the re-scan still flags the package and *force* is False.
        """
        # Resolve the key: exact if version given, else find first match
        with _ManifestLock(self.manifest_path):
            manifest = _load_manifest(self.manifest_path)
            if version is not None:
                key = _manifest_key(name, version)
                data = manifest.get(key)
            else:
                key = None
                data = None
                norm = normalise_name(name)
                for k, v in manifest.items():
                    try:
                        _validate_manifest_entry(v, self.quarantine_dir)
                        if normalise_name(v.get("name", "")) == norm:
                            key = k
                            data = v
                            break
                    except (TypeError, ManifestValidationError):
                        continue
        if data is None:
            logger.warning("Package %s is not quarantined", name)
            return False

        _validate_manifest_entry(data, self.quarantine_dir)
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
            _remove_dir(venv_path, self.quarantine_dir)

        # Remove from manifest (locked + atomic)
        with _ManifestLock(self.manifest_path):
            manifest = _load_manifest(self.manifest_path)
            manifest.pop(key, None)
            _save_manifest(manifest, self.manifest_path)

        logger.info("Released %s==%s from quarantine", entry.name, entry.version)
        return True

    def remove_quarantined(self, name: str, version: Optional[str] = None) -> bool:
        """Remove a quarantined package without installing it.

        Deletes the quarantine venv and manifest entry.
        When *version* is given, removes that exact entry.  When omitted,
        removes the first entry matching *name*.
        """
        with _ManifestLock(self.manifest_path):
            manifest = _load_manifest(self.manifest_path)

            if version is not None:
                key = _manifest_key(name, version)
            else:
                key = None
                norm = normalise_name(name)
                for k, v in manifest.items():
                    try:
                        _validate_manifest_entry(v, self.quarantine_dir)
                        if normalise_name(v.get("name", "")) == norm:
                            key = k
                            break
                    except (TypeError, ManifestValidationError):
                        continue

            if key is None or key not in manifest:
                return False

            data = manifest[key]
            _validate_manifest_entry(data, self.quarantine_dir)
            venv_path = Path(data.get("venv_path", ""))
            if venv_path.exists():
                _remove_dir(venv_path, self.quarantine_dir)

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


def _remove_dir(path: Path, quarantine_dir: Path) -> None:
    """Recursively remove a directory tree, with path containment check.

    Raises ``ValueError`` if *path* does not resolve to a location inside
    *quarantine_dir*, preventing arbitrary directory deletion from a
    tampered manifest.
    """
    import shutil

    resolved = path.resolve()
    qdir = quarantine_dir.resolve()
    if not resolved.is_relative_to(qdir):
        raise ValueError(
            f"Refusing to delete {path}: resolved path {resolved} "
            f"is outside quarantine directory {qdir}"
        )
    try:
        shutil.rmtree(resolved)
    except OSError as exc:
        logger.warning("Failed to remove %s: %s", path, exc)
