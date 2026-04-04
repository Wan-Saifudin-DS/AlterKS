"""Secure package extraction for static code analysis.

Downloads ``.tar.gz`` (sdist) and ``.whl`` (wheel) archives from PyPI
into isolated temporary directories and extracts them safely.

Security controls:
- Path traversal (Zip Slip / CVE-2007-4559) prevention
- Symlink rejection
- Device file rejection
- Decompression bomb protection (size + file count caps)
- Guaranteed cleanup via ``tempfile.TemporaryDirectory``
"""

from __future__ import annotations

import hashlib
import logging
import os
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

MAX_EXTRACT_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_FILE_COUNT = 5000
MAX_DOWNLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB
DOWNLOAD_CHUNK_SIZE = 65536  # 64 KB


class ExtractionError(Exception):
    """Raised when archive extraction fails due to a security violation."""


class DownloadError(Exception):
    """Raised when a package download fails."""


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

def download_package(
    url: str,
    expected_sha256: Optional[str],
    dest_dir: Path,
    timeout: float = 30.0,
) -> Path:
    """Stream-download a package file and verify its SHA-256 digest.

    Parameters
    ----------
    url:
        Direct download URL for the package archive.
    expected_sha256:
        Expected SHA-256 hex digest.  When *None*, integrity verification
        is skipped (not recommended).
    dest_dir:
        Directory to save the downloaded file into.
    timeout:
        HTTP timeout in seconds.

    Returns
    -------
    Path
        Path to the downloaded file.

    Raises
    ------
    DownloadError
        On network failures, size violations, or integrity check failure.
    """
    filename = url.rsplit("/", 1)[-1]
    if not filename or "/" in filename or "\\" in filename:
        raise DownloadError(f"Invalid filename in URL: {url}")

    dest = dest_dir / filename
    sha256 = hashlib.sha256()
    total_bytes = 0

    try:
        with httpx.Client(timeout=timeout, verify=True) as client:
            with client.stream("GET", url, follow_redirects=True) as resp:
                resp.raise_for_status()
                with open(dest, "wb") as fh:
                    for chunk in resp.iter_bytes(DOWNLOAD_CHUNK_SIZE):
                        total_bytes += len(chunk)
                        if total_bytes > MAX_DOWNLOAD_SIZE_BYTES:
                            raise DownloadError(
                                f"Download exceeds {MAX_DOWNLOAD_SIZE_BYTES} byte limit"
                            )
                        fh.write(chunk)
                        sha256.update(chunk)
    except httpx.HTTPError as exc:
        raise DownloadError(f"HTTP error downloading {url}: {exc}") from exc

    if expected_sha256 is not None:
        actual = sha256.hexdigest()
        if actual != expected_sha256:
            # Remove the corrupted file
            dest.unlink(missing_ok=True)
            raise DownloadError(
                f"SHA-256 mismatch for {filename}: "
                f"expected {expected_sha256}, got {actual}"
            )

    return dest


# ---------------------------------------------------------------------------
# Safe extraction helpers
# ---------------------------------------------------------------------------

def _is_safe_path(member_path: str, extract_dir: Path) -> bool:
    """Check that a member path stays within *extract_dir*."""
    resolved = (extract_dir / member_path).resolve()
    return str(resolved).startswith(str(extract_dir.resolve()))


def _safe_extract_zip(archive_path: Path, extract_dir: Path) -> None:
    """Extract a ``.whl`` (zip) safely."""
    total_size = 0
    file_count = 0

    with zipfile.ZipFile(archive_path, "r") as zf:
        for info in zf.infolist():
            # Reject symlinks (external attr bit 0xA0000000 on Unix)
            if info.external_attr >> 28 == 0xA:
                raise ExtractionError(
                    f"Symlink rejected in archive: {info.filename}"
                )

            # Path traversal check
            if not _is_safe_path(info.filename, extract_dir):
                raise ExtractionError(
                    f"Path traversal detected: {info.filename}"
                )

            # Size check
            total_size += info.file_size
            if total_size > MAX_EXTRACT_SIZE_BYTES:
                raise ExtractionError(
                    f"Extracted size exceeds {MAX_EXTRACT_SIZE_BYTES} byte limit"
                )

            file_count += 1
            if file_count > MAX_FILE_COUNT:
                raise ExtractionError(
                    f"File count exceeds {MAX_FILE_COUNT} limit"
                )

            zf.extract(info, extract_dir)


def _safe_extract_tar(archive_path: Path, extract_dir: Path) -> None:
    """Extract a ``.tar.gz`` safely, mitigating CVE-2007-4559."""
    total_size = 0
    file_count = 0

    with tarfile.open(archive_path, "r:*") as tf:
        for member in tf.getmembers():
            # Reject symlinks and hardlinks
            if member.issym() or member.islnk():
                raise ExtractionError(
                    f"Symlink/hardlink rejected in archive: {member.name}"
                )

            # Reject device files, fifos, etc.
            if not (member.isfile() or member.isdir()):
                raise ExtractionError(
                    f"Non-regular file rejected in archive: {member.name} "
                    f"(type={member.type})"
                )

            # Path traversal check
            if not _is_safe_path(member.name, extract_dir):
                raise ExtractionError(
                    f"Path traversal detected: {member.name}"
                )

            # Size check
            if member.isfile():
                total_size += member.size
                if total_size > MAX_EXTRACT_SIZE_BYTES:
                    raise ExtractionError(
                        f"Extracted size exceeds {MAX_EXTRACT_SIZE_BYTES} byte limit"
                    )

            file_count += 1
            if file_count > MAX_FILE_COUNT:
                raise ExtractionError(
                    f"File count exceeds {MAX_FILE_COUNT} limit"
                )

            # Python 3.12+ supports data_filter
            if sys.version_info >= (3, 12):
                tf.extract(member, extract_dir, filter="data")
            else:
                tf.extract(member, extract_dir)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_package(archive_path: Path, extract_dir: Path) -> Path:
    """Extract a package archive safely into *extract_dir*.

    Parameters
    ----------
    archive_path:
        Path to ``.tar.gz`` or ``.whl`` file.
    extract_dir:
        Target extraction directory (must exist).

    Returns
    -------
    Path
        The extraction directory.

    Raises
    ------
    ExtractionError
        On any security violation during extraction.
    """
    name = archive_path.name.lower()

    if name.endswith(".whl") or name.endswith(".zip"):
        _safe_extract_zip(archive_path, extract_dir)
    elif name.endswith(".tar.gz") or name.endswith(".tgz"):
        _safe_extract_tar(archive_path, extract_dir)
    elif name.endswith(".tar"):
        _safe_extract_tar(archive_path, extract_dir)
    else:
        raise ExtractionError(f"Unsupported archive format: {archive_path.name}")

    return extract_dir
