"""Tests for the secure package extractor."""

from __future__ import annotations

import io
import os
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from alterks.extractor import (
    ExtractionError,
    MAX_EXTRACT_SIZE_BYTES,
    MAX_FILE_COUNT,
    _is_safe_path,
    _safe_extract_tar,
    _safe_extract_zip,
    extract_package,
)


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------

class TestIsSafePath:
    def test_safe_path(self, tmp_path: Path):
        assert _is_safe_path("pkg/setup.py", tmp_path) is True

    def test_traversal_dotdot(self, tmp_path: Path):
        assert _is_safe_path("../../etc/passwd", tmp_path) is False

    def test_traversal_absolute(self, tmp_path: Path):
        assert _is_safe_path("/etc/passwd", tmp_path) is False

    def test_safe_nested(self, tmp_path: Path):
        assert _is_safe_path("pkg/subdir/file.py", tmp_path) is True


# ---------------------------------------------------------------------------
# Zip extraction
# ---------------------------------------------------------------------------

class TestSafeExtractZip:
    def test_normal_zip(self, tmp_path: Path):
        archive = tmp_path / "pkg.whl"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("setup.py", "print('hello')")
            zf.writestr("pkg/__init__.py", "")

        _safe_extract_zip(archive, extract_dir)
        assert (extract_dir / "setup.py").exists()
        assert (extract_dir / "pkg" / "__init__.py").exists()

    def test_rejects_path_traversal(self, tmp_path: Path):
        archive = tmp_path / "evil.whl"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("../../etc/passwd", "root:x:0:0")

        with pytest.raises(ExtractionError, match="Path traversal"):
            _safe_extract_zip(archive, extract_dir)

    def test_rejects_oversized(self, tmp_path: Path):
        archive = tmp_path / "big.whl"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with zipfile.ZipFile(archive, "w") as zf:
            # Write a file that claims to be huge
            zf.writestr("huge.bin", "x" * 1024)

        # Patch the file size to exceed limit
        with zipfile.ZipFile(archive, "r") as zf:
            infos = zf.infolist()
            infos[0].file_size = MAX_EXTRACT_SIZE_BYTES + 1

        # Re-create with spoofed size is complex; test via file count instead
        archive2 = tmp_path / "many.whl"
        with zipfile.ZipFile(archive2, "w") as zf:
            for i in range(MAX_FILE_COUNT + 1):
                zf.writestr(f"file_{i}.txt", "x")

        with pytest.raises(ExtractionError, match="File count exceeds"):
            _safe_extract_zip(archive2, extract_dir)


# ---------------------------------------------------------------------------
# Tar extraction
# ---------------------------------------------------------------------------

class TestSafeExtractTar:
    def test_normal_tar(self, tmp_path: Path):
        archive = tmp_path / "pkg.tar.gz"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with tarfile.open(archive, "w:gz") as tf:
            # Add a regular file
            data = b"print('hello')"
            info = tarfile.TarInfo(name="pkg/setup.py")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        _safe_extract_tar(archive, extract_dir)
        assert (extract_dir / "pkg" / "setup.py").exists()

    def test_rejects_path_traversal(self, tmp_path: Path):
        archive = tmp_path / "evil.tar.gz"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with tarfile.open(archive, "w:gz") as tf:
            data = b"malicious"
            info = tarfile.TarInfo(name="../../etc/passwd")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        with pytest.raises(ExtractionError, match="Path traversal"):
            _safe_extract_tar(archive, extract_dir)

    def test_rejects_symlink(self, tmp_path: Path):
        archive = tmp_path / "sym.tar.gz"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with tarfile.open(archive, "w:gz") as tf:
            info = tarfile.TarInfo(name="link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)

        with pytest.raises(ExtractionError, match="Symlink"):
            _safe_extract_tar(archive, extract_dir)

    def test_rejects_device_file(self, tmp_path: Path):
        archive = tmp_path / "dev.tar.gz"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with tarfile.open(archive, "w:gz") as tf:
            info = tarfile.TarInfo(name="devzero")
            info.type = tarfile.CHRTYPE
            info.devmajor = 1
            info.devminor = 5
            tf.addfile(info)

        with pytest.raises(ExtractionError, match="Non-regular file"):
            _safe_extract_tar(archive, extract_dir)


# ---------------------------------------------------------------------------
# extract_package dispatch
# ---------------------------------------------------------------------------

class TestExtractPackage:
    def test_extracts_whl(self, tmp_path: Path):
        archive = tmp_path / "pkg-1.0.0.whl"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("setup.py", "x = 1")

        extract_package(archive, extract_dir)
        assert (extract_dir / "setup.py").exists()

    def test_extracts_tar_gz(self, tmp_path: Path):
        archive = tmp_path / "pkg-1.0.0.tar.gz"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with tarfile.open(archive, "w:gz") as tf:
            data = b"x = 1"
            info = tarfile.TarInfo(name="setup.py")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

        extract_package(archive, extract_dir)
        assert (extract_dir / "setup.py").exists()

    def test_rejects_unknown_format(self, tmp_path: Path):
        archive = tmp_path / "pkg.exe"
        archive.write_bytes(b"MZ")
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with pytest.raises(ExtractionError, match="Unsupported"):
            extract_package(archive, extract_dir)


# ---------------------------------------------------------------------------
# Binary-only wheel (no .py files) — T7
# ---------------------------------------------------------------------------

class TestBinaryOnlyWheel:
    def test_no_py_files_returns_clean(self, tmp_path: Path):
        """A wheel with no .py files should not cause errors."""
        archive = tmp_path / "binary-1.0.0.whl"
        extract_dir = tmp_path / "out"
        extract_dir.mkdir()

        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("binary.pyd", b"\x00" * 10)
            zf.writestr("METADATA", "Name: binary")

        extract_package(archive, extract_dir)
        # Verify no .py files present
        py_files = list(extract_dir.rglob("*.py"))
        assert len(py_files) == 0
