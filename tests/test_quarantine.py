"""Tests for the quarantine manager.

These tests avoid creating real virtual environments (slow, side-effects)
by mocking ``venv.create`` and ``subprocess.check_call``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from alterks.quarantine import (
    QuarantineEntry,
    QuarantineManager,
    _load_manifest,
    _normalise_name,
    _save_manifest,
)


# ---------------------------------------------------------------------------
# _normalise_name
# ---------------------------------------------------------------------------

class TestNormaliseName:
    def test_lowercase(self):
        assert _normalise_name("Flask") == "flask"

    def test_underscores(self):
        assert _normalise_name("my_package") == "my-package"

    def test_dots(self):
        assert _normalise_name("a.b.c") == "a-b-c"

    def test_mixed(self):
        assert _normalise_name("My_Cool.Package") == "my-cool-package"


# ---------------------------------------------------------------------------
# Manifest I/O
# ---------------------------------------------------------------------------

class TestManifest:
    def test_load_missing_file(self, tmp_path: Path):
        result = _load_manifest(tmp_path / "missing.json")
        assert result == {}

    def test_save_and_load(self, tmp_path: Path):
        path = tmp_path / "quarantine.json"
        data = {"flask": {"name": "flask", "version": "2.0", "reason": "test",
                          "venv_path": "/tmp/q/flask", "quarantined_at": "2026-01-01"}}
        _save_manifest(data, path)
        loaded = _load_manifest(path)
        assert loaded["flask"]["name"] == "flask"

    def test_load_corrupt_file(self, tmp_path: Path):
        path = tmp_path / "quarantine.json"
        path.write_text("not json", encoding="utf-8")
        assert _load_manifest(path) == {}

    def test_save_creates_directories(self, tmp_path: Path):
        path = tmp_path / "deep" / "nested" / "quarantine.json"
        _save_manifest({"test": {}}, path)
        assert path.is_file()


# ---------------------------------------------------------------------------
# QuarantineEntry
# ---------------------------------------------------------------------------

class TestQuarantineEntry:
    def test_defaults(self):
        entry = QuarantineEntry(name="pkg", version="1.0", reason="test", venv_path="/tmp/q")
        assert entry.quarantined_at  # auto-set
        assert entry.vulnerability_ids == []
        assert entry.risk_score == 0.0

    def test_explicit_timestamp(self):
        entry = QuarantineEntry(
            name="pkg", version="1.0", reason="test",
            venv_path="/tmp", quarantined_at="2026-01-01T00:00:00",
        )
        assert entry.quarantined_at == "2026-01-01T00:00:00"


# ---------------------------------------------------------------------------
# QuarantineManager.quarantine_package
# ---------------------------------------------------------------------------

class TestQuarantinePackage:
    @patch("alterks.quarantine.subprocess.check_call")
    @patch("alterks.quarantine.venv.create")
    def test_quarantines_and_records(self, mock_venv, mock_pip, tmp_path: Path):
        qdir = tmp_path / "quarantine"
        manifest = tmp_path / "quarantine.json"
        mgr = QuarantineManager(quarantine_dir=qdir, manifest_path=manifest)

        entry = mgr.quarantine_package("flask", "2.3.3", "test reason", ["PYSEC-2024-1"])

        assert entry.name == "flask"
        assert entry.version == "2.3.3"
        assert entry.reason == "test reason"
        assert entry.vulnerability_ids == ["PYSEC-2024-1"]
        mock_venv.assert_called_once()
        mock_pip.assert_called_once()

        # Manifest updated
        data = json.loads(manifest.read_text())
        assert "flask" in data

    @patch("alterks.quarantine.subprocess.check_call")
    @patch("alterks.quarantine.venv.create")
    def test_normalises_name_in_manifest(self, mock_venv, mock_pip, tmp_path: Path):
        mgr = QuarantineManager(
            quarantine_dir=tmp_path / "q",
            manifest_path=tmp_path / "q.json",
        )
        mgr.quarantine_package("My_Package", "1.0", "test")

        data = json.loads((tmp_path / "q.json").read_text())
        assert "my-package" in data


# ---------------------------------------------------------------------------
# QuarantineManager.list_quarantined
# ---------------------------------------------------------------------------

class TestListQuarantined:
    def test_empty(self, tmp_path: Path):
        mgr = QuarantineManager(
            quarantine_dir=tmp_path,
            manifest_path=tmp_path / "q.json",
        )
        assert mgr.list_quarantined() == []

    def test_lists_entries(self, tmp_path: Path):
        manifest = tmp_path / "q.json"
        manifest.write_text(json.dumps({
            "flask": {
                "name": "flask", "version": "2.0", "reason": "vuln",
                "venv_path": str(tmp_path / "flask"),
                "quarantined_at": "2026-01-01T00:00:00",
                "vulnerability_ids": [], "risk_score": 0.0,
            },
            "requests": {
                "name": "requests", "version": "2.30", "reason": "old",
                "venv_path": str(tmp_path / "requests"),
                "quarantined_at": "2026-01-01T00:00:00",
                "vulnerability_ids": [], "risk_score": 0.0,
            },
        }))
        mgr = QuarantineManager(quarantine_dir=tmp_path, manifest_path=manifest)
        entries = mgr.list_quarantined()
        assert len(entries) == 2
        names = {e.name for e in entries}
        assert names == {"flask", "requests"}


# ---------------------------------------------------------------------------
# QuarantineManager.inspect_quarantined
# ---------------------------------------------------------------------------

class TestInspectQuarantined:
    def test_found(self, tmp_path: Path):
        manifest = tmp_path / "q.json"
        manifest.write_text(json.dumps({
            "flask": {
                "name": "flask", "version": "2.0", "reason": "vuln",
                "venv_path": str(tmp_path), "quarantined_at": "2026-01-01",
                "vulnerability_ids": ["PYSEC-1"], "risk_score": 42.0,
            },
        }))
        mgr = QuarantineManager(quarantine_dir=tmp_path, manifest_path=manifest)
        entry = mgr.inspect_quarantined("flask")
        assert entry is not None
        assert entry.version == "2.0"
        assert entry.vulnerability_ids == ["PYSEC-1"]

    def test_not_found(self, tmp_path: Path):
        mgr = QuarantineManager(
            quarantine_dir=tmp_path,
            manifest_path=tmp_path / "q.json",
        )
        assert mgr.inspect_quarantined("nonexistent") is None

    def test_normalised_lookup(self, tmp_path: Path):
        manifest = tmp_path / "q.json"
        manifest.write_text(json.dumps({
            "my-package": {
                "name": "My_Package", "version": "1.0", "reason": "test",
                "venv_path": str(tmp_path), "quarantined_at": "2026-01-01",
                "vulnerability_ids": [], "risk_score": 0.0,
            },
        }))
        mgr = QuarantineManager(quarantine_dir=tmp_path, manifest_path=manifest)
        assert mgr.inspect_quarantined("My_Package") is not None


# ---------------------------------------------------------------------------
# QuarantineManager.release_quarantined
# ---------------------------------------------------------------------------

class TestReleaseQuarantined:
    @patch("alterks.quarantine.subprocess.check_call")
    def test_release_installs_and_cleans(self, mock_pip, tmp_path: Path):
        # Set up a quarantine dir that exists
        venv_dir = tmp_path / "quarantine" / "flask"
        venv_dir.mkdir(parents=True)
        (venv_dir / "marker.txt").write_text("exists")

        manifest = tmp_path / "q.json"
        manifest.write_text(json.dumps({
            "flask": {
                "name": "flask", "version": "2.3.3", "reason": "vuln",
                "venv_path": str(venv_dir), "quarantined_at": "2026-01-01",
                "vulnerability_ids": [], "risk_score": 0.0,
            },
        }))

        mgr = QuarantineManager(
            quarantine_dir=tmp_path / "quarantine",
            manifest_path=manifest,
        )
        result = mgr.release_quarantined("flask")

        assert result is True
        mock_pip.assert_called_once()
        # Venv cleaned up
        assert not venv_dir.exists()
        # Removed from manifest
        data = json.loads(manifest.read_text())
        assert "flask" not in data

    def test_release_not_found(self, tmp_path: Path):
        mgr = QuarantineManager(
            quarantine_dir=tmp_path,
            manifest_path=tmp_path / "q.json",
        )
        assert mgr.release_quarantined("nonexistent") is False


# ---------------------------------------------------------------------------
# QuarantineManager.remove_quarantined
# ---------------------------------------------------------------------------

class TestRemoveQuarantined:
    def test_remove_cleans_venv_and_manifest(self, tmp_path: Path):
        venv_dir = tmp_path / "q" / "flask"
        venv_dir.mkdir(parents=True)

        manifest = tmp_path / "q.json"
        manifest.write_text(json.dumps({
            "flask": {
                "name": "flask", "version": "2.0", "reason": "test",
                "venv_path": str(venv_dir), "quarantined_at": "2026-01-01",
                "vulnerability_ids": [], "risk_score": 0.0,
            },
        }))

        mgr = QuarantineManager(quarantine_dir=tmp_path / "q", manifest_path=manifest)
        assert mgr.remove_quarantined("flask") is True
        assert not venv_dir.exists()
        data = json.loads(manifest.read_text())
        assert "flask" not in data

    def test_remove_not_found(self, tmp_path: Path):
        mgr = QuarantineManager(
            quarantine_dir=tmp_path,
            manifest_path=tmp_path / "q.json",
        )
        assert mgr.remove_quarantined("nope") is False
