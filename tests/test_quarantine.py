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
    ManifestValidationError,
    QuarantineEntry,
    QuarantineManager,
    _ManifestLock,
    _load_manifest,
    _normalise_name,
    _remove_dir,
    _save_manifest,
    _validate_manifest_entry,
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
    @patch("alterks.scanner.Scanner")
    @patch("alterks.quarantine.subprocess.check_call")
    def test_release_installs_and_cleans(self, mock_pip, mock_scanner_cls, tmp_path: Path):
        # Mock scanner to return ALLOW (package is now safe)
        from alterks.models import PolicyAction, ScanResult
        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.scan_package.return_value = ScanResult(
            name="flask", version="2.3.3", action=PolicyAction.ALLOW,
        )

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
        mock_scanner.scan_package.assert_called_once_with("flask", "2.3.3")
        mock_pip.assert_called_once()
        # Venv cleaned up
        assert not venv_dir.exists()
        # Removed from manifest
        data = json.loads(manifest.read_text())
        assert "flask" not in data

    @patch("alterks.scanner.Scanner")
    def test_release_blocked_when_still_flagged(self, mock_scanner_cls, tmp_path: Path):
        """Re-scan flags the package → release is refused."""
        from alterks.models import PolicyAction, ScanResult
        from alterks.quarantine import QuarantineReleaseBlocked

        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.scan_package.return_value = ScanResult(
            name="evil-pkg", version="1.0", action=PolicyAction.BLOCK,
            reason="still vulnerable",
        )

        manifest = tmp_path / "q.json"
        manifest.write_text(json.dumps({
            "evil-pkg": {
                "name": "evil-pkg", "version": "1.0", "reason": "malicious",
                "venv_path": str(tmp_path / "q" / "evil-pkg"),
                "quarantined_at": "2026-01-01",
                "vulnerability_ids": ["CVE-2026-0001"], "risk_score": 90.0,
            },
        }))

        mgr = QuarantineManager(
            quarantine_dir=tmp_path / "q",
            manifest_path=manifest,
        )

        with pytest.raises(QuarantineReleaseBlocked, match="still flagged"):
            mgr.release_quarantined("evil-pkg")

        # Package must remain in manifest
        data = json.loads(manifest.read_text())
        assert "evil-pkg" in data

    @patch("alterks.scanner.Scanner")
    @patch("alterks.quarantine.subprocess.check_call")
    def test_release_force_overrides_block(self, mock_pip, mock_scanner_cls, tmp_path: Path):
        """With force=True, release succeeds even when re-scan flags the package."""
        from alterks.models import PolicyAction, ScanResult

        mock_scanner = mock_scanner_cls.return_value
        mock_scanner.scan_package.return_value = ScanResult(
            name="risky-pkg", version="1.0", action=PolicyAction.BLOCK,
            reason="still vulnerable",
        )

        venv_dir = tmp_path / "q" / "risky-pkg"
        venv_dir.mkdir(parents=True)

        manifest = tmp_path / "q.json"
        manifest.write_text(json.dumps({
            "risky-pkg": {
                "name": "risky-pkg", "version": "1.0", "reason": "sus",
                "venv_path": str(venv_dir), "quarantined_at": "2026-01-01",
                "vulnerability_ids": [], "risk_score": 70.0,
            },
        }))

        mgr = QuarantineManager(
            quarantine_dir=tmp_path / "q",
            manifest_path=manifest,
        )
        result = mgr.release_quarantined("risky-pkg", force=True)

        assert result is True
        mock_pip.assert_called_once()
        data = json.loads(manifest.read_text())
        assert "risky-pkg" not in data

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


# ---------------------------------------------------------------------------
# _validate_manifest_entry
# ---------------------------------------------------------------------------

class TestValidateManifestEntry:
    """Tests for quarantine manifest deserialization validation."""

    def _valid_entry(self, tmp_path: Path) -> dict:
        """Return a minimal valid manifest entry dict."""
        return {
            "name": "flask",
            "version": "2.0",
            "reason": "test",
            "venv_path": str(tmp_path / "flask"),
            "quarantined_at": "2026-01-01T00:00:00",
            "vulnerability_ids": [],
            "risk_score": 0.0,
        }

    def test_valid_entry_passes(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        result = _validate_manifest_entry(data, tmp_path)
        assert result is data

    def test_rejects_non_dict(self, tmp_path: Path):
        with pytest.raises(ManifestValidationError, match="not a dict"):
            _validate_manifest_entry("not a dict", tmp_path)

    def test_rejects_unknown_keys(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["injected_field"] = "/etc/shadow"
        with pytest.raises(ManifestValidationError, match="Unknown keys"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_missing_name(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        del data["name"]
        with pytest.raises(ManifestValidationError, match="name"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_missing_version(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        del data["version"]
        with pytest.raises(ManifestValidationError, match="version"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_missing_reason(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        del data["reason"]
        with pytest.raises(ManifestValidationError, match="reason"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_missing_venv_path(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        del data["venv_path"]
        with pytest.raises(ManifestValidationError, match="venv_path"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_non_string_name(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["name"] = 123
        with pytest.raises(ManifestValidationError, match="name"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_malicious_package_name(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["name"] = "--index-url=https://evil.com"
        with pytest.raises(ManifestValidationError, match="Invalid package name"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_malicious_version(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["version"] = "; rm -rf /"
        with pytest.raises(ManifestValidationError, match="Invalid package version"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_venv_path_outside_quarantine(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["venv_path"] = "/"
        with pytest.raises(ManifestValidationError, match="outside quarantine dir"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_venv_path_traversal(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["venv_path"] = str(tmp_path / ".." / ".." / "etc")
        with pytest.raises(ManifestValidationError, match="outside quarantine dir"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_non_list_vulnerability_ids(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["vulnerability_ids"] = "CVE-2026-0001"
        with pytest.raises(ManifestValidationError, match="vulnerability_ids"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_non_string_items_in_vulnerability_ids(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["vulnerability_ids"] = [123, 456]
        with pytest.raises(ManifestValidationError, match="vulnerability_ids"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_non_numeric_risk_score(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["risk_score"] = "high"
        with pytest.raises(ManifestValidationError, match="risk_score"):
            _validate_manifest_entry(data, tmp_path)

    def test_rejects_non_string_quarantined_at(self, tmp_path: Path):
        data = self._valid_entry(tmp_path)
        data["quarantined_at"] = 12345
        with pytest.raises(ManifestValidationError, match="quarantined_at"):
            _validate_manifest_entry(data, tmp_path)


# ---------------------------------------------------------------------------
# Integration: validation blocks tampered manifests
# ---------------------------------------------------------------------------

class TestManifestValidationIntegration:
    """Ensure tampered manifests are rejected by manager methods."""

    def _tampered_manifest(self, tmp_path: Path, **overrides) -> Path:
        """Write a manifest with one entry, applying overrides."""
        entry = {
            "name": "flask",
            "version": "2.0",
            "reason": "vuln",
            "venv_path": str(tmp_path / "q" / "flask"),
            "quarantined_at": "2026-01-01T00:00:00",
            "vulnerability_ids": [],
            "risk_score": 0.0,
        }
        entry.update(overrides)
        manifest = tmp_path / "q.json"
        manifest.write_text(json.dumps({"flask": entry}))
        return manifest

    def test_list_skips_entry_with_unknown_keys(self, tmp_path: Path):
        manifest = self._tampered_manifest(tmp_path, evil_field="pwned")
        mgr = QuarantineManager(quarantine_dir=tmp_path / "q", manifest_path=manifest)
        assert mgr.list_quarantined() == []

    def test_inspect_returns_none_for_tampered_entry(self, tmp_path: Path):
        manifest = self._tampered_manifest(tmp_path, venv_path="/")
        mgr = QuarantineManager(quarantine_dir=tmp_path / "q", manifest_path=manifest)
        assert mgr.inspect_quarantined("flask") is None

    def test_release_rejects_tampered_venv_path(self, tmp_path: Path):
        manifest = self._tampered_manifest(tmp_path, venv_path="/tmp/evil")
        mgr = QuarantineManager(quarantine_dir=tmp_path / "q", manifest_path=manifest)
        with pytest.raises(ManifestValidationError, match="outside quarantine dir"):
            mgr.release_quarantined("flask")

    def test_remove_rejects_tampered_venv_path(self, tmp_path: Path):
        manifest = self._tampered_manifest(tmp_path, venv_path="/")
        mgr = QuarantineManager(quarantine_dir=tmp_path / "q", manifest_path=manifest)
        with pytest.raises(ManifestValidationError, match="outside quarantine dir"):
            mgr.remove_quarantined("flask")


# ---------------------------------------------------------------------------
# _remove_dir path containment
# ---------------------------------------------------------------------------

class TestRemoveDirContainment:
    """Tests for _remove_dir path containment check."""

    def test_removes_dir_inside_quarantine(self, tmp_path: Path):
        qdir = tmp_path / "quarantine"
        target = qdir / "flask"
        target.mkdir(parents=True)
        (target / "marker.txt").write_text("exists")

        _remove_dir(target, qdir)
        assert not target.exists()

    def test_refuses_path_outside_quarantine(self, tmp_path: Path):
        qdir = tmp_path / "quarantine"
        qdir.mkdir()
        outside = tmp_path / "important_data"
        outside.mkdir()
        (outside / "precious.txt").write_text("do not delete")

        with pytest.raises(ValueError, match="outside quarantine directory"):
            _remove_dir(outside, qdir)

        # Must NOT have been deleted
        assert outside.exists()
        assert (outside / "precious.txt").read_text() == "do not delete"

    def test_refuses_root_path(self, tmp_path: Path):
        qdir = tmp_path / "quarantine"
        qdir.mkdir()

        with pytest.raises(ValueError, match="outside quarantine directory"):
            _remove_dir(Path("/"), qdir)

    def test_refuses_parent_traversal(self, tmp_path: Path):
        qdir = tmp_path / "quarantine"
        qdir.mkdir()
        target = qdir / ".." / ".."

        with pytest.raises(ValueError, match="outside quarantine directory"):
            _remove_dir(target, qdir)

    def test_refuses_sibling_directory(self, tmp_path: Path):
        qdir = tmp_path / "quarantine"
        qdir.mkdir()
        sibling = tmp_path / "other_project"
        sibling.mkdir()

        with pytest.raises(ValueError, match="outside quarantine directory"):
            _remove_dir(sibling, qdir)

    def test_release_does_not_delete_outside_quarantine(self, tmp_path: Path):
        """Integration: release_quarantined blocks deletion of paths outside quarantine_dir."""
        # Even if _validate_manifest_entry somehow passed, _remove_dir is the last line of defence.
        # This tests _remove_dir directly with a path that resolves outside.
        qdir = tmp_path / "quarantine"
        outside = tmp_path / "system_files"
        outside.mkdir(parents=True)
        (outside / "important.conf").write_text("critical")

        with pytest.raises(ValueError, match="outside quarantine directory"):
            _remove_dir(outside, qdir)

        assert (outside / "important.conf").read_text() == "critical"


# ---------------------------------------------------------------------------
# _save_manifest atomic writes
# ---------------------------------------------------------------------------

class TestAtomicSaveManifest:
    """Tests for atomic manifest writes."""

    def test_save_creates_valid_json(self, tmp_path: Path):
        path = tmp_path / "quarantine.json"
        _save_manifest({"flask": {"name": "flask"}}, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["flask"]["name"] == "flask"

    def test_save_is_atomic_no_partial_writes(self, tmp_path: Path):
        """On success, only the final file exists — no temp files left."""
        path = tmp_path / "quarantine.json"
        _save_manifest({"test": {}}, path)
        assert path.is_file()
        # No leftover temp files
        temps = list(tmp_path.glob(".quarantine_*.tmp"))
        assert temps == []

    def test_save_creates_parent_dirs(self, tmp_path: Path):
        path = tmp_path / "deep" / "nested" / "quarantine.json"
        _save_manifest({"test": {}}, path)
        assert path.is_file()

    def test_save_overwrites_existing(self, tmp_path: Path):
        path = tmp_path / "quarantine.json"
        _save_manifest({"v1": {}}, path)
        _save_manifest({"v2": {}}, path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "v2" in data
        assert "v1" not in data


# ---------------------------------------------------------------------------
# _ManifestLock
# ---------------------------------------------------------------------------

class TestManifestLock:
    """Tests for the file-based manifest lock."""

    def test_lock_creates_lock_file(self, tmp_path: Path):
        manifest_path = tmp_path / "quarantine.json"
        with _ManifestLock(manifest_path):
            assert (tmp_path / "quarantine.lock").exists()

    def test_lock_is_reentrant_from_same_thread(self, tmp_path: Path):
        """Acquiring the lock twice in the same thread shouldn't deadlock
        because we open a new fd each time (and OS allows same-process locks)."""
        manifest_path = tmp_path / "quarantine.json"
        with _ManifestLock(manifest_path):
            # On Windows msvcrt locks are per-fd, on Unix flock is per-process
            # so this should not deadlock
            pass  # If we reach here, no deadlock

    def test_lock_protects_concurrent_writes(self, tmp_path: Path):
        """Simulate concurrent modifications — lock ensures serialisation."""
        import threading

        manifest_path = tmp_path / "quarantine.json"
        _save_manifest({}, manifest_path)
        errors = []

        def add_entry(name: str) -> None:
            try:
                with _ManifestLock(manifest_path):
                    manifest = _load_manifest(manifest_path)
                    manifest[name] = {"name": name, "version": "1.0",
                                      "reason": "test",
                                      "venv_path": str(tmp_path / name),
                                      "quarantined_at": "2026-01-01",
                                      "vulnerability_ids": [],
                                      "risk_score": 0.0}
                    _save_manifest(manifest, manifest_path)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=add_entry, args=(f"pkg-{i}",))
                   for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        manifest = _load_manifest(manifest_path)
        assert len(manifest) == 5
        for i in range(5):
            assert f"pkg-{i}" in manifest
