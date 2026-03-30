"""Tests for the Scanner orchestrator."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Sequence, Tuple
from unittest.mock import MagicMock, patch

import pytest

from alterks.config import AlterKSConfig
from alterks.models import PolicyAction, ScanResult, Severity, Vulnerability
from alterks.scanner import Scanner, _extract_pinned_version, _parse_requirements_file
from alterks.sources.osv import OSVError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_vuln(
    vuln_id: str = "PYSEC-2024-001",
    severity: Severity = Severity.HIGH,
    fix_versions: list[str] | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        summary="Test vulnerability",
        severity=severity,
        fix_versions=fix_versions or [],
    )


def _make_config(**overrides) -> AlterKSConfig:
    return AlterKSConfig(**overrides)


def _mock_osv_client(
    query_return: list[Vulnerability] | None = None,
    batch_return: Dict[Tuple[str, str], List[Vulnerability]] | None = None,
) -> MagicMock:
    client = MagicMock()
    client.query_package.return_value = query_return or []
    client.query_batch.return_value = batch_return or {}
    return client


# ---------------------------------------------------------------------------
# Scanner.scan_package
# ---------------------------------------------------------------------------

class TestScanPackage:
    def test_clean_package_returns_allow(self):
        osv = _mock_osv_client(query_return=[])
        scanner = Scanner(config=_make_config(), osv_client=osv)

        result = scanner.scan_package("requests", "2.31.0")

        assert result.action == PolicyAction.ALLOW
        assert result.name == "requests"
        assert result.version == "2.31.0"
        assert result.vulnerabilities == []
        osv.query_package.assert_called_once_with("requests", "2.31.0")

    def test_vulnerable_package_gets_blocked(self):
        vuln = _make_vuln(severity=Severity.CRITICAL)
        osv = _mock_osv_client(query_return=[vuln])
        scanner = Scanner(config=_make_config(), osv_client=osv)

        result = scanner.scan_package("flask", "0.12.0")

        assert result.action == PolicyAction.BLOCK
        assert result.is_vulnerable
        assert "PYSEC-2024-001" in result.reason

    def test_medium_severity_gets_alert(self):
        vuln = _make_vuln(severity=Severity.MEDIUM)
        osv = _mock_osv_client(query_return=[vuln])
        scanner = Scanner(config=_make_config(), osv_client=osv)

        result = scanner.scan_package("some-pkg", "1.0.0")

        assert result.action == PolicyAction.ALERT

    def test_allowlisted_package_skips_osv(self):
        osv = _mock_osv_client()
        config = _make_config(allowlist=["trusted-pkg"])
        scanner = Scanner(config=config, osv_client=osv)

        result = scanner.scan_package("trusted-pkg", "1.0.0")

        assert result.action == PolicyAction.ALLOW
        assert "allowlist" in result.reason
        osv.query_package.assert_not_called()

    def test_blocklisted_package_skips_osv(self):
        osv = _mock_osv_client()
        config = _make_config(blocklist=["evil-pkg"])
        scanner = Scanner(config=config, osv_client=osv)

        result = scanner.scan_package("evil-pkg", "0.1.0")

        assert result.action == PolicyAction.BLOCK
        assert "blocklist" in result.reason
        osv.query_package.assert_not_called()

    def test_osv_error_falls_back_to_allow(self):
        osv = _mock_osv_client()
        osv.query_package.side_effect = OSVError("network error")
        scanner = Scanner(config=_make_config(), osv_client=osv)

        result = scanner.scan_package("oops", "1.0.0")

        assert result.action == PolicyAction.ALLOW
        assert result.vulnerabilities == []

    def test_osv_error_with_fail_closed_returns_alert(self):
        osv = _mock_osv_client()
        osv.query_package.side_effect = OSVError("network error")
        config = _make_config(fail_closed=True)
        scanner = Scanner(config=config, osv_client=osv)

        result = scanner.scan_package("oops", "1.0.0")

        assert result.action == PolicyAction.ALERT
        assert "fail-closed" in result.reason
        assert "network error" in result.reason

    def test_multiple_vulns_uses_highest_severity(self):
        vulns = [
            _make_vuln("V-1", Severity.LOW),
            _make_vuln("V-2", Severity.HIGH),
            _make_vuln("V-3", Severity.MEDIUM),
        ]
        osv = _mock_osv_client(query_return=vulns)
        scanner = Scanner(config=_make_config(), osv_client=osv)

        result = scanner.scan_package("pkg", "1.0.0")

        # HIGH → block per default config
        assert result.action == PolicyAction.BLOCK
        assert "3 vulnerabilities" in result.reason

    def test_more_than_five_vulns_shows_suffix(self):
        vulns = [_make_vuln(f"V-{i}", Severity.LOW) for i in range(7)]
        osv = _mock_osv_client(query_return=vulns)
        scanner = Scanner(config=_make_config(), osv_client=osv)

        result = scanner.scan_package("pkg", "1.0.0")

        assert "+2 more" in result.reason


# ---------------------------------------------------------------------------
# Scanner.scan_environment
# ---------------------------------------------------------------------------

class TestScanEnvironment:
    def test_scans_installed_packages(self):
        fake_pkgs = [("requests", "2.31.0"), ("flask", "2.3.3")]
        batch_vulns = {
            ("requests", "2.31.0"): [],
            ("flask", "2.3.3"): [_make_vuln()],
        }
        osv = _mock_osv_client(batch_return=batch_vulns)
        scanner = Scanner(config=_make_config(), osv_client=osv)

        with patch("alterks.scanner._get_installed_packages", return_value=fake_pkgs):
            results = scanner.scan_environment()

        assert len(results) == 2
        names = {r.name for r in results}
        assert names == {"requests", "flask"}
        osv.query_batch.assert_called_once()

    def test_empty_environment(self):
        osv = _mock_osv_client()
        scanner = Scanner(config=_make_config(), osv_client=osv)

        with patch("alterks.scanner._get_installed_packages", return_value=[]):
            results = scanner.scan_environment()

        assert results == []
        osv.query_batch.assert_not_called()

    def test_allowlisted_skipped_in_batch(self):
        fake_pkgs = [("trusted", "1.0.0"), ("other", "2.0.0")]
        batch_vulns = {("other", "2.0.0"): []}
        osv = _mock_osv_client(batch_return=batch_vulns)
        config = _make_config(allowlist=["trusted"])
        scanner = Scanner(config=config, osv_client=osv)

        with patch("alterks.scanner._get_installed_packages", return_value=fake_pkgs):
            results = scanner.scan_environment()

        assert len(results) == 2
        # Only "other" should be in the batch query
        osv.query_batch.assert_called_once_with([("other", "2.0.0")])

    def test_batch_osv_error_fail_open(self):
        fake_pkgs = [("requests", "2.31.0")]
        osv = _mock_osv_client()
        osv.query_batch.side_effect = OSVError("API down")
        scanner = Scanner(config=_make_config(), osv_client=osv)

        with patch("alterks.scanner._get_installed_packages", return_value=fake_pkgs):
            results = scanner.scan_environment()

        assert len(results) == 1
        assert results[0].action == PolicyAction.ALLOW

    def test_batch_osv_error_fail_closed(self):
        fake_pkgs = [("requests", "2.31.0"), ("flask", "2.3.3")]
        osv = _mock_osv_client()
        osv.query_batch.side_effect = OSVError("API down")
        config = _make_config(fail_closed=True)
        scanner = Scanner(config=config, osv_client=osv)

        with patch("alterks.scanner._get_installed_packages", return_value=fake_pkgs):
            results = scanner.scan_environment()

        assert len(results) == 2
        for r in results:
            assert r.action == PolicyAction.ALERT
            assert "fail-closed" in r.reason


# ---------------------------------------------------------------------------
# Scanner.scan_requirements
# ---------------------------------------------------------------------------

class TestScanRequirements:
    def test_scans_pinned_requirements(self, tmp_path: Path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.31.0\nflask==2.3.3\n")

        batch_vulns = {
            ("requests", "2.31.0"): [],
            ("flask", "2.3.3"): [_make_vuln()],
        }
        osv = _mock_osv_client(batch_return=batch_vulns)
        scanner = Scanner(config=_make_config(), osv_client=osv)

        results = scanner.scan_requirements(req_file)

        assert len(results) == 2
        osv.query_batch.assert_called_once()

    def test_missing_file_raises(self):
        osv = _mock_osv_client()
        scanner = Scanner(config=_make_config(), osv_client=osv)

        with pytest.raises(FileNotFoundError):
            scanner.scan_requirements(Path("/nonexistent/requirements.txt"))

    def test_empty_requirements_file(self, tmp_path: Path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# just a comment\n\n")

        osv = _mock_osv_client()
        scanner = Scanner(config=_make_config(), osv_client=osv)

        results = scanner.scan_requirements(req_file)

        assert results == []
        osv.query_batch.assert_not_called()


# ---------------------------------------------------------------------------
# _parse_requirements_file
# ---------------------------------------------------------------------------

class TestParseRequirementsFile:
    def test_pinned_versions(self, tmp_path: Path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.31.0\nflask==2.3.3\n")

        result = _parse_requirements_file(req_file)

        assert ("requests", "2.31.0") in result
        assert ("flask", "2.3.3") in result

    def test_skips_unpinned(self, tmp_path: Path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests>=2.0\nflask==2.3.3\n")

        result = _parse_requirements_file(req_file)

        assert len(result) == 1
        assert result[0] == ("flask", "2.3.3")

    def test_skips_comments_and_blank_lines(self, tmp_path: Path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# comment\n\nflask==2.3.3  # inline\n")

        result = _parse_requirements_file(req_file)

        assert result == [("flask", "2.3.3")]

    def test_skips_pip_options(self, tmp_path: Path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("-i https://pypi.org/simple\n--index-url https://pypi.org\nflask==1.0\n")

        result = _parse_requirements_file(req_file)

        assert result == [("flask", "1.0")]

    def test_file_not_found(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            _parse_requirements_file(tmp_path / "missing.txt")


# ---------------------------------------------------------------------------
# _extract_pinned_version
# ---------------------------------------------------------------------------

class TestExtractPinnedVersion:
    def test_pinned(self):
        from packaging.requirements import Requirement
        assert _extract_pinned_version(Requirement("flask==2.3.3")) == "2.3.3"

    def test_not_pinned(self):
        from packaging.requirements import Requirement
        assert _extract_pinned_version(Requirement("flask>=2.0")) is None

    def test_no_specifiers(self):
        from packaging.requirements import Requirement
        assert _extract_pinned_version(Requirement("flask")) is None


# ---------------------------------------------------------------------------
# _resolve_action
# ---------------------------------------------------------------------------

class TestResolveAction:
    def test_no_vulns_allows(self):
        scanner = Scanner(config=_make_config(), osv_client=_mock_osv_client())
        action, reason = scanner._resolve_action("pkg", "1.0.0", [])
        assert action == PolicyAction.ALLOW
        assert "No known vulnerabilities" in reason

    def test_critical_blocks(self):
        scanner = Scanner(config=_make_config(), osv_client=_mock_osv_client())
        vulns = [_make_vuln(severity=Severity.CRITICAL)]
        action, _ = scanner._resolve_action("pkg", "1.0.0", vulns)
        assert action == PolicyAction.BLOCK

    def test_low_allows(self):
        scanner = Scanner(config=_make_config(), osv_client=_mock_osv_client())
        vulns = [_make_vuln(severity=Severity.LOW)]
        action, _ = scanner._resolve_action("pkg", "1.0.0", vulns)
        assert action == PolicyAction.ALLOW

    def test_custom_severity_actions(self):
        from alterks.config import _parse_severity_actions
        custom = _parse_severity_actions({"low": "quarantine", "medium": "block"})
        config = _make_config(severity_actions=custom)
        scanner = Scanner(config=config, osv_client=_mock_osv_client())

        vulns = [_make_vuln(severity=Severity.LOW)]
        action, _ = scanner._resolve_action("pkg", "1.0.0", vulns)
        assert action == PolicyAction.QUARANTINE
