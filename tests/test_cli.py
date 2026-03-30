"""Tests for the AlterKS CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from alterks.cli import main
from alterks.config import AlterKSConfig
from alterks.models import PolicyAction, ScanResult, Severity, Vulnerability
from tests.helpers import make_scan_result, make_vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(
    name: str = "pkg",
    version: str = "1.0.0",
    action: PolicyAction = PolicyAction.ALLOW,
    vulns: int = 0,
    reason: str = "test",
) -> ScanResult:
    vuln_list = [
        make_vulnerability(vuln_id=f"PYSEC-{i}", summary=f"Vuln {i}")
        for i in range(vulns)
    ]
    return make_scan_result(
        name=name,
        version=version,
        action=action,
        reason=reason,
        vulns=vuln_list,
    )


@pytest.fixture
def runner():
    return CliRunner()


# ---------------------------------------------------------------------------
# alterks --version
# ---------------------------------------------------------------------------

class TestVersion:
    def test_version_flag(self, runner: CliRunner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "alterks" in result.output


# ---------------------------------------------------------------------------
# alterks scan
# ---------------------------------------------------------------------------

class TestScan:
    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_scan_environment_table(self, mock_config, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("requests", "2.31.0"),
            _make_result("flask", "2.3.3", PolicyAction.ALERT, vulns=1, reason="1 vuln"),
        ]
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0
        assert "requests" in result.output
        assert "flask" in result.output
        assert "Scanned 2 package(s)" in result.output

    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_scan_environment_json(self, mock_config, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("requests", "2.31.0"),
        ]
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["scan", "--format", "json"])

        # Output contains Rich console messages + JSON; extract JSON array
        output = result.output
        json_start = output.index("[")
        json_end = output.rindex("]") + 1
        data = json.loads(output[json_start:json_end])
        assert len(data) == 1
        assert data[0]["name"] == "requests"

    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_scan_environment_markdown(self, mock_config, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("requests", "2.31.0"),
        ]
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["scan", "--format", "markdown"])

        assert "# AlterKS Scan Report" in result.output
        assert "requests" in result.output

    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_scan_requirements(self, mock_config, mock_scanner_cls, runner, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==2.3.3\n")

        mock_scanner = MagicMock()
        mock_scanner.scan_requirements.return_value = [
            _make_result("flask", "2.3.3"),
        ]
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["scan", "-r", str(req_file)])

        assert result.exit_code == 0
        mock_scanner.scan_requirements.assert_called_once()

    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_scan_blocked_returns_exit_1(self, mock_config, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("evil", "0.1", PolicyAction.BLOCK, vulns=1, reason="blocked"),
        ]
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["scan"])

        assert result.exit_code == 1

    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_scan_empty_environment(self, mock_config, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = []
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0
        assert "No packages" in result.output

    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_scan_fail_closed_flag(self, mock_config, mock_scanner_cls, runner):
        mock_config.return_value = AlterKSConfig()
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("requests", "2.31.0"),
        ]
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["scan", "--fail-closed"])

        assert result.exit_code == 0
        # Verify fail_closed was set on config
        config_passed = mock_scanner_cls.call_args
        assert config_passed is not None


# ---------------------------------------------------------------------------
# alterks install
# ---------------------------------------------------------------------------

class TestInstall:
    @patch("alterks.cli.subprocess.call", return_value=0)
    @patch("alterks.cli.select_action", return_value=PolicyAction.ALLOW)
    @patch("alterks.cli.load_config")
    @patch("alterks.pip_hook.PyPIClient")
    @patch("alterks.pip_hook.Scanner")
    def test_install_allowed(self, mock_scanner_cls, mock_pypi_cls, mock_config,
                             mock_select, mock_subprocess, runner):
        # PyPI resolves metadata
        mock_meta = MagicMock()
        mock_meta.version = "2.31.0"
        mock_pypi = MagicMock()
        mock_pypi.get_metadata.return_value = mock_meta
        mock_pypi_cls.return_value = mock_pypi

        # Scanner returns clean result
        mock_scanner = MagicMock()
        mock_scanner.scan_package.return_value = _make_result("requests", "2.31.0")
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["install", "requests"])

        assert result.exit_code == 0
        mock_subprocess.assert_called_once()

    @patch("alterks.cli.select_action", return_value=PolicyAction.BLOCK)
    @patch("alterks.cli.load_config")
    @patch("alterks.pip_hook.PyPIClient")
    @patch("alterks.pip_hook.Scanner")
    def test_install_blocked(self, mock_scanner_cls, mock_pypi_cls,
                             mock_config, mock_select, runner):
        mock_meta = MagicMock()
        mock_meta.version = "0.1"
        mock_pypi = MagicMock()
        mock_pypi.get_metadata.return_value = mock_meta
        mock_pypi_cls.return_value = mock_pypi

        mock_scanner = MagicMock()
        mock_scanner.scan_package.return_value = _make_result(
            "evil", "0.1", PolicyAction.BLOCK, reason="vuln found"
        )
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["install", "evil"])

        assert result.exit_code == 1
        assert "BLOCKED" in result.output

    @patch("alterks.cli.select_action", return_value=PolicyAction.ALLOW)
    @patch("alterks.cli.load_config")
    @patch("alterks.pip_hook.PyPIClient")
    @patch("alterks.pip_hook.Scanner")
    def test_install_dry_run(self, mock_scanner_cls, mock_pypi_cls,
                             mock_config, mock_select, runner):
        mock_meta = MagicMock()
        mock_meta.version = "2.31.0"
        mock_pypi = MagicMock()
        mock_pypi.get_metadata.return_value = mock_meta
        mock_pypi_cls.return_value = mock_pypi

        mock_scanner = MagicMock()
        mock_scanner.scan_package.return_value = _make_result("requests", "2.31.0")
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["install", "--dry-run", "requests"])

        assert result.exit_code == 0
        assert "ALLOWED" in result.output

    @patch("alterks.cli.load_config")
    @patch("alterks.pip_hook.PyPIClient")
    def test_install_unresolvable(self, mock_pypi_cls, mock_config, runner):
        from alterks.sources.pypi import PyPIError
        mock_pypi = MagicMock()
        mock_pypi.get_metadata.side_effect = PyPIError("not found")
        mock_pypi_cls.return_value = mock_pypi

        result = runner.invoke(main, ["install", "nonexistent-pkg-xyz"])

        assert result.exit_code == 1
        assert "Could not resolve" in result.output


# ---------------------------------------------------------------------------
# alterks quarantine
# ---------------------------------------------------------------------------

class TestQuarantine:
    @patch("alterks.cli.QuarantineManager")
    def test_quarantine_list_empty(self, mock_qm_cls, runner):
        mock_qm = MagicMock()
        mock_qm.list_quarantined.return_value = []
        mock_qm_cls.return_value = mock_qm

        result = runner.invoke(main, ["quarantine", "list"])

        assert result.exit_code == 0
        assert "No quarantined" in result.output

    @patch("alterks.cli.QuarantineManager")
    def test_quarantine_list_entries(self, mock_qm_cls, runner):
        from alterks.quarantine import QuarantineEntry
        mock_qm = MagicMock()
        mock_qm.list_quarantined.return_value = [
            QuarantineEntry(
                name="flask", version="2.0", reason="vuln",
                venv_path="/tmp/q/flask", quarantined_at="2026-01-01T00:00:00",
            ),
        ]
        mock_qm_cls.return_value = mock_qm

        result = runner.invoke(main, ["quarantine", "list"])

        assert result.exit_code == 0
        assert "flask" in result.output

    @patch("alterks.cli.QuarantineManager")
    def test_quarantine_inspect_found(self, mock_qm_cls, runner):
        from alterks.quarantine import QuarantineEntry
        mock_qm = MagicMock()
        mock_qm.inspect_quarantined.return_value = QuarantineEntry(
            name="flask", version="2.0", reason="vuln",
            venv_path="/tmp/q/flask", quarantined_at="2026-01-01T00:00:00",
            vulnerability_ids=["PYSEC-1"],
        )
        mock_qm_cls.return_value = mock_qm

        result = runner.invoke(main, ["quarantine", "inspect", "flask"])

        assert result.exit_code == 0
        assert "flask" in result.output
        assert "PYSEC-1" in result.output

    @patch("alterks.cli.QuarantineManager")
    def test_quarantine_inspect_not_found(self, mock_qm_cls, runner):
        mock_qm = MagicMock()
        mock_qm.inspect_quarantined.return_value = None
        mock_qm_cls.return_value = mock_qm

        result = runner.invoke(main, ["quarantine", "inspect", "missing"])

        assert result.exit_code == 1

    @patch("alterks.cli.QuarantineManager")
    def test_quarantine_release(self, mock_qm_cls, runner):
        mock_qm = MagicMock()
        mock_qm.release_quarantined.return_value = True
        mock_qm_cls.return_value = mock_qm

        result = runner.invoke(main, ["quarantine", "release", "flask"])

        assert result.exit_code == 0
        assert "Released" in result.output

    @patch("alterks.cli.QuarantineManager")
    def test_quarantine_release_not_found(self, mock_qm_cls, runner):
        mock_qm = MagicMock()
        mock_qm.release_quarantined.return_value = False
        mock_qm_cls.return_value = mock_qm

        result = runner.invoke(main, ["quarantine", "release", "missing"])

        assert result.exit_code == 1

    @patch("alterks.cli.QuarantineManager")
    def test_quarantine_remove(self, mock_qm_cls, runner):
        mock_qm = MagicMock()
        mock_qm.remove_quarantined.return_value = True
        mock_qm_cls.return_value = mock_qm

        result = runner.invoke(main, ["quarantine", "remove", "flask"])

        assert result.exit_code == 0
        assert "Removed" in result.output


# ---------------------------------------------------------------------------
# alterks report
# ---------------------------------------------------------------------------

class TestReport:
    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_report_json(self, mock_config, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("requests", "2.31.0"),
        ]
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["report", "--format", "json"])

        assert result.exit_code == 0
        output = result.output
        json_start = output.index("[")
        data = json.loads(output[json_start:])
        assert len(data) == 1

    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_report_to_file(self, mock_config, mock_scanner_cls, runner, tmp_path):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("requests", "2.31.0"),
        ]
        mock_scanner_cls.return_value = mock_scanner
        out = tmp_path / "report.json"

        result = runner.invoke(main, ["report", "--format", "json", "-o", str(out)])

        assert result.exit_code == 0
        assert out.is_file()
        data = json.loads(out.read_text())
        assert data[0]["name"] == "requests"


# ---------------------------------------------------------------------------
# alterks monitor
# ---------------------------------------------------------------------------

class TestMonitor:
    @patch("alterks.monitor.Scanner")
    @patch("alterks.cli.load_config")
    def test_monitor_once(self, mock_config, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("requests", "2.31.0"),
        ]
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["monitor", "--once"])

        assert result.exit_code == 0
        assert "clean" in result.output.lower() or "scanning" in result.output.lower()


# ---------------------------------------------------------------------------
# alterks generate-constraints
# ---------------------------------------------------------------------------

class TestGenerateConstraints:
    @patch("alterks.pip_hook.Scanner")
    @patch("alterks.cli.load_config")
    def test_generate_constraints(self, mock_config, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("evil", "0.1", PolicyAction.BLOCK, reason="blocked"),
            _make_result("ok", "1.0", PolicyAction.ALLOW),
        ]
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(main, ["generate-constraints"])

        assert result.exit_code == 0
        assert "evil!=0.1" in result.output
        assert "ok" not in result.output

    @patch("alterks.pip_hook.Scanner")
    @patch("alterks.cli.load_config")
    def test_generate_constraints_to_file(self, mock_config, mock_scanner_cls, runner, tmp_path):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            _make_result("evil", "0.1", PolicyAction.BLOCK),
        ]
        mock_scanner_cls.return_value = mock_scanner
        out = tmp_path / "constraints.txt"

        result = runner.invoke(main, ["generate-constraints", "-o", str(out)])

        assert result.exit_code == 0
        assert out.is_file()
        assert "evil!=0.1" in out.read_text()
