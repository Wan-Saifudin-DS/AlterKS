"""Phase 3 tests: T12 (JSON Schema), T13 (Quarantine E2E), T14 (Rich Table Layout).

T12: JSON report includes file_path/line_range for code pattern findings,
     defaults to null for metadata-only findings.
T13: _do_quarantine() creates venv via QuarantineManager and records manifest.
T14: Rich table renders code findings without layout breakage.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from alterks.actions import _do_quarantine, execute_action
from alterks.cli import _format_findings, _render_json, _render_table, main
from alterks.models import (
    PackageRisk,
    PolicyAction,
    RiskFactor,
    ScanResult,
    Severity,
    Vulnerability,
)

try:
    from click.testing import CliRunner
except ImportError:
    CliRunner = None  # type: ignore[misc]

from rich.console import Console


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _result_with_risk(
    name: str = "evil-pkg",
    version: str = "0.1.0",
    action: PolicyAction = PolicyAction.ALERT,
    reason: str = "suspicious code",
    code_pattern_score: float = 0.85,
    file_path: str = "setup.py",
    line_range: str = "14",
) -> ScanResult:
    """Create a ScanResult with code_patterns risk factor."""
    factors = [
        RiskFactor(
            name="typosquatting",
            score=0.3,
            weight=0.25,
            reason="Edit distance 2 from 'requests'",
        ),
        RiskFactor(
            name="code_patterns",
            score=code_pattern_score,
            weight=0.25,
            reason=f"exec/eval with obfuscated input in {file_path}:{line_range}",
            file_path=file_path,
            line_range=line_range,
        ),
        RiskFactor(
            name="package_age",
            score=0.0,
            weight=0.15,
            reason="Package is 500 days old",
        ),
    ]
    risk = PackageRisk(
        name=name,
        version=version,
        risk_score=45.0,
        risk_factors=factors,
    )
    return ScanResult(
        name=name,
        version=version,
        action=action,
        reason=reason,
        risk=risk,
    )


def _result_metadata_only(
    name: str = "safe-pkg",
    version: str = "2.0.0",
) -> ScanResult:
    """Create a ScanResult with metadata-only risk factors (no file_path)."""
    factors = [
        RiskFactor(
            name="typosquatting",
            score=0.0,
            weight=0.25,
            reason="",
        ),
        RiskFactor(
            name="code_patterns",
            score=0.0,
            weight=0.25,
            reason="No suspicious code patterns detected",
            file_path=None,
            line_range=None,
        ),
    ]
    risk = PackageRisk(
        name=name,
        version=version,
        risk_score=0.0,
        risk_factors=factors,
    )
    return ScanResult(
        name=name,
        version=version,
        action=PolicyAction.ALLOW,
        reason="clean",
        risk=risk,
    )


# ---------------------------------------------------------------------------
# T12: JSON Schema Validation
# ---------------------------------------------------------------------------

class TestJSONSchemaValidation:
    """Assert JSON report includes file_path/line_range for code pattern
    findings and defaults to null for metadata-only findings."""

    def test_code_pattern_has_file_path_and_line_range(self):
        result = _result_with_risk()
        json_str = _render_json([result])
        data = json.loads(json_str)

        assert len(data) == 1
        entry = data[0]
        assert "risk_factors" in entry
        cp = next(f for f in entry["risk_factors"] if f["name"] == "code_patterns")
        assert cp["file_path"] == "setup.py"
        assert cp["line_range"] == "14"
        assert cp["score"] > 0

    def test_metadata_only_has_null_fields(self):
        result = _result_metadata_only()
        json_str = _render_json([result])
        data = json.loads(json_str)

        entry = data[0]
        assert "risk_factors" in entry
        typo = next(f for f in entry["risk_factors"] if f["name"] == "typosquatting")
        assert typo["file_path"] is None
        assert typo["line_range"] is None

    def test_mixed_results_schema(self):
        results = [_result_with_risk(), _result_metadata_only()]
        json_str = _render_json(results)
        data = json.loads(json_str)

        assert len(data) == 2
        # Each entry should have risk_factors key
        for entry in data:
            assert "risk_factors" in entry
            assert isinstance(entry["risk_factors"], list)

    def test_no_risk_empty_factors(self):
        result = ScanResult(
            name="bare-pkg", version="1.0", action=PolicyAction.ALLOW
        )
        json_str = _render_json([result])
        data = json.loads(json_str)
        assert data[0]["risk_factors"] == []

    def test_risk_factor_fields_present(self):
        result = _result_with_risk()
        json_str = _render_json([result])
        data = json.loads(json_str)

        for factor in data[0]["risk_factors"]:
            assert "name" in factor
            assert "score" in factor
            assert "weight" in factor
            assert "reason" in factor
            assert "file_path" in factor
            assert "line_range" in factor


# ---------------------------------------------------------------------------
# T13: Quarantine E2E Test
# ---------------------------------------------------------------------------

class TestQuarantineE2E:
    """Verify _do_quarantine() calls QuarantineManager.quarantine_package()."""

    @patch("alterks.actions.QuarantineManager")
    def test_quarantine_calls_manager(self, mock_qm_cls):
        mock_qm = MagicMock()
        mock_qm_cls.return_value = mock_qm

        result = ScanResult(
            name="suspect",
            version="0.1.0",
            action=PolicyAction.QUARANTINE,
            reason="risky package",
            vulnerabilities=[
                Vulnerability(id="PYSEC-2024-001", summary="test vuln"),
            ],
        )
        risk = PackageRisk(name="suspect", version="0.1.0", risk_score=75.0)
        result.risk = risk

        stderr = io.StringIO()
        action_result = _do_quarantine(result, stderr)

        # Verify QuarantineManager was called
        mock_qm.quarantine_package.assert_called_once_with(
            "suspect",
            "0.1.0",
            "risky package",
            vulnerability_ids=["PYSEC-2024-001"],
            risk_score=75.0,
        )
        assert action_result.action == PolicyAction.QUARANTINE
        assert "QUARANTINE" in stderr.getvalue()

    @patch("alterks.actions.QuarantineManager")
    def test_quarantine_via_execute_action(self, mock_qm_cls):
        mock_qm = MagicMock()
        mock_qm_cls.return_value = mock_qm

        result = ScanResult(
            name="suspect",
            version="0.2.0",
            action=PolicyAction.QUARANTINE,
            reason="test quarantine",
        )

        stderr = io.StringIO()
        action_result = execute_action(result, stderr=stderr)

        assert action_result.action == PolicyAction.QUARANTINE
        mock_qm.quarantine_package.assert_called_once()

    @patch("alterks.actions.QuarantineManager")
    def test_quarantine_with_no_vulns(self, mock_qm_cls):
        mock_qm = MagicMock()
        mock_qm_cls.return_value = mock_qm

        result = ScanResult(
            name="unknown-pkg",
            version="1.0.0",
            action=PolicyAction.QUARANTINE,
            reason="heuristic risk",
        )

        stderr = io.StringIO()
        _do_quarantine(result, stderr)

        mock_qm.quarantine_package.assert_called_once_with(
            "unknown-pkg",
            "1.0.0",
            "heuristic risk",
            vulnerability_ids=[],
            risk_score=0.0,
        )

    @patch("alterks.actions.QuarantineManager")
    def test_quarantine_failure_does_not_crash(self, mock_qm_cls):
        """If quarantine fails, the action should still return."""
        mock_qm = MagicMock()
        mock_qm.quarantine_package.side_effect = OSError("disk full")
        mock_qm_cls.return_value = mock_qm

        result = ScanResult(
            name="pkg",
            version="1.0",
            action=PolicyAction.QUARANTINE,
            reason="test",
        )
        stderr = io.StringIO()
        action_result = _do_quarantine(result, stderr)

        assert action_result.action == PolicyAction.QUARANTINE
        assert not action_result.blocked


# ---------------------------------------------------------------------------
# T14: CLI Rich Table Layout Test
# ---------------------------------------------------------------------------

class TestCLIRichTableLayout:
    """Verify findings render correctly in Rich tables without breakage."""

    def test_format_findings_with_code_pattern(self):
        result = _result_with_risk()
        text = _format_findings(result)
        assert "code_patterns" in text
        assert "setup.py:14" in text

    def test_format_findings_metadata_only(self):
        result = _result_metadata_only()
        text = _format_findings(result)
        # All scores are 0, so nothing should appear
        assert text == ""

    def test_format_findings_no_risk(self):
        result = ScanResult(name="pkg", version="1.0", action=PolicyAction.ALLOW)
        text = _format_findings(result)
        assert text == ""

    def test_format_findings_long_file_path(self):
        """Long file paths should not crash the formatter."""
        result = _result_with_risk(
            file_path="very/deeply/nested/package/subdirectory/inner/setup.py",
            line_range="142-156",
        )
        text = _format_findings(result)
        assert "setup.py" in text
        assert "142-156" in text

    def test_render_table_does_not_crash(self):
        """Rich table rendering with findings should not raise."""
        results = [_result_with_risk(), _result_metadata_only()]
        console = Console(file=io.StringIO(), no_color=True, width=120)
        _render_table(results, console)
        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "evil-pkg" in output
        assert "safe-pkg" in output

    def test_render_table_with_many_findings(self):
        """Table with many risk factors should cap at 5."""
        factors = [
            RiskFactor(name=f"factor_{i}", score=0.5, weight=0.1, reason=f"reason {i}")
            for i in range(10)
        ]
        risk = PackageRisk(name="pkg", version="1.0", risk_score=50.0, risk_factors=factors)
        result = ScanResult(
            name="pkg", version="1.0", action=PolicyAction.ALERT, risk=risk
        )
        text = _format_findings(result)
        # Should cap at 5 findings
        assert text.count("factor_") <= 5

    @pytest.mark.skipif(CliRunner is None, reason="click testing not available")
    @patch("alterks.cli.Scanner")
    @patch("alterks.cli.load_config")
    def test_scan_table_with_findings(self, mock_config, mock_scanner_cls):
        """Full CLI scan with findings column in table output."""
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [_result_with_risk()]
        mock_scanner_cls.return_value = mock_scanner

        runner = CliRunner()
        result = runner.invoke(main, ["scan"])

        assert result.exit_code == 0
        assert "evil-pkg" in result.output
