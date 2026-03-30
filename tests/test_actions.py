"""Tests for the action engine."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from alterks.actions import (
    ActionResult,
    _do_alert,
    _do_allow,
    _do_block,
    _do_quarantine,
    _determine_final_action,
    _write_json_report,
    execute_action,
    select_action,
)
from alterks.config import AlterKSConfig
from alterks.models import (
    PackageRisk,
    PolicyAction,
    RiskFactor,
    ScanResult,
    Severity,
    Vulnerability,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vuln(vuln_id: str = "PYSEC-2024-001", severity: Severity = Severity.HIGH) -> Vulnerability:
    return Vulnerability(id=vuln_id, summary="Test vuln", severity=severity)


def _result(
    action: PolicyAction = PolicyAction.ALLOW,
    vulns: list | None = None,
    risk_score: float = 0.0,
    reason: str = "test",
) -> ScanResult:
    risk = PackageRisk(name="pkg", version="1.0", risk_score=risk_score) if risk_score else None
    return ScanResult(
        name="pkg",
        version="1.0.0",
        vulnerabilities=vulns or [],
        risk=risk,
        action=action,
        reason=reason,
    )


# ---------------------------------------------------------------------------
# ActionResult
# ---------------------------------------------------------------------------

class TestActionResult:
    def test_to_dict(self):
        ar = ActionResult(
            action=PolicyAction.BLOCK,
            package="evil",
            version="0.1",
            reason="blocked",
            blocked=True,
        )
        d = ar.to_dict()
        assert d["action"] == "block"
        assert d["blocked"] is True
        assert "timestamp" in d


# ---------------------------------------------------------------------------
# _determine_final_action
# ---------------------------------------------------------------------------

class TestDetermineFinalAction:
    def test_preserves_vuln_action(self):
        r = _result(action=PolicyAction.BLOCK)
        assert _determine_final_action(r) == PolicyAction.BLOCK

    def test_allow_stays_allow_without_risk(self):
        r = _result(action=PolicyAction.ALLOW)
        assert _determine_final_action(r) == PolicyAction.ALLOW

    def test_elevates_to_block_on_risk_threshold(self):
        r = _result(action=PolicyAction.ALLOW, risk_score=80.0)
        config = AlterKSConfig(risk_threshold=60.0)
        assert _determine_final_action(r, config) == PolicyAction.BLOCK

    def test_alert_elevated_to_block_on_risk(self):
        r = _result(action=PolicyAction.ALERT, risk_score=75.0)
        config = AlterKSConfig(risk_threshold=60.0)
        assert _determine_final_action(r, config) == PolicyAction.BLOCK

    def test_quarantine_not_elevated(self):
        r = _result(action=PolicyAction.QUARANTINE, risk_score=80.0)
        config = AlterKSConfig(risk_threshold=60.0)
        assert _determine_final_action(r, config) == PolicyAction.QUARANTINE

    def test_below_threshold_stays(self):
        r = _result(action=PolicyAction.ALLOW, risk_score=30.0)
        config = AlterKSConfig(risk_threshold=60.0)
        assert _determine_final_action(r, config) == PolicyAction.ALLOW


# ---------------------------------------------------------------------------
# Block action
# ---------------------------------------------------------------------------

class TestDoBlock:
    def test_raises_system_exit(self):
        r = _result(action=PolicyAction.BLOCK, reason="dangerous")
        stderr = io.StringIO()
        with pytest.raises(SystemExit, match="blocked"):
            _do_block(r, stderr)

    def test_writes_to_stderr(self):
        r = _result(
            action=PolicyAction.BLOCK,
            vulns=[_vuln()],
            reason="1 vulnerability found (max severity: high): PYSEC-2024-001",
        )
        stderr = io.StringIO()
        with pytest.raises(SystemExit):
            _do_block(r, stderr)
        output = stderr.getvalue()
        assert "BLOCKED" in output
        assert "pkg" in output
        assert "PYSEC-2024-001" in output

    def test_block_shows_risk_score(self):
        r = _result(action=PolicyAction.BLOCK, risk_score=85.0, reason="risky")
        stderr = io.StringIO()
        with pytest.raises(SystemExit):
            _do_block(r, stderr)
        assert "85.0" in stderr.getvalue()


# ---------------------------------------------------------------------------
# Alert action
# ---------------------------------------------------------------------------

class TestDoAlert:
    def test_writes_warning_to_stderr(self):
        r = _result(action=PolicyAction.ALERT, reason="medium vuln")
        stderr = io.StringIO()
        result = _do_alert(r, None, stderr)
        assert "WARNING" in stderr.getvalue()
        assert result.action == PolicyAction.ALERT
        assert not result.blocked

    def test_writes_json_report(self, tmp_path: Path):
        r = _result(action=PolicyAction.ALERT, reason="alert test")
        report = tmp_path / "report.jsonl"
        stderr = io.StringIO()
        _do_alert(r, report, stderr)

        assert report.is_file()
        data = json.loads(report.read_text().strip())
        assert data["action"] == "alert"
        assert data["package"] == "pkg"

    def test_appends_multiple_reports(self, tmp_path: Path):
        report = tmp_path / "report.jsonl"
        stderr = io.StringIO()
        _do_alert(_result(reason="first"), report, stderr)
        _do_alert(_result(reason="second"), report, stderr)
        lines = report.read_text().strip().splitlines()
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# Quarantine action
# ---------------------------------------------------------------------------

class TestDoQuarantine:
    def test_writes_to_stderr(self):
        r = _result(action=PolicyAction.QUARANTINE, reason="suspect")
        stderr = io.StringIO()
        result = _do_quarantine(r, stderr)
        assert "QUARANTINE" in stderr.getvalue()
        assert result.action == PolicyAction.QUARANTINE
        assert not result.blocked


# ---------------------------------------------------------------------------
# Allow action
# ---------------------------------------------------------------------------

class TestDoAllow:
    def test_returns_allow(self):
        r = _result(action=PolicyAction.ALLOW, reason="clean")
        result = _do_allow(r)
        assert result.action == PolicyAction.ALLOW
        assert not result.blocked


# ---------------------------------------------------------------------------
# execute_action
# ---------------------------------------------------------------------------

class TestExecuteAction:
    def test_block_raises(self):
        r = _result(action=PolicyAction.BLOCK, reason="bad")
        with pytest.raises(SystemExit):
            execute_action(r)

    def test_alert_returns(self):
        r = _result(action=PolicyAction.ALERT, reason="warn")
        result = execute_action(r)
        assert result.action == PolicyAction.ALERT

    def test_allow_returns(self):
        r = _result(action=PolicyAction.ALLOW, reason="ok")
        result = execute_action(r)
        assert result.action == PolicyAction.ALLOW

    def test_quarantine_returns(self):
        r = _result(action=PolicyAction.QUARANTINE, reason="suspect")
        result = execute_action(r)
        assert result.action == PolicyAction.QUARANTINE

    def test_risk_elevation(self):
        r = _result(action=PolicyAction.ALLOW, risk_score=90.0, reason="risky")
        config = AlterKSConfig(risk_threshold=60.0)
        with pytest.raises(SystemExit):
            execute_action(r, config=config)


# ---------------------------------------------------------------------------
# select_action
# ---------------------------------------------------------------------------

class TestSelectAction:
    def test_returns_action_without_executing(self):
        r = _result(action=PolicyAction.BLOCK, reason="bad")
        # Should not raise — just returns the action
        assert select_action(r) == PolicyAction.BLOCK

    def test_risk_elevation(self):
        r = _result(action=PolicyAction.ALERT, risk_score=70.0)
        config = AlterKSConfig(risk_threshold=60.0)
        assert select_action(r, config) == PolicyAction.BLOCK


# ---------------------------------------------------------------------------
# JSON report writing
# ---------------------------------------------------------------------------

class TestWriteJsonReport:
    def test_creates_report_file(self, tmp_path: Path):
        ar = ActionResult(
            action=PolicyAction.ALERT,
            package="pkg",
            version="1.0",
            reason="test",
        )
        path = tmp_path / "subdir" / "report.jsonl"
        _write_json_report(ar, path)
        assert path.is_file()
        data = json.loads(path.read_text().strip())
        assert data["package"] == "pkg"
