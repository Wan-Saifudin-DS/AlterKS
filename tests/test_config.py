"""Tests for alterks.config — policy configuration loading and defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from alterks.config import (
    AlterKSConfig,
    DEFAULT_HEURISTIC_WEIGHTS,
    DEFAULT_RISK_THRESHOLD,
    DEFAULT_SEVERITY_ACTIONS,
    _build_config,
    _parse_severity_actions,
    _read_tool_section,
    load_config,
)
from alterks.models import PolicyAction, Severity, normalise_name


# ---------------------------------------------------------------------------
# AlterKSConfig defaults
# ---------------------------------------------------------------------------


class TestAlterKSConfigDefaults:
    def test_default_severity_actions(self):
        cfg = AlterKSConfig()
        assert cfg.action_for_severity(Severity.CRITICAL) == PolicyAction.BLOCK
        assert cfg.action_for_severity(Severity.HIGH) == PolicyAction.BLOCK
        assert cfg.action_for_severity(Severity.MEDIUM) == PolicyAction.ALERT
        assert cfg.action_for_severity(Severity.LOW) == PolicyAction.ALLOW
        assert cfg.action_for_severity(Severity.UNKNOWN) == PolicyAction.ALERT

    def test_default_risk_threshold(self):
        cfg = AlterKSConfig()
        assert cfg.risk_threshold == DEFAULT_RISK_THRESHOLD

    def test_default_heuristic_weights(self):
        cfg = AlterKSConfig()
        assert cfg.heuristic_weights == dict(DEFAULT_HEURISTIC_WEIGHTS)

    def test_default_lists_empty(self):
        cfg = AlterKSConfig()
        assert cfg.allowlist == []
        assert cfg.blocklist == []

    def test_default_fail_closed_is_false(self):
        cfg = AlterKSConfig()
        assert cfg.fail_closed is False


# ---------------------------------------------------------------------------
# AlterKSConfig query helpers
# ---------------------------------------------------------------------------


class TestAlterKSConfigHelpers:
    def test_is_allowed(self):
        cfg = AlterKSConfig(allowlist=["my-pkg"])
        assert cfg.is_allowed("my-pkg") is True
        assert cfg.is_allowed("My_Pkg") is True  # PEP 503 normalisation
        assert cfg.is_allowed("other") is False

    def test_is_blocked(self):
        cfg = AlterKSConfig(blocklist=["evil-pkg"])
        assert cfg.is_blocked("evil-pkg") is True
        assert cfg.is_blocked("Evil_Pkg") is True
        assert cfg.is_blocked("good") is False

    def test_exceeds_risk_threshold(self):
        cfg = AlterKSConfig(risk_threshold=50.0)
        assert cfg.exceeds_risk_threshold(50.0) is True
        assert cfg.exceeds_risk_threshold(60.0) is True
        assert cfg.exceeds_risk_threshold(49.9) is False

    def test_action_for_unknown_severity_defaults_alert(self):
        cfg = AlterKSConfig()
        assert cfg.action_for_severity(Severity.UNKNOWN) == PolicyAction.ALERT


# ---------------------------------------------------------------------------
# _parse_severity_actions
# ---------------------------------------------------------------------------


class TestParseSeverityActions:
    def test_standard_mapping(self):
        mapping = {"critical": "block", "high": "quarantine", "medium": "alert", "low": "allow"}
        result = _parse_severity_actions(mapping)
        assert result[Severity.CRITICAL] == PolicyAction.BLOCK
        assert result[Severity.HIGH] == PolicyAction.QUARANTINE
        assert result[Severity.MEDIUM] == PolicyAction.ALERT
        assert result[Severity.LOW] == PolicyAction.ALLOW

    def test_invalid_action_falls_back_to_allow(self):
        mapping = {"critical": "explode"}
        result = _parse_severity_actions(mapping)
        assert result[Severity.CRITICAL] == PolicyAction.ALLOW

    def test_case_insensitive(self):
        mapping = {"CRITICAL": "BLOCK"}
        result = _parse_severity_actions(mapping)
        assert result[Severity.CRITICAL] == PolicyAction.BLOCK

    def test_unknown_severity_can_be_overridden_to_block(self):
        mapping = {"unknown": "block"}
        result = _parse_severity_actions(mapping)
        assert result[Severity.UNKNOWN] == PolicyAction.BLOCK


# ---------------------------------------------------------------------------
# _build_config
# ---------------------------------------------------------------------------


class TestBuildConfig:
    def test_empty_raw_gives_defaults(self):
        cfg = _build_config({})
        assert cfg.risk_threshold == DEFAULT_RISK_THRESHOLD
        assert cfg.allowlist == []
        assert cfg.blocklist == []

    def test_overrides(self):
        raw = {
            "risk_threshold": 80,
            "allowlist": ["pkg-a", "pkg-b"],
            "blocklist": ["evil"],
            "severity_actions": {"critical": "alert"},
        }
        cfg = _build_config(raw)
        assert cfg.risk_threshold == 80.0
        assert cfg.allowlist == ["pkg-a", "pkg-b"]
        assert cfg.blocklist == ["evil"]
        assert cfg.action_for_severity(Severity.CRITICAL) == PolicyAction.ALERT

    def test_custom_heuristic_weights(self):
        raw = {
            "heuristic_weights": {
                "typosquatting": 0.50,
                "package_age": 0.50,
            }
        }
        cfg = _build_config(raw)
        assert cfg.heuristic_weights["typosquatting"] == 0.50
        assert cfg.heuristic_weights["package_age"] == 0.50

    def test_fail_closed_from_raw(self):
        cfg = _build_config({"fail_closed": True})
        assert cfg.fail_closed is True

    def test_fail_closed_default_false(self):
        cfg = _build_config({})
        assert cfg.fail_closed is False


# ---------------------------------------------------------------------------
# normalise_name
# ---------------------------------------------------------------------------


class TestNormalise:
    def test_lowercase(self):
        assert normalise_name("Flask") == "flask"

    def test_underscores_to_dashes(self):
        assert normalise_name("my_cool_package") == "my-cool-package"

    def test_dots_to_dashes(self):
        assert normalise_name("zope.interface") == "zope-interface"

    def test_mixed(self):
        assert normalise_name("My_Cool.Package") == "my-cool-package"


# ---------------------------------------------------------------------------
# _read_tool_section
# ---------------------------------------------------------------------------


class TestReadToolSection:
    def test_reads_alterks_section(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[tool.alterks]\n'
            'risk_threshold = 42\n'
            'allowlist = ["safe-pkg"]\n',
            encoding="utf-8",
        )
        data = _read_tool_section(toml)
        assert data["risk_threshold"] == 42
        assert data["allowlist"] == ["safe-pkg"]

    def test_missing_section_returns_empty(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text("[project]\nname = 'test'\n", encoding="utf-8")
        data = _read_tool_section(toml)
        assert data == {}

    def test_empty_file(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text("", encoding="utf-8")
        data = _read_tool_section(toml)
        assert data == {}


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_load_from_explicit_path(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[tool.alterks]\n'
            'risk_threshold = 99\n'
            'blocklist = ["bad-pkg"]\n',
            encoding="utf-8",
        )
        cfg = load_config(pyproject_path=toml)
        assert cfg.risk_threshold == 99.0
        assert cfg.blocklist == ["bad-pkg"]

    def test_load_with_overrides(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[tool.alterks]\n'
            'risk_threshold = 50\n',
            encoding="utf-8",
        )
        cfg = load_config(pyproject_path=toml, overrides={"risk_threshold": 75})
        assert cfg.risk_threshold == 75.0

    def test_load_no_file_gives_defaults(self, tmp_path, monkeypatch):
        # Change to a directory with no pyproject.toml
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert cfg.risk_threshold == DEFAULT_RISK_THRESHOLD

    def test_load_with_severity_actions(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[tool.alterks]\n'
            'severity_actions = { critical = "alert", high = "allow" }\n',
            encoding="utf-8",
        )
        cfg = load_config(pyproject_path=toml)
        assert cfg.action_for_severity(Severity.CRITICAL) == PolicyAction.ALERT
        assert cfg.action_for_severity(Severity.HIGH) == PolicyAction.ALLOW

    def test_load_with_heuristic_weights(self, tmp_path):
        toml = tmp_path / "pyproject.toml"
        toml.write_text(
            '[tool.alterks.heuristic_weights]\n'
            'typosquatting = 0.80\n'
            'package_age = 0.20\n',
            encoding="utf-8",
        )
        cfg = load_config(pyproject_path=toml)
        assert cfg.heuristic_weights["typosquatting"] == 0.80
        assert cfg.heuristic_weights["package_age"] == 0.20
