"""Tests for the pip hook module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from alterks.models import PolicyAction, ScanResult, Vulnerability, Severity
from alterks.pip_hook import _parse_spec, generate_constraints, resolve_and_scan


# ---------------------------------------------------------------------------
# _parse_spec
# ---------------------------------------------------------------------------

class TestParseSpec:
    def test_pinned(self):
        name, version = _parse_spec("requests==2.31.0")
        assert name == "requests"
        assert version == "2.31.0"

    def test_unpinned_gte(self):
        name, version = _parse_spec("requests>=2.0")
        assert name == "requests"
        assert version is None

    def test_unpinned_tilde(self):
        name, version = _parse_spec("requests~=2.0")
        assert name == "requests"
        assert version is None

    def test_bare_name(self):
        name, version = _parse_spec("requests")
        assert name == "requests"
        assert version is None

    def test_whitespace(self):
        name, version = _parse_spec("  flask == 2.3.3  ")
        assert name == "flask"
        assert version == "2.3.3"

    # --- Injection prevention tests (fix #10) ---

    def test_rejects_flag_injection_in_version(self):
        """Version portion cannot contain pip flags."""
        with pytest.raises(ValueError):
            _parse_spec("pkg==1.0 --index-url=https://evil.com/simple")

    def test_rejects_flag_injection_in_name(self):
        """Name portion cannot look like a pip flag."""
        with pytest.raises(ValueError):
            _parse_spec("--index-url=https://evil.com/simple")

    def test_rejects_flag_as_version(self):
        """Version like '--pre' should be caught by packaging validation."""
        with pytest.raises(ValueError):
            _parse_spec("pkg==--pre")

    def test_rejects_semicolon_injection(self):
        """Shell command injection via semicolons should be rejected."""
        with pytest.raises(ValueError):
            _parse_spec("pkg==1.0; rm -rf /")

    def test_rejects_empty_spec(self):
        with pytest.raises(ValueError, match="Empty"):
            _parse_spec("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValueError, match="Empty"):
            _parse_spec("   ")

    def test_complex_pinned_version(self):
        """Pre-release and post-release tags are valid."""
        name, version = _parse_spec("django==4.2.1rc1")
        assert name == "django"
        assert version == "4.2.1rc1"

    def test_multiple_specifiers_returns_pinned(self):
        """When == is among multiple specifiers, it's extracted."""
        name, version = _parse_spec("requests>=2.0,==2.31.0")
        assert name == "requests"
        assert version == "2.31.0"

    def test_not_equal_returns_none(self):
        """!= specifier does not set a pinned version."""
        name, version = _parse_spec("requests!=2.30.0")
        assert name == "requests"
        assert version is None


# ---------------------------------------------------------------------------
# resolve_and_scan
# ---------------------------------------------------------------------------

class TestResolveAndScan:
    @patch("alterks.pip_hook.Scanner")
    @patch("alterks.pip_hook.PyPIClient")
    def test_resolves_latest_version(self, mock_pypi_cls, mock_scanner_cls):
        mock_meta = MagicMock()
        mock_meta.version = "2.31.0"
        mock_pypi = MagicMock()
        mock_pypi.get_metadata.return_value = mock_meta
        mock_pypi_cls.return_value = mock_pypi

        scan_result = ScanResult(name="requests", version="2.31.0", action=PolicyAction.ALLOW)
        mock_scanner = MagicMock()
        mock_scanner.scan_package.return_value = scan_result
        mock_scanner_cls.return_value = mock_scanner

        result = resolve_and_scan("requests")

        assert result is not None
        assert result.name == "requests"
        assert result.version == "2.31.0"
        mock_pypi.get_metadata.assert_called_once_with("requests")
        mock_scanner.scan_package.assert_called_once_with("requests", "2.31.0")

    @patch("alterks.pip_hook.Scanner")
    @patch("alterks.pip_hook.PyPIClient")
    def test_uses_pinned_version(self, mock_pypi_cls, mock_scanner_cls):
        mock_meta = MagicMock()
        mock_meta.version = "2.31.0"
        mock_pypi = MagicMock()
        mock_pypi.get_metadata.return_value = mock_meta
        mock_pypi_cls.return_value = mock_pypi

        scan_result = ScanResult(name="requests", version="2.30.0", action=PolicyAction.ALLOW)
        mock_scanner = MagicMock()
        mock_scanner.scan_package.return_value = scan_result
        mock_scanner_cls.return_value = mock_scanner

        result = resolve_and_scan("requests==2.30.0")

        assert result is not None
        # Should use pinned version, not latest
        mock_scanner.scan_package.assert_called_once_with("requests", "2.30.0")

    @patch("alterks.pip_hook.PyPIClient")
    def test_pypi_error_returns_none(self, mock_pypi_cls):
        from alterks.sources.pypi import PyPIError
        mock_pypi = MagicMock()
        mock_pypi.get_metadata.side_effect = PyPIError("not found")
        mock_pypi_cls.return_value = mock_pypi

        result = resolve_and_scan("nonexistent-xyz")

        assert result is None

    @patch("alterks.pip_hook.Scanner")
    @patch("alterks.pip_hook.PyPIClient")
    def test_heuristic_failure_still_returns(self, mock_pypi_cls, mock_scanner_cls):
        mock_meta = MagicMock()
        mock_meta.version = "1.0"
        mock_pypi = MagicMock()
        mock_pypi.get_metadata.return_value = mock_meta
        mock_pypi_cls.return_value = mock_pypi

        scan_result = ScanResult(name="pkg", version="1.0", action=PolicyAction.ALLOW)
        mock_scanner = MagicMock()
        mock_scanner.scan_package.return_value = scan_result
        mock_scanner_cls.return_value = mock_scanner

        result = resolve_and_scan("pkg")

        # Heuristics now run inside Scanner; result should still be returned
        assert result is not None


# ---------------------------------------------------------------------------
# generate_constraints
# ---------------------------------------------------------------------------

class TestGenerateConstraints:
    @patch("alterks.pip_hook.Scanner")
    def test_generates_constraints(self, mock_scanner_cls):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = [
            ScanResult(name="evil", version="0.1", action=PolicyAction.BLOCK, reason="bad"),
            ScanResult(name="suspect", version="1.0", action=PolicyAction.QUARANTINE, reason="risky"),
            ScanResult(name="ok", version="2.0", action=PolicyAction.ALLOW, reason="clean"),
            ScanResult(name="warn", version="3.0", action=PolicyAction.ALERT, reason="medium"),
        ]
        mock_scanner_cls.return_value = mock_scanner

        text = generate_constraints()

        assert "evil!=0.1" in text
        assert "suspect!=1.0" in text
        assert "ok" not in text
        assert "warn" not in text
        assert "# AlterKS auto-generated" in text

    @patch("alterks.pip_hook.Scanner")
    def test_empty_environment(self, mock_scanner_cls):
        mock_scanner = MagicMock()
        mock_scanner.scan_environment.return_value = []
        mock_scanner_cls.return_value = mock_scanner

        text = generate_constraints()

        assert "# AlterKS auto-generated" in text
