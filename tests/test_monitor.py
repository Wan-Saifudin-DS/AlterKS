"""Tests for alterks.monitor — continuous monitoring daemon."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Set, Tuple
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from alterks.config import AlterKSConfig
from alterks.models import PolicyAction, ScanResult, Severity, Vulnerability
from alterks.monitor import (
    WebhookURLError,
    _build_report,
    _compute_webhook_signature,
    _issue_key,
    _result_to_dict,
    collect_keys,
    diff_issues,
    notify_json_file,
    notify_stderr,
    notify_webhook,
    run_monitor,
    validate_webhook_url,
)
from alterks.sources.osv import OSVError
from tests.helpers import make_scan_result, make_vulnerability


# ---------------------------------------------------------------------------
# Helpers — thin wrappers for backward compatibility
# ---------------------------------------------------------------------------

_make_result = make_scan_result
_make_vuln = make_vulnerability


# ---------------------------------------------------------------------------
# _result_to_dict
# ---------------------------------------------------------------------------

class TestResultToDict:
    def test_basic_serialization(self):
        v = _make_vuln("CVE-2024-001", "Bad thing")
        r = _make_result("requests", "2.31.0", PolicyAction.BLOCK, "vuln found", [v])
        d = _result_to_dict(r)

        assert d["name"] == "requests"
        assert d["version"] == "2.31.0"
        assert d["action"] == "block"
        assert d["vulnerability_count"] == 1
        assert d["vulnerabilities"][0]["id"] == "CVE-2024-001"
        assert d["vulnerabilities"][0]["severity"] == "high"

    def test_no_vulns(self):
        r = _make_result("safe", "1.0.0")
        d = _result_to_dict(r)
        assert d["vulnerability_count"] == 0
        assert d["vulnerabilities"] == []


# ---------------------------------------------------------------------------
# _build_report
# ---------------------------------------------------------------------------

class TestBuildReport:
    def test_report_structure(self):
        r1 = _make_result("bad", "1.0", PolicyAction.BLOCK, "blocked")
        r2 = _make_result("ok", "2.0")
        report = _build_report([r1, r2], [r1], "2026-03-30T00:00:00Z")

        assert report["timestamp"] == "2026-03-30T00:00:00Z"
        assert report["total_packages"] == 2
        assert report["total_issues"] == 1
        assert report["new_issues"] == 1
        assert len(report["issues"]) == 1
        assert len(report["new"]) == 1
        assert report["issues"][0]["name"] == "bad"

    def test_report_no_issues(self):
        r = _make_result("ok", "1.0")
        report = _build_report([r], [], "2026-03-30T00:00:00Z")
        assert report["total_issues"] == 0
        assert report["new_issues"] == 0


# ---------------------------------------------------------------------------
# Issue tracking: _issue_key / diff_issues / collect_keys
# ---------------------------------------------------------------------------

class TestIssueKey:
    def test_key_from_vuln(self):
        v = _make_vuln("CVE-2024-001")
        r = _make_result("requests", "2.31.0", PolicyAction.BLOCK, "vuln", [v])
        keys = _issue_key(r)
        assert ("requests", "2.31.0", "CVE-2024-001") in keys

    def test_key_from_risk_only(self):
        r = _make_result("shady", "0.1", PolicyAction.ALERT, "high risk")
        keys = _issue_key(r)
        assert ("shady", "0.1", "__risk__alert") in keys

    def test_key_from_allowed_is_empty(self):
        r = _make_result("safe", "1.0")
        keys = _issue_key(r)
        assert keys == set()

    def test_multiple_vulns_produce_multiple_keys(self):
        v1 = _make_vuln("CVE-001")
        v2 = _make_vuln("CVE-002")
        r = _make_result("pkg", "1.0", PolicyAction.BLOCK, "vuln", [v1, v2])
        keys = _issue_key(r)
        assert len(keys) == 2


class TestDiffIssues:
    def test_all_new(self):
        r = _make_result("bad", "1.0", PolicyAction.BLOCK, "vuln", [_make_vuln("CVE-001")])
        new = diff_issues([r], set())
        assert len(new) == 1
        assert new[0].name == "bad"

    def test_known_issue_not_new(self):
        r = _make_result("bad", "1.0", PolicyAction.BLOCK, "vuln", [_make_vuln("CVE-001")])
        previous = {("bad", "1.0", "CVE-001")}
        new = diff_issues([r], previous)
        assert new == []

    def test_mixed_new_and_known(self):
        v1 = _make_vuln("CVE-001")
        v2 = _make_vuln("CVE-002")
        r = _make_result("pkg", "1.0", PolicyAction.BLOCK, "vuln", [v1, v2])
        previous = {("pkg", "1.0", "CVE-001")}
        new = diff_issues([r], previous)
        # CVE-002 is new, so the result appears
        assert len(new) == 1

    def test_allowed_packages_excluded(self):
        r = _make_result("ok", "1.0")
        new = diff_issues([r], set())
        assert new == []


class TestCollectKeys:
    def test_collects_all_keys(self):
        v = _make_vuln("CVE-001")
        r1 = _make_result("pkg1", "1.0", PolicyAction.BLOCK, "vuln", [v])
        r2 = _make_result("pkg2", "2.0", PolicyAction.ALERT, "risky")
        r3 = _make_result("ok", "3.0")

        keys = collect_keys([r1, r2, r3])
        assert ("pkg1", "1.0", "CVE-001") in keys
        assert ("pkg2", "2.0", "__risk__alert") in keys
        # ALLOW produces no key
        assert len(keys) == 2


# ---------------------------------------------------------------------------
# Notification channels
# ---------------------------------------------------------------------------

class TestNotifyJsonFile:
    def test_writes_jsonlines(self, tmp_path):
        output = tmp_path / "reports.jsonl"
        report1 = {"timestamp": "t1", "issues": []}
        report2 = {"timestamp": "t2", "issues": [{"name": "bad"}]}

        notify_json_file(report1, output)
        notify_json_file(report2, output)

        lines = output.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["timestamp"] == "t1"
        assert json.loads(lines[1])["timestamp"] == "t2"

    def test_creates_parent_dirs(self, tmp_path):
        output = tmp_path / "subdir" / "deep" / "report.jsonl"
        notify_json_file({"test": True}, output)
        assert output.exists()


class TestNotifyStderr:
    def test_clean_output(self):
        console = Console(file=None, stderr=True, force_terminal=False)
        r = _make_result("ok", "1.0")
        # Should not raise
        notify_stderr([r], [], console)

    def test_issues_output(self):
        console = Console(file=None, stderr=True, force_terminal=False)
        r = _make_result("bad", "1.0", PolicyAction.BLOCK, "vuln found")
        notify_stderr([r], [r], console)


class TestNotifyWebhook:
    @patch("alterks.monitor.httpx.post")
    def test_successful_post(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_post.return_value = mock_resp

        result = notify_webhook({"test": True}, "https://example.com/hook")

        assert result is True
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        body = json.loads(call_kwargs.kwargs["content"])
        assert body == {"test": True}

    @patch("alterks.monitor.httpx.post")
    def test_failed_post(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.is_success = False
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"
        mock_post.return_value = mock_resp

        result = notify_webhook({"test": True}, "https://example.com/hook")
        assert result is False

    @patch("alterks.monitor.httpx.post")
    def test_http_error(self, mock_post):
        import httpx
        mock_post.side_effect = httpx.ConnectError("Connection refused")

        result = notify_webhook({"test": True}, "https://example.com/hook")
        assert result is False

    @patch("alterks.monitor.httpx.post")
    def test_hmac_signature_sent_with_secret(self, mock_post):
        """When webhook_secret is provided, X-AlterKS-Signature header is set."""
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_post.return_value = mock_resp

        result = notify_webhook(
            {"data": "value"},
            "https://example.com/hook",
            webhook_secret="my-secret-key",
        )

        assert result is True
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs["headers"]
        assert "X-AlterKS-Signature" in headers
        sig = headers["X-AlterKS-Signature"]
        assert sig.startswith("sha256=")
        # Verify the signature matches the body
        body_bytes = call_kwargs.kwargs["content"]
        expected = _compute_webhook_signature(body_bytes, "my-secret-key")
        assert sig == expected

    @patch("alterks.monitor.httpx.post")
    def test_no_signature_without_secret(self, mock_post):
        """Without webhook_secret, no signature header is sent."""
        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_post.return_value = mock_resp

        notify_webhook({"data": "value"}, "https://example.com/hook")

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs["headers"]
        assert "X-AlterKS-Signature" not in headers

    @patch("alterks.monitor.httpx.post")
    def test_http_localhost_warns(self, mock_post, caplog):
        """HTTP localhost should succeed but log a warning about plain HTTP."""
        import logging

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_post.return_value = mock_resp

        with caplog.at_level(logging.WARNING, logger="alterks.monitor"):
            notify_webhook({"x": 1}, "http://localhost:8080/hook")

        assert any("plain HTTP" in msg for msg in caplog.messages)

    @patch("alterks.monitor.httpx.post")
    def test_no_secret_warns(self, mock_post, caplog):
        """When no secret is configured, a warning is logged."""
        import logging

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_post.return_value = mock_resp

        with caplog.at_level(logging.WARNING, logger="alterks.monitor"):
            notify_webhook({"x": 1}, "https://example.com/hook")

        assert any("No webhook secret" in msg for msg in caplog.messages)

    @patch("alterks.monitor.httpx.post")
    def test_secret_suppresses_unsigned_warning(self, mock_post, caplog):
        """When a secret IS configured, the 'no secret' warning is absent."""
        import logging

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_post.return_value = mock_resp

        with caplog.at_level(logging.WARNING, logger="alterks.monitor"):
            notify_webhook(
                {"x": 1}, "https://example.com/hook",
                webhook_secret="s3cret",
            )

        assert not any("No webhook secret" in msg for msg in caplog.messages)


# ---------------------------------------------------------------------------
# _compute_webhook_signature
# ---------------------------------------------------------------------------

class TestComputeWebhookSignature:
    def test_deterministic(self):
        payload = b'{"hello":"world"}'
        sig1 = _compute_webhook_signature(payload, "key")
        sig2 = _compute_webhook_signature(payload, "key")
        assert sig1 == sig2
        assert sig1.startswith("sha256=")

    def test_different_keys_produce_different_signatures(self):
        payload = b'{"hello":"world"}'
        sig_a = _compute_webhook_signature(payload, "key-a")
        sig_b = _compute_webhook_signature(payload, "key-b")
        assert sig_a != sig_b

    def test_different_payloads_produce_different_signatures(self):
        sig1 = _compute_webhook_signature(b'{"a":1}', "key")
        sig2 = _compute_webhook_signature(b'{"a":2}', "key")
        assert sig1 != sig2

    def test_known_vector(self):
        """Verify against a hand-computed HMAC-SHA256 value."""
        import hashlib
        import hmac

        payload = b"test-body"
        secret = "test-secret"
        expected_hex = hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256,
        ).hexdigest()
        assert _compute_webhook_signature(payload, secret) == f"sha256={expected_hex}"


# ---------------------------------------------------------------------------
# validate_webhook_url — SSRF prevention
# ---------------------------------------------------------------------------

class TestValidateWebhookUrl:
    """Tests for webhook URL validation against SSRF attacks."""

    def test_https_allowed(self):
        assert validate_webhook_url("https://example.com/hook") == "https://example.com/hook"

    def test_http_localhost_allowed(self):
        assert validate_webhook_url("http://localhost:8080/hook") == "http://localhost:8080/hook"

    def test_http_127_allowed(self):
        assert validate_webhook_url("http://127.0.0.1:9000/hook") == "http://127.0.0.1:9000/hook"

    def test_http_public_rejected(self):
        with pytest.raises(WebhookURLError, match="insecure"):
            validate_webhook_url("http://example.com/hook")

    def test_file_scheme_rejected(self):
        with pytest.raises(WebhookURLError, match="not allowed"):
            validate_webhook_url("file:///etc/passwd")

    def test_ftp_scheme_rejected(self):
        with pytest.raises(WebhookURLError, match="not allowed"):
            validate_webhook_url("ftp://evil.com/data")

    def test_empty_scheme_rejected(self):
        with pytest.raises(WebhookURLError, match="not allowed"):
            validate_webhook_url("//example.com/hook")

    def test_private_ip_10_rejected(self):
        with pytest.raises(WebhookURLError, match="private"):
            validate_webhook_url("https://10.0.0.1/hook")

    def test_private_ip_172_rejected(self):
        with pytest.raises(WebhookURLError, match="private"):
            validate_webhook_url("https://172.16.0.1/hook")

    def test_private_ip_192_rejected(self):
        with pytest.raises(WebhookURLError, match="private"):
            validate_webhook_url("https://192.168.1.1/hook")

    def test_link_local_rejected(self):
        with pytest.raises(WebhookURLError, match="private"):
            validate_webhook_url("https://169.254.1.1/hook")

    def test_aws_metadata_rejected(self):
        with pytest.raises(WebhookURLError, match="metadata"):
            validate_webhook_url("https://169.254.169.254/latest/meta-data/")

    def test_gcp_metadata_rejected(self):
        with pytest.raises(WebhookURLError, match="metadata"):
            validate_webhook_url("https://metadata.google.internal/")

    def test_no_hostname_rejected(self):
        with pytest.raises(WebhookURLError, match="no hostname"):
            validate_webhook_url("https:///path")

    def test_notify_webhook_rejects_bad_url(self):
        """notify_webhook returns False (no exception) for invalid URLs."""
        result = notify_webhook({"test": True}, "http://10.0.0.1/hook")
        assert result is False


class TestRunMonitorWebhookValidation:
    """run_monitor should exit early if webhook URL is invalid."""

    def test_invalid_webhook_exits_immediately(self):
        console = Console(file=MagicMock(), stderr=False, no_color=True)
        # Should return immediately without scanning
        run_monitor(
            once=True,
            console=console,
            webhook_url="http://192.168.1.1/hook",
        )
        # If we get here without error, the function returned early (good)


# ---------------------------------------------------------------------------
# run_monitor — integration
# ---------------------------------------------------------------------------

class TestRunMonitor:
    def _make_scanner(self, results: List[ScanResult]) -> MagicMock:
        scanner = MagicMock()
        scanner.scan_environment.return_value = results
        return scanner

    def test_once_clean(self):
        scanner = self._make_scanner([_make_result("ok", "1.0")])
        console = Console(file=None, stderr=True, force_terminal=False)

        run_monitor(
            config=AlterKSConfig(),
            once=True,
            console=console,
            scanner=scanner,
        )

        scanner.scan_environment.assert_called_once()

    def test_once_with_issues(self):
        v = _make_vuln("CVE-001")
        scanner = self._make_scanner([
            _make_result("bad", "1.0", PolicyAction.BLOCK, "vuln", [v]),
            _make_result("ok", "2.0"),
        ])
        console = Console(file=None, stderr=True, force_terminal=False)

        run_monitor(
            config=AlterKSConfig(),
            once=True,
            console=console,
            scanner=scanner,
        )

        scanner.scan_environment.assert_called_once()

    def test_json_output_file(self, tmp_path):
        v = _make_vuln("CVE-001")
        scanner = self._make_scanner([
            _make_result("bad", "1.0", PolicyAction.BLOCK, "vuln", [v]),
        ])
        console = Console(file=None, stderr=True, force_terminal=False)
        output = tmp_path / "report.jsonl"

        run_monitor(
            config=AlterKSConfig(),
            once=True,
            console=console,
            scanner=scanner,
            json_output=output,
        )

        assert output.exists()
        data = json.loads(output.read_text(encoding="utf-8").strip())
        assert data["total_issues"] == 1

    @patch("alterks.monitor.notify_webhook")
    def test_webhook_called(self, mock_webhook):
        mock_webhook.return_value = True
        scanner = self._make_scanner([
            _make_result("bad", "1.0", PolicyAction.BLOCK, "vuln"),
        ])
        console = Console(file=None, stderr=True, force_terminal=False)

        run_monitor(
            config=AlterKSConfig(),
            once=True,
            console=console,
            scanner=scanner,
            webhook_url="https://example.com/hook",
        )

        mock_webhook.assert_called_once()
        report = mock_webhook.call_args.args[0]
        assert report["total_issues"] == 1

    @patch("alterks.monitor.notify_webhook")
    def test_webhook_secret_passed_from_cli(self, mock_webhook):
        """webhook_secret kwarg from CLI is forwarded to notify_webhook."""
        mock_webhook.return_value = True
        scanner = self._make_scanner([
            _make_result("bad", "1.0", PolicyAction.BLOCK, "vuln"),
        ])
        console = Console(file=None, stderr=True, force_terminal=False)

        run_monitor(
            config=AlterKSConfig(),
            once=True,
            console=console,
            scanner=scanner,
            webhook_url="https://example.com/hook",
            webhook_secret="cli-secret",
        )

        mock_webhook.assert_called_once()
        assert mock_webhook.call_args.kwargs["webhook_secret"] == "cli-secret"

    @patch("alterks.monitor.notify_webhook")
    def test_webhook_secret_from_config(self, mock_webhook):
        """webhook_secret from config is used when CLI doesn't provide one."""
        mock_webhook.return_value = True
        scanner = self._make_scanner([
            _make_result("bad", "1.0", PolicyAction.BLOCK, "vuln"),
        ])
        console = Console(file=None, stderr=True, force_terminal=False)

        run_monitor(
            config=AlterKSConfig(webhook_secret="config-secret"),
            once=True,
            console=console,
            scanner=scanner,
            webhook_url="https://example.com/hook",
        )

        mock_webhook.assert_called_once()
        assert mock_webhook.call_args.kwargs["webhook_secret"] == "config-secret"

    def test_loop_runs_twice_then_stops(self):
        """Verify the loop rescans after sleeping."""
        call_count = 0
        results_sequence = [
            [_make_result("ok", "1.0")],
            [_make_result("bad", "1.0", PolicyAction.BLOCK, "vuln", [_make_vuln("CVE-001")])],
        ]

        scanner = MagicMock()

        def side_effect():
            nonlocal call_count
            idx = min(call_count, len(results_sequence) - 1)
            call_count += 1
            return results_sequence[idx]

        scanner.scan_environment.side_effect = side_effect

        sleep_calls = []

        def fake_sleep(seconds):
            sleep_calls.append(seconds)
            if len(sleep_calls) >= 2:
                raise KeyboardInterrupt("stop the loop")

        console = Console(file=None, stderr=True, force_terminal=False)

        with pytest.raises(KeyboardInterrupt):
            run_monitor(
                config=AlterKSConfig(),
                interval=60,
                once=False,
                console=console,
                scanner=scanner,
                _sleep_fn=fake_sleep,
            )

        assert scanner.scan_environment.call_count >= 2
        assert sleep_calls[0] == 60

    def test_new_issues_detected_on_second_scan(self, tmp_path):
        """Verify that the second scan correctly identifies new issues."""
        v1 = _make_vuln("CVE-001")
        v2 = _make_vuln("CVE-002")
        results_sequence = [
            [_make_result("pkg", "1.0", PolicyAction.BLOCK, "vuln", [v1])],
            [_make_result("pkg", "1.0", PolicyAction.BLOCK, "vuln", [v1, v2])],
        ]

        call_count = 0
        scanner = MagicMock()

        def side_effect():
            nonlocal call_count
            idx = min(call_count, len(results_sequence) - 1)
            call_count += 1
            return results_sequence[idx]

        scanner.scan_environment.side_effect = side_effect

        output = tmp_path / "report.jsonl"
        sleep_calls = []

        def fake_sleep(seconds):
            sleep_calls.append(seconds)
            if len(sleep_calls) >= 2:
                raise KeyboardInterrupt("stop")

        console = Console(file=None, stderr=True, force_terminal=False)

        with pytest.raises(KeyboardInterrupt):
            run_monitor(
                config=AlterKSConfig(),
                interval=300,
                once=False,
                console=console,
                scanner=scanner,
                json_output=output,
                _sleep_fn=fake_sleep,
            )

        lines = output.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        # First scan: everything is new
        assert first["new_issues"] == 1
        # Second scan: CVE-002 is new
        assert second["new_issues"] == 1

    def test_scan_failure_continues(self):
        """Verify the loop survives a scan exception."""
        scanner = MagicMock()
        call_count = 0

        def side_effect():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OSVError("API down")
            return [_make_result("ok", "1.0")]

        scanner.scan_environment.side_effect = side_effect

        sleep_calls = []

        def fake_sleep(seconds):
            sleep_calls.append(seconds)
            if len(sleep_calls) >= 2:
                raise KeyboardInterrupt("stop")

        console = Console(file=None, stderr=True, force_terminal=False)

        with pytest.raises(KeyboardInterrupt):
            run_monitor(
                config=AlterKSConfig(),
                interval=10,
                once=False,
                console=console,
                scanner=scanner,
                _sleep_fn=fake_sleep,
            )

        assert scanner.scan_environment.call_count >= 2

    def test_scan_failure_once_mode_returns(self):
        """In once mode, a scan failure should return immediately."""
        scanner = MagicMock()
        scanner.scan_environment.side_effect = OSVError("API down")

        console = Console(file=None, stderr=True, force_terminal=False)

        # Should not raise
        run_monitor(
            config=AlterKSConfig(),
            once=True,
            console=console,
            scanner=scanner,
        )

        scanner.scan_environment.assert_called_once()
