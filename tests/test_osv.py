"""Tests for the OSV.dev API client (alterks.sources.osv)."""

from __future__ import annotations

import httpx
import pytest
import respx

from alterks.models import Severity, Vulnerability
from alterks.sources.osv import (
    OSV_BATCH_URL,
    OSV_QUERY_URL,
    OSVClient,
    OSVError,
    _extract_fix_versions,
    _extract_severity,
    _parse_vulnerability,
)
from tests.conftest import (
    BATCH_PAGE2_RESPONSE,
    BATCH_PAGINATED_RESPONSE,
    BATCH_RESPONSE,
    EMPTY_RESPONSE,
    FLASK_VULN_RESPONSE,
    NO_VULN_RESPONSE,
    SINGLE_PAGINATED_RESPONSE_PAGE1,
    SINGLE_PAGINATED_RESPONSE_PAGE2,
)


# ---------------------------------------------------------------------------
# Parsing tests (no network calls)
# ---------------------------------------------------------------------------

class TestParseVulnerability:
    def test_basic_fields(self):
        raw = FLASK_VULN_RESPONSE["vulns"][0]
        v = _parse_vulnerability(raw)
        assert v.id == "PYSEC-2019-179"
        assert "memory usage" in v.summary
        assert v.severity == Severity.HIGH
        assert "1.0" in v.fix_versions
        assert "CVE-2019-1010083" in v.aliases
        assert v.has_fix is True
        assert v.published is not None

    def test_database_specific_severity(self):
        raw = FLASK_VULN_RESPONSE["vulns"][1]
        v = _parse_vulnerability(raw)
        assert v.id == "PYSEC-2018-66"
        assert v.severity == Severity.HIGH
        assert "0.12.3" in v.fix_versions

    def test_empty_vuln(self):
        v = _parse_vulnerability({"id": "TEST-001"})
        assert v.id == "TEST-001"
        assert v.summary == ""
        assert v.severity == Severity.UNKNOWN
        assert v.fix_versions == []
        assert v.has_fix is False

    def test_unknown_id(self):
        v = _parse_vulnerability({})
        assert v.id == "UNKNOWN"


class TestExtractSeverity:
    def test_cvss_critical(self):
        assert _extract_severity({"severity": [{"score": "9.5"}]}) == Severity.CRITICAL

    def test_cvss_high(self):
        assert _extract_severity({"severity": [{"score": "7.5"}]}) == Severity.HIGH

    def test_cvss_medium(self):
        assert _extract_severity({"severity": [{"score": "5.0"}]}) == Severity.MEDIUM

    def test_cvss_low(self):
        assert _extract_severity({"severity": [{"score": "2.0"}]}) == Severity.LOW

    def test_database_specific(self):
        raw = {"database_specific": {"severity": "CRITICAL"}}
        assert _extract_severity(raw) == Severity.CRITICAL

    def test_ecosystem_specific(self):
        raw = {"affected": [{"ecosystem_specific": {"severity": "MEDIUM"}}]}
        assert _extract_severity(raw) == Severity.MEDIUM

    def test_no_severity(self):
        assert _extract_severity({}) == Severity.UNKNOWN


class TestExtractFixVersions:
    def test_single_fix(self):
        raw = {
            "affected": [
                {
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "1.0"}]}
                    ]
                }
            ]
        }
        assert _extract_fix_versions(raw) == ["1.0"]

    def test_multiple_fixes(self):
        raw = {
            "affected": [
                {
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "1.0"}]},
                        {"events": [{"introduced": "0"}, {"fixed": "0.12.3"}]},
                    ]
                }
            ]
        }
        fixes = _extract_fix_versions(raw)
        assert "1.0" in fixes
        assert "0.12.3" in fixes

    def test_no_fix(self):
        raw = {"affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}]}
        assert _extract_fix_versions(raw) == []

    def test_dedup(self):
        raw = {
            "affected": [
                {"ranges": [{"events": [{"fixed": "1.0"}]}]},
                {"ranges": [{"events": [{"fixed": "1.0"}]}]},
            ]
        }
        assert _extract_fix_versions(raw) == ["1.0"]


# ---------------------------------------------------------------------------
# Client tests (mocked HTTP)
# ---------------------------------------------------------------------------

class TestOSVClientQueryPackage:
    @respx.mock
    def test_returns_vulnerabilities(self):
        respx.post(OSV_QUERY_URL).mock(
            return_value=httpx.Response(200, json=FLASK_VULN_RESPONSE)
        )
        client = OSVClient(timeout=5, max_retries=1)
        vulns = client.query_package("Flask", "0.5")

        assert len(vulns) == 2
        assert vulns[0].id == "PYSEC-2019-179"
        assert vulns[1].id == "PYSEC-2018-66"

    @respx.mock
    def test_no_vulnerabilities(self):
        respx.post(OSV_QUERY_URL).mock(
            return_value=httpx.Response(200, json=NO_VULN_RESPONSE)
        )
        client = OSVClient(timeout=5, max_retries=1)
        vulns = client.query_package("safe-package", "1.0.0")
        assert vulns == []

    @respx.mock
    def test_empty_response(self):
        respx.post(OSV_QUERY_URL).mock(
            return_value=httpx.Response(200, json=EMPTY_RESPONSE)
        )
        client = OSVClient(timeout=5, max_retries=1)
        vulns = client.query_package("unknown-package", "0.0.1")
        assert vulns == []

    @respx.mock
    def test_pagination(self):
        route = respx.post(OSV_QUERY_URL)
        route.side_effect = [
            httpx.Response(200, json=SINGLE_PAGINATED_RESPONSE_PAGE1),
            httpx.Response(200, json=SINGLE_PAGINATED_RESPONSE_PAGE2),
        ]
        client = OSVClient(timeout=5, max_retries=1)
        vulns = client.query_package("Flask", "0.5")

        assert len(vulns) == 2
        ids = {v.id for v in vulns}
        assert "PYSEC-2019-179" in ids
        assert "PYSEC-2018-66" in ids

    @respx.mock
    def test_bad_request_raises(self):
        respx.post(OSV_QUERY_URL).mock(
            return_value=httpx.Response(400, text="Bad Request")
        )
        client = OSVClient(timeout=5, max_retries=1)
        with pytest.raises(OSVError, match="bad request"):
            client.query_package("bad", "input")

    @respx.mock
    def test_server_error_retries_then_fails(self):
        respx.post(OSV_QUERY_URL).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        client = OSVClient(timeout=5, max_retries=2)
        with pytest.raises(OSVError, match="failed after 2 attempts"):
            client.query_package("Flask", "0.5")

    @respx.mock
    def test_timeout_retries_then_fails(self):
        respx.post(OSV_QUERY_URL).mock(side_effect=httpx.ConnectTimeout("timeout"))
        client = OSVClient(timeout=1, max_retries=2)
        with pytest.raises(OSVError, match="failed after 2 attempts"):
            client.query_package("Flask", "0.5")


class TestOSVClientQueryBatch:
    @respx.mock
    def test_batch_query(self):
        respx.post(OSV_BATCH_URL).mock(
            return_value=httpx.Response(200, json=BATCH_RESPONSE)
        )
        client = OSVClient(timeout=5, max_retries=1)
        packages = [("Flask", "0.5"), ("requests", "2.28.0")]
        results = client.query_batch(packages)

        assert len(results) == 2
        assert len(results[("Flask", "0.5")]) == 1
        assert results[("Flask", "0.5")][0].id == "PYSEC-2019-179"
        assert len(results[("requests", "2.28.0")]) == 0

    @respx.mock
    def test_batch_pagination(self):
        route = respx.post(OSV_BATCH_URL)
        route.side_effect = [
            httpx.Response(200, json=BATCH_PAGINATED_RESPONSE),
            httpx.Response(200, json=BATCH_PAGE2_RESPONSE),
        ]
        client = OSVClient(timeout=5, max_retries=1)
        packages = [("Flask", "0.5"), ("requests", "2.28.0")]
        results = client.query_batch(packages)

        # Flask should have both vulns (from page 1 + page 2)
        flask_vulns = results[("Flask", "0.5")]
        assert len(flask_vulns) == 2
        ids = {v.id for v in flask_vulns}
        assert "PYSEC-2019-179" in ids
        assert "PYSEC-2018-66" in ids

        # requests should have 0 vulns
        assert len(results[("requests", "2.28.0")]) == 0

    @respx.mock
    def test_empty_batch(self):
        client = OSVClient(timeout=5, max_retries=1)
        results = client.query_batch([])
        assert results == {}


# ---------------------------------------------------------------------------
# TLS verification enforcement
# ---------------------------------------------------------------------------

class TestTLSVerification:
    """Verify that httpx.AsyncClient is called with verify=True."""

    @respx.mock
    def test_async_client_uses_verify_true(self):
        respx.post(OSV_QUERY_URL).respond(200, json={"vulns": []})
        import unittest.mock as _m

        original_cls = httpx.AsyncClient

        captured = {}

        class SpyAsyncClient(original_cls):
            def __init__(self, **kwargs):
                captured.update(kwargs)
                super().__init__(**kwargs)

        with _m.patch("alterks.sources.osv.httpx.AsyncClient", SpyAsyncClient):
            client = OSVClient(timeout=5, max_retries=1)
            client.query_package("pkg", "1.0")

        assert captured.get("verify") is True
