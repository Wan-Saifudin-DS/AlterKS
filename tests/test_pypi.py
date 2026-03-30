"""Tests for the PyPI JSON API client."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import respx

from alterks.sources.pypi import (
    DEFAULT_CACHE_TTL,
    PyPIClient,
    PyPIError,
    PyPIMetadata,
    ReleaseInfo,
    _compute_hmac,
    _earliest_upload,
    _get_hmac_key,
    _parse_datetime,
    _parse_metadata,
    _verify_hmac,
)

# ---------------------------------------------------------------------------
# Minimal PyPI JSON fixture
# ---------------------------------------------------------------------------

SAMPLE_PYPI_RESPONSE = {
    "info": {
        "name": "requests",
        "version": "2.31.0",
        "summary": "Python HTTP for Humans.",
        "description": "# Requests\n\nA long description that is over 50 chars for sure...",
        "author": "Kenneth Reitz",
        "author_email": "me@kennethreitz.org",
        "maintainer": "Seth Michael Larson",
        "maintainer_email": "sethmichaellarson@gmail.com",
        "home_page": "https://requests.readthedocs.io",
        "project_urls": {
            "Homepage": "https://requests.readthedocs.io",
            "Source": "https://github.com/psf/requests",
        },
        "classifiers": [
            "Development Status :: 5 - Production/Stable",
            "License :: OSI Approved :: Apache Software License",
        ],
    },
    "releases": {
        "2.30.0": [
            {
                "upload_time_iso_8601": "2023-05-03T14:00:00Z",
                "yanked": False,
            }
        ],
        "2.31.0": [
            {
                "upload_time_iso_8601": "2023-06-15T10:00:00Z",
                "yanked": False,
            }
        ],
    },
}

MINIMAL_PYPI_RESPONSE = {
    "info": {
        "name": "sketchy-pkg",
        "version": "0.0.1",
        "summary": "",
        "description": "",
        "author": "",
        "author_email": "",
        "maintainer": "",
        "maintainer_email": "",
        "home_page": "",
        "project_urls": None,
        "classifiers": [],
    },
    "releases": {
        "0.0.1": [
            {
                "upload_time_iso_8601": "2026-03-28T10:00:00Z",
                "yanked": False,
            }
        ],
    },
}


# ---------------------------------------------------------------------------
# _parse_metadata
# ---------------------------------------------------------------------------

class TestParseMetadata:
    def test_parses_full_response(self):
        meta = _parse_metadata(SAMPLE_PYPI_RESPONSE)
        assert meta.name == "requests"
        assert meta.version == "2.31.0"
        assert meta.summary == "Python HTTP for Humans."
        assert meta.author == "Kenneth Reitz"
        assert meta.maintainer == "Seth Michael Larson"
        assert len(meta.releases) == 2
        assert meta.has_homepage is True
        assert meta.has_description is True
        assert len(meta.classifiers) == 2

    def test_upload_times(self):
        meta = _parse_metadata(SAMPLE_PYPI_RESPONSE)
        assert meta.first_upload == datetime(2023, 5, 3, 14, 0, tzinfo=timezone.utc)
        assert meta.latest_upload == datetime(2023, 6, 15, 10, 0, tzinfo=timezone.utc)

    def test_minimal_metadata(self):
        meta = _parse_metadata(MINIMAL_PYPI_RESPONSE)
        assert meta.name == "sketchy-pkg"
        assert meta.has_homepage is False
        assert meta.has_description is False
        assert meta.classifiers == []
        assert meta.release_count == 1

    def test_empty_response(self):
        meta = _parse_metadata({})
        assert meta.name == ""
        assert meta.releases == []
        assert meta.first_upload is None

    def test_releases_sorted_by_upload_time(self):
        meta = _parse_metadata(SAMPLE_PYPI_RESPONSE)
        times = [r.upload_time for r in meta.releases if r.upload_time]
        assert times == sorted(times)


class TestPyPIMetadataProperties:
    def test_age_days(self):
        meta = _parse_metadata(MINIMAL_PYPI_RESPONSE)
        age = meta.age_days
        assert age is not None
        # Package uploaded 2026-03-28, test date is 2026-03-30
        assert age >= 0

    def test_age_days_no_upload(self):
        meta = _parse_metadata({})
        assert meta.age_days is None

    def test_maintainer_count_multiple(self):
        meta = _parse_metadata(SAMPLE_PYPI_RESPONSE)
        assert meta.maintainer_count >= 2  # author + maintainer (different people)

    def test_maintainer_count_single(self):
        meta = _parse_metadata(MINIMAL_PYPI_RESPONSE)
        assert meta.maintainer_count == 1

    def test_has_homepage_via_project_urls(self):
        raw = {
            "info": {
                "name": "x",
                "version": "1.0",
                "home_page": "",
                "project_urls": {"Source": "https://github.com/x/x"},
            },
            "releases": {},
        }
        meta = _parse_metadata(raw)
        assert meta.has_homepage is True

    def test_release_count(self):
        meta = _parse_metadata(SAMPLE_PYPI_RESPONSE)
        assert meta.release_count == 2


# ---------------------------------------------------------------------------
# _parse_datetime / _earliest_upload
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_parse_datetime_z(self):
        dt = _parse_datetime("2023-06-15T10:00:00Z")
        assert dt == datetime(2023, 6, 15, 10, 0, tzinfo=timezone.utc)

    def test_parse_datetime_offset(self):
        dt = _parse_datetime("2023-06-15T10:00:00+00:00")
        assert dt is not None

    def test_parse_datetime_invalid(self):
        assert _parse_datetime("not-a-date") is None

    def test_earliest_upload(self):
        files = [
            {"upload_time_iso_8601": "2023-06-15T10:00:00Z"},
            {"upload_time_iso_8601": "2023-06-01T08:00:00Z"},
        ]
        dt = _earliest_upload(files)
        assert dt == datetime(2023, 6, 1, 8, 0, tzinfo=timezone.utc)

    def test_earliest_upload_empty(self):
        assert _earliest_upload([]) is None


# ---------------------------------------------------------------------------
# PyPIClient HTTP
# ---------------------------------------------------------------------------

class TestPyPIClient:
    @respx.mock
    def test_get_metadata_success(self):
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=SAMPLE_PYPI_RESPONSE)
        )
        client = PyPIClient(cache_dir=None)
        meta = client.get_metadata("requests")
        assert meta.name == "requests"

    @respx.mock
    def test_404_raises(self):
        respx.get("https://pypi.org/pypi/nonexistent/json").mock(
            return_value=httpx.Response(404)
        )
        client = PyPIClient(cache_dir=None)
        with pytest.raises(PyPIError, match="not found"):
            client.get_metadata("nonexistent")

    @respx.mock
    def test_server_error_raises(self):
        respx.get("https://pypi.org/pypi/broken/json").mock(
            return_value=httpx.Response(500)
        )
        client = PyPIClient(cache_dir=None)
        with pytest.raises(PyPIError, match="500"):
            client.get_metadata("broken")

    @respx.mock
    def test_timeout_raises(self):
        respx.get("https://pypi.org/pypi/slow/json").mock(
            side_effect=httpx.ReadTimeout("timeout")
        )
        client = PyPIClient(cache_dir=None)
        with pytest.raises(PyPIError, match="Timeout"):
            client.get_metadata("slow")


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

class TestPyPICache:
    @respx.mock
    def test_caches_response(self, tmp_path: Path):
        route = respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=SAMPLE_PYPI_RESPONSE)
        )
        client = PyPIClient(cache_dir=tmp_path, cache_ttl=3600)

        meta1 = client.get_metadata("requests")
        meta2 = client.get_metadata("requests")

        assert meta1.name == meta2.name
        assert route.call_count == 1  # Second call served from cache

    @respx.mock
    def test_expired_cache_refetches(self, tmp_path: Path):
        route = respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=SAMPLE_PYPI_RESPONSE)
        )
        client = PyPIClient(cache_dir=tmp_path, cache_ttl=0)  # TTL=0 → always expired

        client.get_metadata("requests")
        client.get_metadata("requests")

        assert route.call_count == 2

    def test_no_cache_dir(self):
        client = PyPIClient(cache_dir=None)
        assert client._cache_path("requests") is None

    def test_cache_path_is_safe(self, tmp_path: Path):
        client = PyPIClient(cache_dir=tmp_path)
        path = client._cache_path("requests")
        assert path is not None
        assert "requests" in path.name


# ---------------------------------------------------------------------------
# Cache integrity (HMAC)
# ---------------------------------------------------------------------------

class TestCacheIntegrity:
    def test_hmac_key_created_on_first_use(self, tmp_path: Path):
        key = _get_hmac_key(tmp_path)
        assert len(key) == 32
        assert (tmp_path / ".hmac_key").is_file()

    def test_hmac_key_reused_on_subsequent_calls(self, tmp_path: Path):
        key1 = _get_hmac_key(tmp_path)
        key2 = _get_hmac_key(tmp_path)
        assert key1 == key2

    def test_hmac_key_regenerated_if_corrupted(self, tmp_path: Path):
        key_file = tmp_path / ".hmac_key"
        key_file.write_bytes(b"short")  # Wrong length
        key = _get_hmac_key(tmp_path)
        assert len(key) == 32
        assert key != b"short"

    def test_compute_and_verify_hmac(self):
        key = b"x" * 32
        payload = '{"name": "test"}'
        digest = _compute_hmac(payload, key)
        assert _verify_hmac(payload, digest, key) is True

    def test_verify_hmac_rejects_tampered_payload(self):
        key = b"x" * 32
        payload = '{"name": "test"}'
        digest = _compute_hmac(payload, key)
        assert _verify_hmac('{"name": "evil"}', digest, key) is False

    def test_verify_hmac_rejects_wrong_key(self):
        key1 = b"a" * 32
        key2 = b"b" * 32
        payload = '{"name": "test"}'
        digest = _compute_hmac(payload, key1)
        assert _verify_hmac(payload, digest, key2) is False

    @respx.mock
    def test_cached_entry_has_hmac(self, tmp_path: Path):
        respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=SAMPLE_PYPI_RESPONSE)
        )
        client = PyPIClient(cache_dir=tmp_path, cache_ttl=3600)
        client.get_metadata("requests")

        # Inspect the written cache file
        cache_files = list(tmp_path.glob("requests_*.json"))
        assert len(cache_files) == 1
        cached = json.loads(cache_files[0].read_text(encoding="utf-8"))
        assert "_hmac" in cached
        assert isinstance(cached["_hmac"], str)
        assert len(cached["_hmac"]) == 64  # SHA-256 hex

    @respx.mock
    def test_tampered_cache_is_discarded(self, tmp_path: Path):
        route = respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=SAMPLE_PYPI_RESPONSE)
        )
        client = PyPIClient(cache_dir=tmp_path, cache_ttl=3600)
        client.get_metadata("requests")
        assert route.call_count == 1

        # Tamper with the cache file
        cache_files = list(tmp_path.glob("requests_*.json"))
        cached = json.loads(cache_files[0].read_text(encoding="utf-8"))
        cached["info"]["name"] = "evil-override"
        cache_files[0].write_text(json.dumps(cached), encoding="utf-8")

        # Next read should detect tampering and refetch
        client.get_metadata("requests")
        assert route.call_count == 2

    @respx.mock
    def test_cache_without_hmac_is_discarded(self, tmp_path: Path):
        route = respx.get("https://pypi.org/pypi/requests/json").mock(
            return_value=httpx.Response(200, json=SAMPLE_PYPI_RESPONSE)
        )
        client = PyPIClient(cache_dir=tmp_path, cache_ttl=3600)

        # Write a cache file without HMAC (old format)
        import time as _time
        cache_path = client._cache_path("requests")
        old_format = dict(SAMPLE_PYPI_RESPONSE)
        old_format["_cached_at"] = _time.time()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(old_format), encoding="utf-8")

        # Should discard the old-format cache and refetch
        client.get_metadata("requests")
        assert route.call_count == 1
