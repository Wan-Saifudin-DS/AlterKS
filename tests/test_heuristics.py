"""Tests for the heuristic risk scorer."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx

from alterks.config import AlterKSConfig, DEFAULT_HEURISTIC_WEIGHTS
from alterks.heuristics import (
    TOP_PYPI_PACKAGES_URL,
    _levenshtein,
    _score_maintainer_count,
    _score_metadata_quality,
    _score_package_age,
    _score_release_pattern,
    _typosquat_score,
    compute_risk,
    refresh_top_packages,
)
from alterks.models import PackageRisk, RiskFactor
from alterks.sources.pypi import PyPIMetadata, ReleaseInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_meta(
    name: str = "testpkg",
    version: str = "1.0.0",
    first_upload: datetime | None = None,
    releases: list[ReleaseInfo] | None = None,
    author: str = "Alice",
    maintainer: str = "",
    author_email: str = "alice@example.com",
    maintainer_email: str = "",
    home_page: str = "https://example.com",
    project_urls: dict | None = None,
    description: str = "A" * 60,
    summary: str = "A test package",
    classifiers: list[str] | None = None,
) -> PyPIMetadata:
    if releases is None:
        releases = [ReleaseInfo(version="1.0.0", upload_time=first_upload)]
    return PyPIMetadata(
        name=name,
        version=version,
        summary=summary,
        description=description,
        author=author,
        author_email=author_email,
        maintainer=maintainer,
        maintainer_email=maintainer_email,
        home_page=home_page,
        project_urls=project_urls or {},
        classifiers=classifiers or ["License :: OSI Approved"],
        releases=releases,
        first_upload=first_upload,
        latest_upload=first_upload,
    )


# ---------------------------------------------------------------------------
# Levenshtein distance
# ---------------------------------------------------------------------------

class TestLevenshtein:
    def test_equal(self):
        assert _levenshtein("requests", "requests") == 0

    def test_one_edit(self):
        assert _levenshtein("requests", "requets") == 1

    def test_two_edits(self):
        assert _levenshtein("requests", "reqests") == 1  # single deletion

    def test_empty_strings(self):
        assert _levenshtein("", "") == 0
        assert _levenshtein("abc", "") == 3
        assert _levenshtein("", "abc") == 3

    def test_completely_different(self):
        assert _levenshtein("abc", "xyz") == 3


# ---------------------------------------------------------------------------
# Typosquatting detection
# ---------------------------------------------------------------------------

class TestTyposquatScore:
    def test_exact_match_no_risk(self):
        top = {"requests", "flask", "numpy"}
        score, reason = _typosquat_score("requests", top)
        assert score == 0.0

    def test_edit_distance_1(self):
        top = {"requests"}
        score, reason = _typosquat_score("requets", top)
        assert score >= 0.7
        assert "requests" in reason

    def test_edit_distance_2(self):
        top = {"requests"}
        score, reason = _typosquat_score("reqets", top)
        assert 0.3 <= score <= 0.6

    def test_prefix_attack(self):
        top = {"requests"}
        score, reason = _typosquat_score("python-requests", top)
        assert score >= 0.8
        assert "prefix/suffix" in reason

    def test_suffix_attack(self):
        top = {"flask"}
        score, reason = _typosquat_score("flask-python", top)
        assert score >= 0.8

    def test_character_substitution(self):
        top = {"requests"}
        score, reason = _typosquat_score("request5", top)
        # "request5" is edit distance 1 from "requests"
        assert score >= 0.5

    def test_no_resemblance(self):
        top = {"requests", "flask"}
        score, reason = _typosquat_score("completely-unique-name-xyz", top)
        assert score == 0.0

    def test_dash_underscore_normalisation(self):
        top = {"my-package"}
        score, reason = _typosquat_score("my_package", top)
        assert score == 0.0  # normalised forms match


# ---------------------------------------------------------------------------
# Package age scoring
# ---------------------------------------------------------------------------

class TestScorePackageAge:
    def test_very_new_package(self):
        meta = _make_meta(first_upload=datetime(2026, 3, 28, tzinfo=timezone.utc))
        score, reason = _score_package_age(meta)
        assert score >= 0.7
        assert "days old" in reason

    def test_old_package(self):
        meta = _make_meta(first_upload=datetime(2020, 1, 1, tzinfo=timezone.utc))
        score, _ = _score_package_age(meta)
        assert score == 0.0

    def test_unknown_age(self):
        meta = _make_meta(first_upload=None)
        score, reason = _score_package_age(meta)
        assert score == 0.5
        assert "Unable" in reason


# ---------------------------------------------------------------------------
# Maintainer count scoring
# ---------------------------------------------------------------------------

class TestScoreMaintainerCount:
    def test_single_maintainer(self):
        meta = _make_meta(author="Alice", maintainer="", author_email="", maintainer_email="")
        score, reason = _score_maintainer_count(meta)
        assert score >= 0.5
        assert "Single" in reason or "1" in reason

    def test_multiple_maintainers(self):
        meta = _make_meta(
            author="Alice", maintainer="Bob",
            author_email="alice@x.com", maintainer_email="bob@x.com",
        )
        score, _ = _score_maintainer_count(meta)
        assert score < 0.5


# ---------------------------------------------------------------------------
# Release pattern scoring
# ---------------------------------------------------------------------------

class TestScoreReleasePattern:
    def test_single_release(self):
        meta = _make_meta(releases=[ReleaseInfo("1.0")])
        score, reason = _score_release_pattern(meta)
        assert score >= 0.6
        assert "1 release" in reason

    def test_many_releases(self):
        releases = [ReleaseInfo(f"{i}.0") for i in range(20)]
        meta = _make_meta(releases=releases, first_upload=datetime(2020, 1, 1, tzinfo=timezone.utc))
        score, _ = _score_release_pattern(meta)
        assert score == 0.0

    def test_no_releases(self):
        meta = _make_meta(releases=[])
        score, _ = _score_release_pattern(meta)
        assert score >= 0.7

    def test_burst_pattern(self):
        releases = [ReleaseInfo(f"{i}.0") for i in range(5)]
        meta = _make_meta(
            releases=releases,
            first_upload=datetime(2026, 3, 28, tzinfo=timezone.utc),
        )
        score, reason = _score_release_pattern(meta)
        assert score >= 0.7
        assert "burst" in reason


# ---------------------------------------------------------------------------
# Metadata quality scoring
# ---------------------------------------------------------------------------

class TestScoreMetadataQuality:
    def test_complete_metadata(self):
        meta = _make_meta()
        score, reason = _score_metadata_quality(meta)
        assert score == 0.0
        assert "complete" in reason.lower()

    def test_missing_everything(self):
        meta = _make_meta(
            home_page="",
            description="",
            summary="",
            classifiers=[],
            author="",
            maintainer="",
        )
        score, reason = _score_metadata_quality(meta)
        assert score >= 0.75
        assert "no homepage" in reason


# ---------------------------------------------------------------------------
# Composite risk scorer
# ---------------------------------------------------------------------------

class TestComputeRisk:
    def test_low_risk_established_package(self):
        meta = _make_meta(
            name="wellknown",
            first_upload=datetime(2018, 1, 1, tzinfo=timezone.utc),
            author="Team",
            maintainer="Lead",
            author_email="a@x.com",
            maintainer_email="b@x.com",
            releases=[ReleaseInfo(f"{i}.0") for i in range(30)],
        )
        risk = compute_risk("wellknown", "1.0.0", meta)
        assert isinstance(risk, PackageRisk)
        assert risk.risk_score < 30

    def test_high_risk_sketchy_package(self):
        meta = _make_meta(
            name="requets",  # typosquat of "requests"
            first_upload=datetime(2026, 3, 29, tzinfo=timezone.utc),
            author="",
            maintainer="",
            author_email="",
            maintainer_email="",
            home_page="",
            description="",
            summary="",
            classifiers=[],
            releases=[ReleaseInfo("0.0.1")],
        )
        risk = compute_risk("requets", "0.0.1", meta)
        assert risk.risk_score > 50
        assert risk.is_risky

    def test_factors_populated(self):
        meta = _make_meta()
        risk = compute_risk("testpkg", "1.0.0", meta)
        factor_names = {f.name for f in risk.risk_factors}
        assert "typosquatting" in factor_names
        assert "package_age" in factor_names
        assert "maintainer_count" in factor_names
        assert "release_pattern" in factor_names
        assert "metadata_quality" in factor_names

    def test_custom_weights(self):
        meta = _make_meta(
            name="requets",  # typosquat
            first_upload=datetime(2020, 1, 1, tzinfo=timezone.utc),
            releases=[ReleaseInfo(f"{i}.0") for i in range(10)],
        )
        # Only weight typosquatting — should get high score
        config = AlterKSConfig(
            heuristic_weights={
                "typosquatting": 1.0,
                "package_age": 0.0,
                "maintainer_count": 0.0,
                "release_pattern": 0.0,
                "metadata_quality": 0.0,
            }
        )
        risk = compute_risk("requets", "1.0.0", meta, config=config)
        assert risk.risk_score > 50

    def test_zero_weights_gives_zero(self):
        meta = _make_meta()
        config = AlterKSConfig(
            heuristic_weights={
                "typosquatting": 0.0,
                "package_age": 0.0,
                "maintainer_count": 0.0,
                "release_pattern": 0.0,
                "metadata_quality": 0.0,
            }
        )
        risk = compute_risk("pkg", "1.0.0", meta, config=config)
        assert risk.risk_score == 0.0


# ---------------------------------------------------------------------------
# refresh_top_packages
# ---------------------------------------------------------------------------

SAMPLE_TOP_RESPONSE = {
    "last_update": "2026-03-30T10:00:00",
    "rows": [
        {"project": "boto3", "download_count": 999_999},
        {"project": "requests", "download_count": 888_888},
        {"project": "numpy", "download_count": 777_777},
    ],
}


class TestRefreshTopPackages:
    @respx.mock
    def test_fetches_and_writes(self, tmp_path: Path):
        """refresh_top_packages writes a valid top_packages.txt."""
        respx.get(TOP_PYPI_PACKAGES_URL).mock(
            return_value=httpx.Response(200, json=SAMPLE_TOP_RESPONSE)
        )
        with patch("alterks.heuristics._DATA_DIR", tmp_path):
            count = refresh_top_packages()

        assert count == 3
        txt = (tmp_path / "top_packages.txt").read_text(encoding="utf-8")
        assert "boto3" in txt
        assert "requests" in txt
        assert "numpy" in txt
        assert "Last updated:" in txt

    @respx.mock
    def test_invalidates_in_memory_cache(self, tmp_path: Path):
        """After refresh, the in-memory cache should be cleared."""
        respx.get(TOP_PYPI_PACKAGES_URL).mock(
            return_value=httpx.Response(200, json=SAMPLE_TOP_RESPONSE)
        )
        import alterks.heuristics as h

        h._TOP_PACKAGES = {"old-cached-pkg"}
        with patch("alterks.heuristics._DATA_DIR", tmp_path):
            refresh_top_packages()
        assert h._TOP_PACKAGES is None

    @respx.mock
    def test_http_error_raises(self):
        """Network errors should propagate as httpx.HTTPStatusError."""
        respx.get(TOP_PYPI_PACKAGES_URL).mock(
            return_value=httpx.Response(500)
        )
        with pytest.raises(httpx.HTTPStatusError):
            refresh_top_packages()

    @respx.mock
    def test_bad_json_structure_raises(self, tmp_path: Path):
        """Missing 'rows' key should raise ValueError."""
        respx.get(TOP_PYPI_PACKAGES_URL).mock(
            return_value=httpx.Response(200, json={"unexpected": True})
        )
        with patch("alterks.heuristics._DATA_DIR", tmp_path):
            with pytest.raises(ValueError, match="missing 'rows'"):
                refresh_top_packages()

    @respx.mock
    def test_empty_rows_raises(self, tmp_path: Path):
        """Empty rows list should raise ValueError."""
        respx.get(TOP_PYPI_PACKAGES_URL).mock(
            return_value=httpx.Response(200, json={"rows": []})
        )
        with patch("alterks.heuristics._DATA_DIR", tmp_path):
            with pytest.raises(ValueError, match="No package names"):
                refresh_top_packages()

    @respx.mock
    def test_respects_count_limit(self, tmp_path: Path):
        """Only the first N packages should be written."""
        many_rows = [{"project": f"pkg-{i}"} for i in range(100)]
        respx.get(TOP_PYPI_PACKAGES_URL).mock(
            return_value=httpx.Response(200, json={"rows": many_rows})
        )
        with patch("alterks.heuristics._DATA_DIR", tmp_path):
            count = refresh_top_packages(count=10)
        assert count == 10

    @respx.mock
    def test_uses_verify_true(self, tmp_path: Path):
        """HTTP client must use verify=True for TLS."""
        respx.get(TOP_PYPI_PACKAGES_URL).mock(
            return_value=httpx.Response(200, json=SAMPLE_TOP_RESPONSE)
        )
        import unittest.mock as _m

        original_cls = httpx.Client
        captured = {}

        class SpyClient(original_cls):
            def __init__(self, **kwargs):
                captured.update(kwargs)
                super().__init__(**kwargs)

        with _m.patch("alterks.heuristics.httpx.Client", SpyClient):
            with patch("alterks.heuristics._DATA_DIR", tmp_path):
                refresh_top_packages()

        assert captured.get("verify") is True
