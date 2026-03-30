"""PyPI JSON API client for package metadata retrieval.

Fetches package metadata from ``https://pypi.org/pypi/{package}/json`` and
extracts fields relevant to heuristic risk scoring: upload times, maintainer
info, release history, project URLs, and description quality.

Includes a local file-based cache with configurable TTL to avoid hammering
PyPI on repeated scans.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"
DEFAULT_TIMEOUT = 15.0
DEFAULT_CACHE_TTL = 3600  # 1 hour
DEFAULT_CACHE_DIR = Path.home() / ".alterks" / "cache"


class PyPIError(Exception):
    """Raised when a PyPI API request fails."""


# ---------------------------------------------------------------------------
# Parsed metadata
# ---------------------------------------------------------------------------

@dataclass
class ReleaseInfo:
    """Metadata for a single release version."""

    version: str
    upload_time: Optional[datetime] = None
    yanked: bool = False


@dataclass
class PyPIMetadata:
    """Extracted PyPI metadata relevant to heuristic risk scoring."""

    name: str
    version: str
    summary: str = ""
    description: str = ""
    author: str = ""
    author_email: str = ""
    maintainer: str = ""
    maintainer_email: str = ""
    home_page: str = ""
    project_urls: Dict[str, str] = field(default_factory=dict)
    classifiers: List[str] = field(default_factory=list)
    releases: List[ReleaseInfo] = field(default_factory=list)
    first_upload: Optional[datetime] = None
    latest_upload: Optional[datetime] = None

    @property
    def age_days(self) -> Optional[int]:
        """Days since the first upload, or None if unknown."""
        if self.first_upload is None:
            return None
        delta = datetime.now(timezone.utc) - self.first_upload
        return max(0, delta.days)

    @property
    def release_count(self) -> int:
        return len(self.releases)

    @property
    def has_homepage(self) -> bool:
        if self.home_page:
            return True
        urls = {k.lower(): v for k, v in self.project_urls.items()}
        return bool(urls.get("homepage") or urls.get("home") or urls.get("source"))

    @property
    def has_description(self) -> bool:
        return len(self.description.strip()) > 50

    @property
    def maintainer_count(self) -> int:
        """Estimate maintainer count from available metadata.

        PyPI JSON API doesn't expose ownership roles directly, so we
        heuristically count unique author/maintainer identities.
        """
        identities: set[str] = set()
        for val in (self.author, self.maintainer):
            if val and val.strip():
                identities.add(val.strip().lower())
        for val in (self.author_email, self.maintainer_email):
            if val and val.strip():
                for email in val.split(","):
                    email = email.strip().lower()
                    if email:
                        identities.add(email)
        return max(1, len(identities))


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class PyPIClient:
    """Client for the PyPI JSON API with local file-based caching.

    Parameters
    ----------
    cache_dir:
        Directory for cached responses.  Set to *None* to disable caching.
    cache_ttl:
        Cache time-to-live in seconds.
    timeout:
        HTTP request timeout in seconds.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = DEFAULT_CACHE_DIR,
        cache_ttl: float = DEFAULT_CACHE_TTL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        self.timeout = timeout

    def get_metadata(self, package: str) -> PyPIMetadata:
        """Fetch and parse metadata for a PyPI package.

        Returns cached data when available and fresh.
        """
        raw = self._fetch_json(package)
        return _parse_metadata(raw)

    # -- Cache ---------------------------------------------------------------

    def _cache_path(self, package: str) -> Optional[Path]:
        if self.cache_dir is None:
            return None
        safe = hashlib.sha256(package.lower().encode()).hexdigest()[:16]
        return self.cache_dir / f"{package.lower()}_{safe}.json"

    def _read_cache(self, package: str) -> Optional[Dict[str, Any]]:
        path = self._cache_path(package)
        if path is None or not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            cached_at = data.get("_cached_at", 0)
            if time.time() - cached_at > self.cache_ttl:
                logger.debug("Cache expired for %s", package)
                return None
            return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Cache read failed for %s: %s", package, exc)
            return None

    def _write_cache(self, package: str, data: Dict[str, Any]) -> None:
        path = self._cache_path(package)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = dict(data)
            payload["_cached_at"] = time.time()
            path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError as exc:
            logger.debug("Cache write failed for %s: %s", package, exc)

    # -- HTTP ----------------------------------------------------------------

    def _fetch_json(self, package: str) -> Dict[str, Any]:
        cached = self._read_cache(package)
        if cached is not None:
            logger.debug("Cache hit for %s", package)
            cached.pop("_cached_at", None)
            return cached

        url = PYPI_JSON_URL.format(package=package)
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url, follow_redirects=True)
        except httpx.TimeoutException as exc:
            raise PyPIError(f"Timeout fetching {url}") from exc
        except httpx.HTTPError as exc:
            raise PyPIError(f"HTTP error fetching {url}: {exc}") from exc

        if resp.status_code == 404:
            raise PyPIError(f"Package not found on PyPI: {package}")
        if resp.status_code != 200:
            raise PyPIError(
                f"PyPI returned status {resp.status_code} for {package}"
            )

        data = resp.json()
        self._write_cache(package, data)
        return data


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_metadata(raw: Dict[str, Any]) -> PyPIMetadata:
    """Parse the PyPI JSON API response into a :class:`PyPIMetadata`."""
    info = raw.get("info", {})
    releases_raw = raw.get("releases", {})

    releases: List[ReleaseInfo] = []
    all_upload_times: List[datetime] = []

    for version, files in releases_raw.items():
        upload_time = _earliest_upload(files)
        yanked = any(f.get("yanked", False) for f in files) if files else False
        releases.append(ReleaseInfo(
            version=version,
            upload_time=upload_time,
            yanked=yanked,
        ))
        if upload_time is not None:
            all_upload_times.append(upload_time)

    # Sort releases by upload time (earliest first)
    releases.sort(key=lambda r: r.upload_time or datetime.max.replace(tzinfo=timezone.utc))

    first_upload = min(all_upload_times) if all_upload_times else None
    latest_upload = max(all_upload_times) if all_upload_times else None

    return PyPIMetadata(
        name=info.get("name", ""),
        version=info.get("version", ""),
        summary=info.get("summary", "") or "",
        description=info.get("description", "") or "",
        author=info.get("author", "") or "",
        author_email=info.get("author_email", "") or "",
        maintainer=info.get("maintainer", "") or "",
        maintainer_email=info.get("maintainer_email", "") or "",
        home_page=info.get("home_page", "") or "",
        project_urls=info.get("project_urls") or {},
        classifiers=info.get("classifiers") or [],
        releases=releases,
        first_upload=first_upload,
        latest_upload=latest_upload,
    )


def _earliest_upload(files: List[Dict[str, Any]]) -> Optional[datetime]:
    """Return the earliest upload_time_iso_8601 from a release's file list."""
    times: List[datetime] = []
    for f in files:
        ts = f.get("upload_time_iso_8601")
        if ts:
            dt = _parse_datetime(ts)
            if dt:
                times.append(dt)
    return min(times) if times else None


def _parse_datetime(value: str) -> Optional[datetime]:
    """Parse an ISO 8601 datetime string."""
    try:
        value = value.rstrip("Z") + "+00:00" if value.endswith("Z") else value
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None
