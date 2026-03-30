"""OSV.dev API client for querying Python package vulnerabilities.

Uses the public OSV.dev REST API:
- ``POST /v1/query``      — single package query
- ``POST /v1/querybatch`` — batch query (multiple packages at once)

See https://google.github.io/osv.dev/api/ for full documentation.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Tuple

import httpx

from alterks.models import Severity, Vulnerability

logger = logging.getLogger(__name__)

OSV_API_BASE = "https://api.osv.dev"
OSV_QUERY_URL = f"{OSV_API_BASE}/v1/query"
OSV_BATCH_URL = f"{OSV_API_BASE}/v1/querybatch"

DEFAULT_TIMEOUT = 30.0  # seconds
MAX_RETRIES = 3
BATCH_CHUNK_SIZE = 1000  # OSV recommends ≤1000 queries per batch


class OSVError(Exception):
    """Raised when the OSV API returns an unexpected error."""


class OSVClient:
    """Client for the OSV.dev vulnerability database.

    Parameters
    ----------
    timeout:
        HTTP request timeout in seconds.
    max_retries:
        Maximum number of retries with exponential backoff on transient errors.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = MAX_RETRIES,
    ) -> None:
        self._timeout = timeout
        self._max_retries = max_retries

    # -- Public API ----------------------------------------------------------

    def query_package(self, name: str, version: str) -> List[Vulnerability]:
        """Query OSV for known vulnerabilities of a single package.

        Parameters
        ----------
        name:
            PyPI package name (case-sensitive on OSV — use canonical form).
        version:
            Exact version string.

        Returns
        -------
        list[Vulnerability]
            Parsed vulnerability records. Empty list if no results.
        """
        return asyncio.run(self.aquery_package(name, version))

    def query_batch(
        self, packages: Sequence[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], List[Vulnerability]]:
        """Query OSV for vulnerabilities across multiple packages at once.

        Parameters
        ----------
        packages:
            Sequence of ``(name, version)`` tuples.

        Returns
        -------
        dict[(name, version), list[Vulnerability]]
            Mapping of each package to its vulnerabilities. Packages with no
            known vulnerabilities map to an empty list.
        """
        return asyncio.run(self.aquery_batch(packages))

    # -- Async API -----------------------------------------------------------

    async def aquery_package(self, name: str, version: str) -> List[Vulnerability]:
        """Async variant of :meth:`query_package`."""
        payload = {
            "package": {"name": name, "ecosystem": "PyPI"},
            "version": version,
        }
        raw_vulns = await self._post_with_pagination(OSV_QUERY_URL, payload)
        return [_parse_vulnerability(v) for v in raw_vulns]

    async def aquery_batch(
        self, packages: Sequence[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], List[Vulnerability]]:
        """Async variant of :meth:`query_batch`."""
        packages = list(packages)
        results: Dict[Tuple[str, str], List[Vulnerability]] = {}

        # Process in chunks to stay within OSV limits
        for start in range(0, len(packages), BATCH_CHUNK_SIZE):
            chunk = packages[start : start + BATCH_CHUNK_SIZE]
            chunk_results = await self._batch_chunk(chunk)
            results.update(chunk_results)

        return results

    # -- Internals -----------------------------------------------------------

    async def _batch_chunk(
        self, packages: List[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], List[Vulnerability]]:
        """Execute a single batch query chunk and handle pagination."""
        queries = [
            {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
            for name, version in packages
        ]

        # First request
        payload: Dict[str, Any] = {"queries": queries}
        data = await self._post_json(OSV_BATCH_URL, payload)
        raw_results: List[List[Dict[str, Any]]] = []

        batch_results = data.get("results", [])

        # Collect initial results and track which queries need pagination
        needs_pagination: List[Tuple[int, str]] = []  # (original_index, token)
        for i, result in enumerate(batch_results):
            vulns = result.get("vulns", [])
            raw_results.append(vulns)
            token = result.get("next_page_token")
            if token:
                needs_pagination.append((i, token))

        # Handle pagination for queries that returned next_page_token
        while needs_pagination:
            paged_queries = []
            paged_indices = []
            for orig_idx, token in needs_pagination:
                name, version = packages[orig_idx]
                paged_queries.append({
                    "package": {"name": name, "ecosystem": "PyPI"},
                    "version": version,
                    "page_token": token,
                })
                paged_indices.append(orig_idx)

            page_payload: Dict[str, Any] = {"queries": paged_queries}
            page_data = await self._post_json(OSV_BATCH_URL, page_payload)
            page_results = page_data.get("results", [])

            needs_pagination = []
            for j, result in enumerate(page_results):
                orig_idx = paged_indices[j]
                vulns = result.get("vulns", [])
                raw_results[orig_idx].extend(vulns)
                token = result.get("next_page_token")
                if token:
                    needs_pagination.append((orig_idx, token))

        # Parse into Vulnerability objects
        results: Dict[Tuple[str, str], List[Vulnerability]] = {}
        for i, pkg in enumerate(packages):
            if i < len(raw_results):
                results[pkg] = [_parse_vulnerability(v) for v in raw_results[i]]
            else:
                results[pkg] = []

        return results

    async def _post_with_pagination(
        self, url: str, payload: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """POST to a single-query endpoint and follow pagination."""
        all_vulns: List[Dict[str, Any]] = []
        current_payload = dict(payload)

        while True:
            data = await self._post_json(url, current_payload)
            vulns = data.get("vulns", [])
            all_vulns.extend(vulns)

            next_token = data.get("next_page_token")
            if not next_token:
                break

            current_payload = dict(payload)
            current_payload["page_token"] = next_token

        return all_vulns

    async def _post_json(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST JSON with retries and exponential backoff."""
        last_error: Optional[Exception] = None

        for attempt in range(self._max_retries):
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout, verify=True,
                ) as client:
                    response = await client.post(url, json=payload)

                if response.status_code == 200:
                    return response.json()  # type: ignore[no-any-return]

                if response.status_code == 400:
                    # Client error — don't retry
                    raise OSVError(
                        f"OSV API bad request (400): {response.text}"
                    )

                # Server errors (5xx) or rate limiting — retry
                if response.status_code >= 500 or response.status_code == 429:
                    logger.warning(
                        "OSV API returned %d (attempt %d/%d)",
                        response.status_code,
                        attempt + 1,
                        self._max_retries,
                    )
                    last_error = OSVError(
                        f"OSV API error {response.status_code}: {response.text}"
                    )
                else:
                    raise OSVError(
                        f"OSV API unexpected status {response.status_code}: {response.text}"
                    )

            except httpx.TimeoutException as exc:
                logger.warning(
                    "OSV API timeout (attempt %d/%d): %s",
                    attempt + 1,
                    self._max_retries,
                    exc,
                )
                last_error = exc
            except httpx.HTTPError as exc:
                logger.warning(
                    "OSV API HTTP error (attempt %d/%d): %s",
                    attempt + 1,
                    self._max_retries,
                    exc,
                )
                last_error = exc

            # Exponential backoff: 1s, 2s, 4s
            if attempt < self._max_retries - 1:
                delay = 2**attempt
                await asyncio.sleep(delay)

        raise OSVError(f"OSV API request failed after {self._max_retries} attempts") from last_error


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_vulnerability(raw: Dict[str, Any]) -> Vulnerability:
    """Parse a raw OSV vulnerability JSON object into a Vulnerability model."""
    vuln_id = raw.get("id", "UNKNOWN")
    summary = raw.get("summary", "")
    details = raw.get("details", "")
    aliases = raw.get("aliases", [])

    # Parse severity — OSV uses multiple formats
    severity = _extract_severity(raw)

    # Parse fix versions from affected[].ranges[].events[]
    fix_versions = _extract_fix_versions(raw)

    # Parse timestamps
    published = _parse_datetime(raw.get("published"))
    modified = _parse_datetime(raw.get("modified"))

    return Vulnerability(
        id=vuln_id,
        summary=summary,
        severity=severity,
        fix_versions=fix_versions,
        aliases=aliases,
        details=details,
        published=published,
        modified=modified,
    )


def _extract_severity(raw: Dict[str, Any]) -> Severity:
    """Extract the highest severity from an OSV record.

    OSV records may carry severity in multiple places:
    1. ``severity[]`` top-level array with CVSS vectors
    2. ``database_specific.severity`` string
    3. ``ecosystem_specific.severity`` string
    4. ``affected[].ecosystem_specific.severity`` string
    """
    # 1. Top-level severity array (CVSS-based)
    for sev_entry in raw.get("severity", []):
        score_str = sev_entry.get("score", "")
        if score_str:
            parsed = _cvss_score_to_severity(score_str)
            if parsed != Severity.UNKNOWN:
                return parsed

    # 2. database_specific.severity
    db_sev = raw.get("database_specific", {}).get("severity")
    if db_sev and isinstance(db_sev, str):
        parsed = Severity.from_str(db_sev)
        if parsed != Severity.UNKNOWN:
            return parsed

    # 3. affected[].database_specific.severity or ecosystem_specific.severity
    for affected in raw.get("affected", []):
        db_sev = affected.get("database_specific", {}).get("severity")
        if db_sev and isinstance(db_sev, str):
            parsed = Severity.from_str(db_sev)
            if parsed != Severity.UNKNOWN:
                return parsed
        eco_sev = affected.get("ecosystem_specific", {}).get("severity")
        if eco_sev and isinstance(eco_sev, str):
            parsed = Severity.from_str(eco_sev)
            if parsed != Severity.UNKNOWN:
                return parsed

    return Severity.UNKNOWN


def _cvss_score_to_severity(score_str: str) -> Severity:
    """Convert a CVSS score string or vector to a severity level.

    Handles both plain numeric scores and CVSS vectors containing /S:X.
    """
    try:
        score = float(score_str)
    except ValueError:
        # Try to extract numeric base score from CVSS vector
        # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → no direct score
        # Some OSV records include the score directly
        return Severity.UNKNOWN

    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score > 0.0:
        return Severity.LOW
    return Severity.UNKNOWN


def _extract_fix_versions(raw: Dict[str, Any]) -> List[str]:
    """Extract fix versions from affected[].ranges[].events[] 'fixed' entries."""
    fix_versions: List[str] = []
    seen: set[str] = set()

    for affected in raw.get("affected", []):
        for range_entry in affected.get("ranges", []):
            for event in range_entry.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed not in seen:
                    fix_versions.append(fixed)
                    seen.add(fixed)

    return fix_versions


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 datetime string from OSV."""
    if not value:
        return None
    try:
        # Handle trailing Z
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except (ValueError, TypeError):
        return None
