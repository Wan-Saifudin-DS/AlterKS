"""Shared test fixtures and mock data for AlterKS tests."""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Sample OSV API responses
# ---------------------------------------------------------------------------

FLASK_VULN_RESPONSE = {
    "vulns": [
        {
            "id": "PYSEC-2019-179",
            "summary": "The Pallets Project Flask before 1.0 is affected by unexpected memory usage.",
            "details": "DoS via crafted encoded JSON data.",
            "aliases": ["CVE-2019-1010083", "GHSA-5wv5-4vpf-pj6m"],
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "affected": [
                {
                    "package": {"name": "Flask", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "1.0"},
                            ],
                        }
                    ],
                    "ecosystem_specific": {"severity": "HIGH"},
                }
            ],
            "published": "2019-07-17T00:00:00Z",
            "modified": "2022-04-13T03:04:39Z",
        },
        {
            "id": "PYSEC-2018-66",
            "summary": "Flask before 0.12.3 CWE-20: Improper Input Validation.",
            "details": "Large amount of memory usage leading to denial of service.",
            "aliases": ["CVE-2018-1000656", "GHSA-562c-5r94-xh97"],
            "affected": [
                {
                    "package": {"name": "Flask", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "0.12.3"},
                            ],
                        }
                    ],
                    "database_specific": {"severity": "HIGH"},
                }
            ],
            "published": "2018-08-20T00:00:00Z",
            "modified": "2022-04-13T03:04:30Z",
        },
    ]
}

NO_VULN_RESPONSE: dict = {"vulns": []}

EMPTY_RESPONSE: dict = {}

BATCH_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "PYSEC-2019-179",
                    "modified": "2022-04-13T03:04:39Z",
                }
            ]
        },
        {"vulns": []},
    ]
}

BATCH_PAGINATED_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "PYSEC-2019-179",
                    "modified": "2022-04-13T03:04:39Z",
                }
            ],
            "next_page_token": "token_page2",
        },
        {"vulns": []},
    ]
}

BATCH_PAGE2_RESPONSE = {
    "results": [
        {
            "vulns": [
                {
                    "id": "PYSEC-2018-66",
                    "modified": "2022-04-13T03:04:30Z",
                }
            ]
        },
    ]
}

SINGLE_PAGINATED_RESPONSE_PAGE1 = {
    "vulns": [
        {
            "id": "PYSEC-2019-179",
            "summary": "Flask DoS",
            "affected": [
                {
                    "package": {"name": "Flask", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.0"}],
                        }
                    ],
                }
            ],
        }
    ],
    "next_page_token": "abc123",
}

SINGLE_PAGINATED_RESPONSE_PAGE2 = {
    "vulns": [
        {
            "id": "PYSEC-2018-66",
            "summary": "Flask CWE-20",
            "affected": [
                {
                    "package": {"name": "Flask", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "0.12.3"}],
                        }
                    ],
                }
            ],
        }
    ],
}
