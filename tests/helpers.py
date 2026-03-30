"""Reusable test factory helpers for AlterKS tests."""

from __future__ import annotations

from typing import List, Optional

from alterks.models import PolicyAction, ScanResult, Severity, Vulnerability


def make_vulnerability(
    vuln_id: str = "GHSA-1234",
    summary: str = "test vuln",
    severity: Severity = Severity.HIGH,
) -> Vulnerability:
    """Create a Vulnerability with sensible defaults."""
    return Vulnerability(id=vuln_id, summary=summary, severity=severity)


def make_scan_result(
    name: str = "pkg",
    version: str = "1.0.0",
    action: PolicyAction = PolicyAction.ALLOW,
    reason: str = "",
    vulns: Optional[List[Vulnerability]] = None,
) -> ScanResult:
    """Create a ScanResult with sensible defaults."""
    return ScanResult(
        name=name,
        version=version,
        action=action,
        reason=reason,
        vulnerabilities=vulns or [],
    )
