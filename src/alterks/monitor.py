"""Continuous monitoring daemon — re-scans the environment on a schedule.

This module is invoked by ``alterks monitor`` and performs periodic
vulnerability checks against all installed packages.

Features
--------
- Scheduled re-scan with configurable interval (default: daily)
- Detects *newly disclosed* vulnerabilities by diffing against previous results
- Notification channels: stderr log (Rich), JSON file output
- Optional webhook URL for external notification systems
- Lightweight: delegates to :class:`Scanner` which uses batch OSV queries
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from rich.console import Console

from alterks.config import AlterKSConfig, load_config
from alterks.models import PolicyAction, ScanResult
from alterks.scanner import Scanner

logger = logging.getLogger(__name__)

# Default location for the state / output file
_DEFAULT_STATE_DIR = Path.home() / ".alterks"


# ---------------------------------------------------------------------------
# Notification helpers
# ---------------------------------------------------------------------------

def _result_to_dict(r: ScanResult) -> Dict[str, Any]:
    """Serialize a ScanResult into a JSON-friendly dict."""
    return {
        "name": r.name,
        "version": r.version,
        "vulnerability_count": r.vulnerability_count,
        "max_severity": r.max_severity.value,
        "risk_score": r.risk_score,
        "action": r.action.value,
        "reason": r.reason,
        "vulnerabilities": [
            {"id": v.id, "summary": v.summary, "severity": v.severity.value}
            for v in r.vulnerabilities
        ],
    }


def _build_report(
    results: List[ScanResult],
    new_issues: List[ScanResult],
    timestamp: str,
) -> Dict[str, Any]:
    """Build the JSON report payload."""
    issues = [r for r in results if r.action != PolicyAction.ALLOW]
    return {
        "timestamp": timestamp,
        "total_packages": len(results),
        "total_issues": len(issues),
        "new_issues": len(new_issues),
        "issues": [_result_to_dict(r) for r in issues],
        "new": [_result_to_dict(r) for r in new_issues],
    }


def notify_json_file(
    report: Dict[str, Any],
    output_path: Path,
) -> None:
    """Write the scan report as a JSON file.

    Appends to a JSON-lines file so history is preserved.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(report, default=str) + "\n")
    logger.info("Report written to %s", output_path)


def notify_stderr(
    results: List[ScanResult],
    new_issues: List[ScanResult],
    console: Console,
) -> None:
    """Log scan summary and issues to stderr via Rich console."""
    issues = [r for r in results if r.action != PolicyAction.ALLOW]

    if new_issues:
        console.print(
            f"[bold red]🚨 {len(new_issues)} NEW issue(s) detected:[/bold red]"
        )
        for r in new_issues:
            style = "red" if r.action == PolicyAction.BLOCK else "yellow"
            console.print(
                f"  [{style}]NEW {r.action.value.upper()}[/{style}] "
                f"{r.name}=={r.version}: {r.reason}"
            )

    if issues:
        console.print(
            f"[bold yellow]{len(issues)} total issue(s) "
            f"in {len(results)} packages:[/bold yellow]"
        )
        for r in issues:
            style = "red" if r.action == PolicyAction.BLOCK else "yellow"
            console.print(
                f"  [{style}]{r.action.value.upper()}[/{style}] "
                f"{r.name}=={r.version}: {r.reason}"
            )
    else:
        console.print(
            f"[green]All {len(results)} packages clean.[/green]"
        )


def notify_webhook(
    report: Dict[str, Any],
    webhook_url: str,
    *,
    timeout: float = 30.0,
) -> bool:
    """POST the report payload to a webhook URL.

    Returns True on success (2xx), False otherwise.
    Safe: never raises — errors are logged.
    """
    try:
        resp = httpx.post(
            webhook_url,
            json=report,
            timeout=timeout,
            headers={"Content-Type": "application/json"},
        )
        if resp.is_success:
            logger.info("Webhook notification sent to %s", webhook_url)
            return True
        logger.warning(
            "Webhook returned HTTP %d: %s", resp.status_code, resp.text[:200]
        )
        return False
    except httpx.HTTPError as exc:
        logger.warning("Webhook request failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Issue tracking — detect newly disclosed vulnerabilities
# ---------------------------------------------------------------------------

def _issue_key(r: ScanResult) -> Set[Tuple[str, str, str]]:
    """Return a set of (name, version, vuln_id) tuples for a result's vulns.

    For non-vulnerability issues (heuristic-only), use a synthetic key
    based on the action/reason so they are also tracked.
    """
    keys: Set[Tuple[str, str, str]] = set()
    if r.vulnerabilities:
        for v in r.vulnerabilities:
            keys.add((r.name, r.version, v.id))
    elif r.action != PolicyAction.ALLOW:
        keys.add((r.name, r.version, f"__risk__{r.action.value}"))
    return keys


def diff_issues(
    current: List[ScanResult],
    previous_keys: Set[Tuple[str, str, str]],
) -> List[ScanResult]:
    """Return results that contain at least one *new* issue key."""
    new: List[ScanResult] = []
    for r in current:
        if r.action == PolicyAction.ALLOW:
            continue
        keys = _issue_key(r)
        if keys - previous_keys:
            new.append(r)
    return new


def collect_keys(results: List[ScanResult]) -> Set[Tuple[str, str, str]]:
    """Collect all issue keys from a list of results."""
    all_keys: Set[Tuple[str, str, str]] = set()
    for r in results:
        all_keys |= _issue_key(r)
    return all_keys


# ---------------------------------------------------------------------------
# Main monitoring loop
# ---------------------------------------------------------------------------

def run_monitor(
    config: Optional[AlterKSConfig] = None,
    interval: int = 86400,
    once: bool = False,
    console: Optional[Console] = None,
    json_output: Optional[Path] = None,
    webhook_url: Optional[str] = None,
    scanner: Optional[Scanner] = None,
    _sleep_fn: Any = None,
) -> None:
    """Run the monitoring loop.

    Parameters
    ----------
    config:
        AlterKS configuration.
    interval:
        Seconds between scans (default: 86400 = 24 h).
    once:
        If True, run a single scan and exit.
    console:
        Rich console for output.  Defaults to stderr.
    json_output:
        Path to write JSON-lines reports.  ``None`` disables file output.
    webhook_url:
        URL to POST report payloads.  ``None`` disables webhook.
    scanner:
        Pre-built :class:`Scanner`.  Useful for testing.
    _sleep_fn:
        Override for ``time.sleep`` (used in tests to avoid real delays).
    """
    config = config or load_config()
    console = console or Console(stderr=True)
    scanner = scanner or Scanner(config=config)
    sleep = _sleep_fn or time.sleep

    previous_keys: Set[Tuple[str, str, str]] = set()

    while True:
        console.print("[bold]AlterKS monitor: scanning environment…[/bold]")
        timestamp = datetime.now(timezone.utc).isoformat()

        try:
            results = scanner.scan_environment()
        except Exception as exc:
            logger.error("Monitor scan failed: %s", exc)
            console.print(f"[red]Scan failed: {exc}[/red]")
            if once:
                return
            sleep(interval)
            continue

        # Detect newly disclosed issues
        new_issues = diff_issues(results, previous_keys)
        previous_keys = collect_keys(results)

        # --- Notification channels ---

        # 1. stderr log (always active)
        notify_stderr(results, new_issues, console)

        # 2. JSON file (if configured)
        if json_output is not None:
            report = _build_report(results, new_issues, timestamp)
            notify_json_file(report, json_output)

        # 3. Webhook (if configured)
        if webhook_url is not None:
            report = _build_report(results, new_issues, timestamp)
            notify_webhook(report, webhook_url)

        if once:
            return

        console.print(f"Next scan in {interval}s…", style="dim")
        sleep(interval)
