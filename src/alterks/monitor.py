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

import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx
from rich.console import Console

from alterks.config import AlterKSConfig, load_config
from alterks.models import PolicyAction, ScanResult
from alterks.scanner import Scanner
from alterks.sources.osv import OSVError

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


class WebhookURLError(Exception):
    """Raised when a webhook URL fails safety validation."""


# RFC 5735 / RFC 6890 private & special-use ranges checked by ipaddress
_BLOCKED_SCHEMES = frozenset({"file", "ftp", "data", "javascript", ""})


def validate_webhook_url(url: str) -> str:
    """Validate a webhook URL for SSRF safety.

    Checks:
    - Scheme must be ``https`` (``http`` accepted only for ``localhost``
      during development).
    - Hostname must not resolve to a private, loopback, or link-local IP.
    - No ``file://``, ``ftp://``, ``data:``, or blank-scheme URLs.

    Returns the validated URL unchanged, or raises :class:`WebhookURLError`.
    """
    parsed = urlparse(url)

    # --- Scheme check -------------------------------------------------------
    scheme = (parsed.scheme or "").lower()
    if scheme in _BLOCKED_SCHEMES:
        raise WebhookURLError(
            f"Webhook URL scheme '{scheme}' is not allowed. Use https://."
        )
    if scheme not in ("https", "http"):
        raise WebhookURLError(
            f"Webhook URL scheme '{scheme}' is not allowed. Use https://."
        )

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise WebhookURLError("Webhook URL has no hostname.")

    # --- Allow plain http only for localhost ---------------------------------
    _LOCALHOST_HOSTS = {"localhost", "127.0.0.1", "::1"}
    if scheme == "http" and hostname not in _LOCALHOST_HOSTS:
        raise WebhookURLError(
            f"Webhook URL uses http:// which is insecure. "
            f"Use https:// or localhost for development."
        )

    # --- Skip private-IP check for explicit localhost addresses ---------------
    if hostname in _LOCALHOST_HOSTS:
        return url

    # --- Block cloud metadata endpoints first (before generic private check) --
    _METADATA_HOSTS = {
        "169.254.169.254",          # AWS / GCP / Azure metadata
        "metadata.google.internal", # GCP
        "metadata.internal",
    }
    if hostname in _METADATA_HOSTS:
        raise WebhookURLError(
            f"Webhook URL points to a cloud metadata endpoint ({hostname}). "
            "This is blocked to prevent SSRF."
        )

    # --- Block private / reserved IPs (SSRF) --------------------------------
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise WebhookURLError(
                f"Webhook URL points to a private/reserved address ({hostname}). "
                "This is blocked to prevent SSRF."
            )
    except ValueError:
        # hostname is a DNS name — resolve it and check ALL resulting IPs
        # to prevent DNS rebinding attacks.
        _validate_resolved_ips(hostname)

    return url


def _validate_resolved_ips(hostname: str) -> None:
    """Resolve *hostname* via DNS and reject if any address is private/reserved.

    This prevents DNS rebinding attacks where a domain initially resolves
    to a public IP during validation but later rebinds to a private or
    metadata IP at request time.

    Raises :class:`WebhookURLError` if resolution fails or any address
    is private, loopback, link-local, or reserved.
    """
    try:
        # AF_UNSPEC → both IPv4 and IPv6 results
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise WebhookURLError(
            f"Could not resolve hostname '{hostname}': {exc}"
        ) from exc

    if not results:
        raise WebhookURLError(
            f"DNS resolution returned no addresses for '{hostname}'."
        )

    for family, _type, _proto, _canonname, sockaddr in results:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise WebhookURLError(
                f"Webhook URL hostname '{hostname}' resolves to "
                f"private/reserved address {ip_str}. "
                "This is blocked to prevent SSRF."
            )


def _compute_webhook_signature(payload_bytes: bytes, secret: str) -> str:
    """Compute HMAC-SHA256 signature for a webhook payload.

    Returns the hex digest prefixed with ``sha256=``.
    """
    mac = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def _sanitize_url(url: str) -> str:
    """Strip credentials (userinfo) from a URL for safe logging.

    ``https://user:token@hooks.example.com/notify``
    becomes ``https://***@hooks.example.com/notify``.

    If the URL has no credentials, it is returned unchanged.
    """
    parsed = urlparse(url)
    if not parsed.username and not parsed.password:
        return url
    # Rebuild netloc without credentials
    host_port = parsed.hostname or ""
    if parsed.port:
        host_port = f"{host_port}:{parsed.port}"
    safe_netloc = f"***@{host_port}"
    return parsed._replace(netloc=safe_netloc).geturl()


def notify_webhook(
    report: Dict[str, Any],
    webhook_url: str,
    *,
    timeout: float = 30.0,
    webhook_secret: Optional[str] = None,
) -> bool:
    """POST the report payload to a webhook URL.

    Validates the URL for SSRF safety before sending.
    When *webhook_secret* is provided, adds an ``X-AlterKS-Signature``
    header containing an HMAC-SHA256 hex digest of the JSON body.
    Returns True on success (2xx), False otherwise.
    Safe: never raises — errors are logged.
    """
    try:
        validate_webhook_url(webhook_url)
    except WebhookURLError as exc:
        logger.error("Webhook URL rejected: %s", exc)
        return False

    # Warn about insecure transport (HTTP even for localhost)
    parsed = urlparse(webhook_url)
    if (parsed.scheme or "").lower() == "http":
        logger.warning(
            "Webhook URL uses plain HTTP (%s). "
            "Sensitive vulnerability data may be exposed in transit. "
            "Use HTTPS in production.",
            _sanitize_url(webhook_url),
        )

    # Warn if no HMAC secret is configured
    if not webhook_secret:
        logger.warning(
            "No webhook secret configured. "
            "Payload will be sent without HMAC signature. "
            "Set webhook_secret in config or --webhook-secret on the CLI "
            "to authenticate payloads."
        )

    try:
        payload_bytes = json.dumps(report, default=str, separators=(",", ":")).encode("utf-8")

        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if webhook_secret:
            headers["X-AlterKS-Signature"] = _compute_webhook_signature(
                payload_bytes, webhook_secret,
            )

        resp = httpx.post(
            webhook_url,
            content=payload_bytes,
            timeout=timeout,
            headers=headers,
            verify=True,
        )
        if resp.is_success:
            logger.info("Webhook notification sent to %s", _sanitize_url(webhook_url))
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
    webhook_secret: Optional[str] = None,
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
    webhook_secret:
        Shared secret for HMAC-SHA256 webhook payload signing.
        Falls back to ``config.webhook_secret`` when *None*.
    scanner:
        Pre-built :class:`Scanner`.  Useful for testing.
    _sleep_fn:
        Override for ``time.sleep`` (used in tests to avoid real delays).
    """
    config = config or load_config()
    console = console or Console(stderr=True)
    scanner = scanner or Scanner(config=config)
    sleep = _sleep_fn or time.sleep

    # Resolve webhook secret: CLI flag > config file
    effective_secret = webhook_secret or config.webhook_secret

    # Validate webhook URL eagerly so the user gets immediate feedback
    if webhook_url is not None:
        try:
            validate_webhook_url(webhook_url)
        except WebhookURLError as exc:
            console.print(f"[bold red]Invalid webhook URL:[/bold red] {exc}")
            return

    previous_keys: Set[Tuple[str, str, str]] = set()

    try:
        while True:
            console.print("[bold]AlterKS monitor: scanning environment…[/bold]")
            timestamp = datetime.now(timezone.utc).isoformat()

            try:
                results = scanner.scan_environment()
            except (OSError, httpx.HTTPError, OSVError) as exc:
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
                notify_webhook(report, webhook_url, webhook_secret=effective_secret)

            if once:
                return

            console.print(f"Next scan in {interval}s…", style="dim")
            sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Monitor stopped by user.[/bold yellow]")
