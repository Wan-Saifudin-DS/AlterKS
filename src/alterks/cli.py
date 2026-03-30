"""AlterKS CLI — command-line interface for package scanning and monitoring.

Entry point: ``alterks`` (registered in ``pyproject.toml``).

Commands
--------
- ``alterks scan``        — scan current environment
- ``alterks scan -r FILE`` — scan a requirements file
- ``alterks install PKG`` — pre-scan then pip install
- ``alterks monitor``     — continuous monitoring daemon
- ``alterks quarantine``  — manage quarantined packages
- ``alterks report``      — generate scan report
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table

from alterks import __version__
from alterks.actions import execute_action, select_action
from alterks.config import AlterKSConfig, load_config
from alterks.models import PolicyAction, ScanResult, Severity
from alterks.quarantine import QuarantineManager
from alterks.scanner import Scanner

logger = logging.getLogger("alterks")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
        force=True,
    )


def _get_console(no_color: bool) -> Console:
    return Console(no_color=no_color, stderr=True)


def _render_table(results: List[ScanResult], console: Console) -> None:
    """Render scan results as a Rich table to stderr."""
    table = Table(title="AlterKS Scan Results", show_lines=True)
    table.add_column("Package", style="bold")
    table.add_column("Version")
    table.add_column("Vulns", justify="right")
    table.add_column("Max Severity")
    table.add_column("Risk Score", justify="right")
    table.add_column("Action", justify="center")

    severity_style = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.UNKNOWN: "dim",
    }
    action_style = {
        PolicyAction.BLOCK: "bold red",
        PolicyAction.QUARANTINE: "bold yellow",
        PolicyAction.ALERT: "yellow",
        PolicyAction.ALLOW: "green",
    }

    for r in sorted(results, key=lambda x: x.name):
        sev = r.max_severity
        table.add_row(
            r.name,
            r.version,
            str(r.vulnerability_count),
            f"[{severity_style.get(sev, '')}]{sev.value}[/]",
            f"{r.risk_score:.0f}" if r.risk_score > 0 else "-",
            f"[{action_style.get(r.action, '')}]{r.action.value.upper()}[/]",
        )

    console.print(table)


def _render_json(results: List[ScanResult]) -> str:
    """Serialize scan results to JSON."""
    data = []
    for r in results:
        entry = {
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
        data.append(entry)
    return json.dumps(data, indent=2)


def _render_markdown(results: List[ScanResult]) -> str:
    """Render scan results as a Markdown table."""
    lines = [
        "# AlterKS Scan Report",
        "",
        "| Package | Version | Vulns | Max Severity | Risk Score | Action |",
        "|---------|---------|------:|--------------|----------:|--------|",
    ]
    for r in sorted(results, key=lambda x: x.name):
        risk = f"{r.risk_score:.0f}" if r.risk_score > 0 else "-"
        lines.append(
            f"| {r.name} | {r.version} | {r.vulnerability_count} "
            f"| {r.max_severity.value} | {risk} | {r.action.value.upper()} |"
        )
    return "\n".join(lines) + "\n"


def _exit_code_from_results(results: List[ScanResult]) -> int:
    """Return non-zero exit code if any package is blocked."""
    for r in results:
        if r.action == PolicyAction.BLOCK:
            return 1
    return 0


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="alterks")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@click.option("-q", "--quiet", is_flag=True, help="Suppress informational output.")
@click.option("--no-color", is_flag=True, help="Disable coloured output.")
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool, no_color: bool) -> None:
    """AlterKS — ALTER KILL SWITCH.

    Python package scanner, monitor, and supply chain attack mitigation tool.
    """
    _setup_logging(verbose, quiet)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    ctx.obj["no_color"] = no_color
    ctx.obj["console"] = _get_console(no_color)


# ---------------------------------------------------------------------------
# alterks scan
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "-r", "--requirements",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to a requirements.txt file to scan.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["table", "json", "markdown"]),
    default="table",
    help="Output format.",
)
@click.option(
    "--fail-closed", is_flag=True, default=False,
    help="Alert instead of allowing when vulnerability data is unavailable.",
)
@click.pass_context
def scan(ctx: click.Context, requirements: Optional[Path], output_format: str, fail_closed: bool) -> None:
    """Scan installed packages or a requirements file for vulnerabilities."""
    console: Console = ctx.obj["console"]
    config = load_config()
    if fail_closed:
        config.fail_closed = True
    scanner = Scanner(config=config)

    if requirements:
        console.print(f"Scanning requirements file: {requirements}", style="bold")
        results = scanner.scan_requirements(requirements)
    else:
        console.print("Scanning installed environment…", style="bold")
        results = scanner.scan_environment()

    if not results:
        console.print("No packages to scan.", style="dim")
        ctx.exit(0)
        return

    if output_format == "json":
        click.echo(_render_json(results))
    elif output_format == "markdown":
        click.echo(_render_markdown(results))
    else:
        _render_table(results, console)

    # Summary
    blocked = sum(1 for r in results if r.action == PolicyAction.BLOCK)
    alerted = sum(1 for r in results if r.action == PolicyAction.ALERT)
    vulnerable = sum(1 for r in results if r.is_vulnerable)

    console.print(
        f"\nScanned {len(results)} package(s): "
        f"{vulnerable} vulnerable, {blocked} blocked, {alerted} alerted.",
    )

    ctx.exit(_exit_code_from_results(results))


# ---------------------------------------------------------------------------
# alterks install
# ---------------------------------------------------------------------------

@main.command()
@click.argument("package")
@click.option("--dry-run", is_flag=True, help="Scan only, do not install.")
@click.option(
    "--fail-closed", is_flag=True, default=False,
    help="Alert instead of allowing when vulnerability data is unavailable.",
)
@click.pass_context
def install(ctx: click.Context, package: str, dry_run: bool, fail_closed: bool) -> None:
    """Pre-scan a package, then install it if safe.

    PACKAGE should be in pip format (e.g. ``requests==2.31.0`` or just
    ``requests``).
    """
    console: Console = ctx.obj["console"]

    from alterks.pip_hook import resolve_and_scan

    config = load_config()
    if fail_closed:
        config.fail_closed = True
    result = resolve_and_scan(package, config)

    if result is None:
        console.print(f"Could not resolve package: {package}", style="bold red")
        ctx.exit(1)
        return

    action = select_action(result, config)

    if action == PolicyAction.BLOCK:
        console.print(
            f"[bold red]BLOCKED[/bold red]: {result.name}=={result.version} — {result.reason}"
        )
        ctx.exit(1)
        return

    if action == PolicyAction.ALERT:
        console.print(
            f"[yellow]WARNING[/yellow]: {result.name}=={result.version} — {result.reason}"
        )

    if action == PolicyAction.QUARANTINE:
        console.print(
            f"[bold yellow]QUARANTINE[/bold yellow]: {result.name}=={result.version} — {result.reason}"
        )
        if not dry_run:
            qm = QuarantineManager()
            vuln_ids = [v.id for v in result.vulnerabilities]
            qm.quarantine_package(
                result.name, result.version, result.reason,
                vulnerability_ids=vuln_ids,
                risk_score=result.risk_score,
            )
            console.print("Package quarantined successfully.")
        ctx.exit(0)
        return

    if dry_run:
        console.print(f"[green]ALLOWED[/green]: {result.name}=={result.version} (dry run)")
        ctx.exit(0)
        return

    # Proceed with pip install
    from alterks.models import validate_package_name, validate_package_version
    validate_package_name(result.name)
    validate_package_version(result.version)
    console.print(f"Installing {result.name}=={result.version}…")
    ret = subprocess.call(
        [sys.executable, "-m", "pip", "install", "--", f"{result.name}=={result.version}"],
    )
    ctx.exit(ret)


# ---------------------------------------------------------------------------
# alterks quarantine
# ---------------------------------------------------------------------------

@main.group()
@click.pass_context
def quarantine(ctx: click.Context) -> None:
    """Manage quarantined packages."""


@quarantine.command("list")
@click.pass_context
def quarantine_list(ctx: click.Context) -> None:
    """List all quarantined packages."""
    console: Console = ctx.obj["console"]
    qm = QuarantineManager()
    entries = qm.list_quarantined()

    if not entries:
        console.print("No quarantined packages.", style="dim")
        return

    table = Table(title="Quarantined Packages", show_lines=True)
    table.add_column("Package", style="bold")
    table.add_column("Version")
    table.add_column("Reason")
    table.add_column("Quarantined At")
    table.add_column("Risk Score", justify="right")

    for e in entries:
        table.add_row(
            e.name,
            e.version,
            e.reason[:60],
            e.quarantined_at[:19],
            f"{e.risk_score:.0f}" if e.risk_score > 0 else "-",
        )

    console.print(table)


@quarantine.command("inspect")
@click.argument("name")
@click.option("--version", "-v", "pkg_version", default=None, help="Specific version to inspect.")
@click.pass_context
def quarantine_inspect(ctx: click.Context, name: str, pkg_version: Optional[str]) -> None:
    """Show details of a quarantined package."""
    console: Console = ctx.obj["console"]
    qm = QuarantineManager()
    entry = qm.inspect_quarantined(name, version=pkg_version)

    if entry is None:
        console.print(f"Package '{name}' is not quarantined.", style="yellow")
        ctx.exit(1)
        return

    console.print(f"[bold]{entry.name}[/bold]=={entry.version}")
    console.print(f"  Reason:        {entry.reason}")
    console.print(f"  Quarantined:   {entry.quarantined_at}")
    console.print(f"  Venv path:     {entry.venv_path}")
    console.print(f"  Risk score:    {entry.risk_score:.1f}")
    if entry.vulnerability_ids:
        console.print(f"  Vulns:         {', '.join(entry.vulnerability_ids)}")


@quarantine.command("release")
@click.argument("name")
@click.option("--version", "-v", "pkg_version", default=None, help="Specific version to release.")
@click.option("--force", is_flag=True, help="Release even if re-scan still flags the package.")
@click.pass_context
def quarantine_release(ctx: click.Context, name: str, pkg_version: Optional[str], force: bool) -> None:
    """Release a quarantined package into the current environment.

    Before installing, the package is re-scanned for vulnerabilities.
    Use --force to override if it is still flagged.
    """
    from alterks.quarantine import QuarantineReleaseBlocked

    console: Console = ctx.obj["console"]
    qm = QuarantineManager()
    try:
        if qm.release_quarantined(name, version=pkg_version, force=force):
            console.print(f"Released [bold]{name}[/bold] into current environment.", style="green")
        else:
            console.print(f"Package '{name}' not found in quarantine.", style="red")
            ctx.exit(1)
    except QuarantineReleaseBlocked as exc:
        console.print(
            f"[bold red]BLOCKED[/bold red]: {exc}\n"
            "Use [bold]--force[/bold] to override.",
        )
        ctx.exit(1)


@quarantine.command("remove")
@click.argument("name")
@click.option("--version", "-v", "pkg_version", default=None, help="Specific version to remove.")
@click.pass_context
def quarantine_remove(ctx: click.Context, name: str, pkg_version: Optional[str]) -> None:
    """Remove a quarantined package without installing it."""
    console: Console = ctx.obj["console"]
    qm = QuarantineManager()
    if qm.remove_quarantined(name, version=pkg_version):
        console.print(f"Removed [bold]{name}[/bold] from quarantine.", style="green")
    else:
        console.print(f"Package '{name}' not found in quarantine.", style="red")
        ctx.exit(1)


# ---------------------------------------------------------------------------
# alterks report
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "--format", "output_format",
    type=click.Choice(["json", "table", "markdown"]),
    default="table",
    help="Report format.",
)
@click.option(
    "-o", "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write report to a file instead of stdout.",
)
@click.pass_context
def report(ctx: click.Context, output_format: str, output: Optional[Path]) -> None:
    """Generate a full scan report of the current environment."""
    console: Console = ctx.obj["console"]
    config = load_config()
    scanner = Scanner(config=config)

    console.print("Scanning environment for report…", style="bold")
    results = scanner.scan_environment()

    if not results:
        console.print("No packages found.", style="dim")
        return

    if output_format == "json":
        text = _render_json(results)
    elif output_format == "markdown":
        text = _render_markdown(results)
    else:
        if output:
            # Table can't be written to file; fall back to markdown
            text = _render_markdown(results)
        else:
            _render_table(results, console)
            return

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        console.print(f"Report written to {output}")
    else:
        click.echo(text)


# ---------------------------------------------------------------------------
# alterks monitor
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "--interval", type=int, default=86400,
    help="Scan interval in seconds (default: 86400 = 24h).",
)
@click.option(
    "--once", is_flag=True,
    help="Run a single scan and exit (no daemon loop).",
)
@click.option(
    "--json-output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write JSON-lines reports to this file.",
)
@click.option(
    "--webhook-url",
    type=str,
    default=None,
    help="POST scan reports to this webhook URL.",
)
@click.option(
    "--webhook-secret",
    type=str,
    default=None,
    help="Shared secret for HMAC-SHA256 webhook payload signing.",
)
@click.pass_context
def monitor(
    ctx: click.Context,
    interval: int,
    once: bool,
    json_output: Optional[Path],
    webhook_url: Optional[str],
    webhook_secret: Optional[str],
) -> None:
    """Start continuous monitoring of installed packages.

    Re-scans the environment at a configurable interval and reports
    any newly discovered vulnerabilities.
    """
    console: Console = ctx.obj["console"]

    from alterks.monitor import run_monitor

    config = load_config()
    run_monitor(
        config=config,
        interval=interval,
        once=once,
        console=console,
        json_output=json_output,
        webhook_url=webhook_url,
        webhook_secret=webhook_secret,
    )


# ---------------------------------------------------------------------------
# alterks generate-constraints
# ---------------------------------------------------------------------------

@main.command("generate-constraints")
@click.option(
    "-o", "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write constraints to a file instead of stdout.",
)
@click.pass_context
def generate_constraints(ctx: click.Context, output: Optional[Path]) -> None:
    """Generate a pip constraints file blocking known-bad versions."""
    console: Console = ctx.obj["console"]

    from alterks.pip_hook import generate_constraints as gen

    console.print("Scanning environment for constraints…", style="bold")
    text = gen()

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        console.print(f"Constraints written to {output}")
    else:
        click.echo(text)


# ---------------------------------------------------------------------------
# update-db
# ---------------------------------------------------------------------------

@main.command("update-db")
@click.pass_context
def update_db(ctx: click.Context) -> None:
    """Refresh the bundled top-packages list used for typosquatting detection.

    Fetches the latest top-5000 PyPI packages from
    hugovk.github.io/top-pypi-packages and updates the local database.
    """
    console: Console = ctx.obj["console"]

    from alterks.heuristics import refresh_top_packages

    console.print("Fetching latest top-packages list…", style="bold")
    try:
        count = refresh_top_packages()
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise SystemExit(1) from exc

    console.print(f"[green]Updated:[/green] {count} packages written.")
