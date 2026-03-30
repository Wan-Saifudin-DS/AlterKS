"""Kill-switch action engine.

Executes the appropriate response when a package is classified as risky or
vulnerable based on its :class:`~alterks.models.ScanResult`:

- **block** — prevent installation by raising ``SystemExit``
- **quarantine** — install into an isolated venv and log the event
- **alert** — emit a warning and optional JSON report, but allow the install
- **allow** — no-op
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, TextIO

from alterks.config import AlterKSConfig
from alterks.models import PolicyAction, ScanResult

logger = logging.getLogger(__name__)


class ActionResult:
    """Outcome of executing an action on a scan result."""

    def __init__(
        self,
        action: PolicyAction,
        package: str,
        version: str,
        reason: str,
        blocked: bool = False,
    ) -> None:
        self.action = action
        self.package = package
        self.version = version
        self.reason = reason
        self.blocked = blocked
        self.timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "package": self.package,
            "version": self.version,
            "reason": self.reason,
            "blocked": self.blocked,
            "timestamp": self.timestamp.isoformat(),
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def execute_action(
    result: ScanResult,
    config: Optional[AlterKSConfig] = None,
    report_path: Optional[Path] = None,
    stderr: TextIO = sys.stderr,
) -> ActionResult:
    """Execute the kill-switch action for a scan result.

    Parameters
    ----------
    result:
        The scan result whose ``action`` field dictates behaviour.
    config:
        AlterKS configuration (used for risk threshold checks).
    report_path:
        Optional path for writing a JSON alert report.
    stderr:
        Stream for warning output (defaults to ``sys.stderr``).

    Returns
    -------
    ActionResult
        Describes what was done.  For ``BLOCK``, this function raises
        ``SystemExit`` *after* returning the result object only when
        ``raise_on_block`` is handled by the caller.

    Raises
    ------
    SystemExit
        When the action is ``BLOCK``.
    """
    action = _determine_final_action(result, config)

    if action == PolicyAction.BLOCK:
        return _do_block(result, stderr)
    elif action == PolicyAction.QUARANTINE:
        return _do_quarantine(result, stderr)
    elif action == PolicyAction.ALERT:
        return _do_alert(result, report_path, stderr)
    else:
        return _do_allow(result)


def select_action(
    result: ScanResult,
    config: Optional[AlterKSConfig] = None,
) -> PolicyAction:
    """Determine the final action for a scan result without executing it.

    Combines the vulnerability-based action from the scan with the
    heuristic risk score check from the config.
    """
    return _determine_final_action(result, config)


# ---------------------------------------------------------------------------
# Internal action handlers
# ---------------------------------------------------------------------------

def _determine_final_action(
    result: ScanResult,
    config: Optional[AlterKSConfig] = None,
) -> PolicyAction:
    """Resolve the final action considering both vuln severity and risk score."""
    action = result.action

    # Elevate to BLOCK if risk score exceeds threshold
    if config and result.risk is not None:
        if config.exceeds_risk_threshold(result.risk.risk_score):
            if action in (PolicyAction.ALLOW, PolicyAction.ALERT):
                action = PolicyAction.BLOCK
                logger.info(
                    "Elevated action for %s to BLOCK (risk score %.1f >= threshold %.1f)",
                    result.name,
                    result.risk.risk_score,
                    config.risk_threshold,
                )

    return action


def _do_block(result: ScanResult, stderr: TextIO) -> ActionResult:
    """Block a package installation."""
    msg = (
        f"\n{'='*60}\n"
        f"  BLOCKED: {result.name}=={result.version}\n"
        f"  Reason: {result.reason}\n"
    )
    if result.vulnerabilities:
        msg += f"  Vulnerabilities: {result.vulnerability_count}\n"
        for v in result.vulnerabilities[:5]:
            msg += f"    - {v.id}: {v.summary[:80]}\n"
        if result.vulnerability_count > 5:
            msg += f"    ... and {result.vulnerability_count - 5} more\n"
    if result.risk and result.risk.risk_score > 0:
        msg += f"  Risk score: {result.risk.risk_score:.1f}/100\n"
    msg += f"{'='*60}\n"

    stderr.write(msg)
    stderr.flush()

    action_result = ActionResult(
        action=PolicyAction.BLOCK,
        package=result.name,
        version=result.version,
        reason=result.reason,
        blocked=True,
    )

    raise SystemExit(
        f"AlterKS: Installation of {result.name}=={result.version} blocked. "
        f"{result.reason}"
    )


def _do_quarantine(result: ScanResult, stderr: TextIO) -> ActionResult:
    """Quarantine a package — defer to quarantine module for venv isolation."""
    msg = (
        f"[AlterKS QUARANTINE] {result.name}=={result.version}: {result.reason}\n"
    )
    stderr.write(msg)
    stderr.flush()

    logger.warning("Quarantining %s==%s: %s", result.name, result.version, result.reason)

    return ActionResult(
        action=PolicyAction.QUARANTINE,
        package=result.name,
        version=result.version,
        reason=result.reason,
        blocked=False,
    )


def _do_alert(
    result: ScanResult,
    report_path: Optional[Path],
    stderr: TextIO,
) -> ActionResult:
    """Alert about a package but allow installation to proceed."""
    msg = (
        f"[AlterKS WARNING] {result.name}=={result.version}: {result.reason}\n"
    )
    stderr.write(msg)
    stderr.flush()

    logger.warning("Alert for %s==%s: %s", result.name, result.version, result.reason)

    action_result = ActionResult(
        action=PolicyAction.ALERT,
        package=result.name,
        version=result.version,
        reason=result.reason,
        blocked=False,
    )

    if report_path is not None:
        _write_json_report(action_result, report_path)

    return action_result


def _do_allow(result: ScanResult) -> ActionResult:
    """Allow a package — no-op."""
    return ActionResult(
        action=PolicyAction.ALLOW,
        package=result.name,
        version=result.version,
        reason=result.reason,
        blocked=False,
    )


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def _write_json_report(action_result: ActionResult, path: Path) -> None:
    """Append an action result to a JSON-lines report file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(action_result.to_dict()) + "\n")
    except OSError as exc:
        logger.error("Failed to write report to %s: %s", path, exc)
