# AlterKS — ALTER KILL SWITCH

[![PyPI version](https://img.shields.io/pypi/v/alterks)](https://pypi.org/project/alterks/)
[![Python](https://img.shields.io/pypi/pyversions/alterks)](https://pypi.org/project/alterks/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-orange)](https://buymeacoffee.com/wansaifudin)
[![Tests](https://github.com/Wan-Saifudin-DS/AlterKS/actions/workflows/tests.yml/badge.svg)](https://github.com/Wan-Saifudin-DS/AlterKS/actions)

**Python package scanner, monitor, and supply chain attack mitigation tool.**

AlterKS scans your Python dependencies for known vulnerabilities (via [OSV.dev](https://osv.dev)) and suspicious package metadata heuristics, then takes configurable action: **block** installation, **quarantine** to an isolated environment, or **alert** with a warning.

## Why AlterKS?

Supply chain attacks on PyPI are increasing — typosquatting, dependency confusion, and hijacked maintainer accounts are real threats. Existing tools like `pip-audit` and `safety` check for known CVEs, but don't:

- **Block installs before they happen** — AlterKS wraps `pip install` with a pre-scan gate
- **Score risk heuristically** — detect suspicious packages that have no CVEs yet (typosquats, brand-new single-maintainer packages)
- **Quarantine instead of just blocking** — isolate risky packages for inspection without polluting your environment
- **Monitor continuously** — detect newly disclosed vulnerabilities against already-installed packages
- **Generate constraints** — output pip constraint files to lock down your dependency tree

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI Interface                           │
│  alterks scan | install | monitor | quarantine | report         │
├─────────────┬───────────────────────────────────┬───────────────┤
│  Scanner    │        Heuristic Risk Engine       │   Monitor     │
│  (scanner)  │         (heuristics)               │  (monitor)    │
├─────────────┼───────────────────────────────────┼───────────────┤
│             │       Data Sources Layer           │               │
│             │  ┌──────────┐  ┌───────────┐      │               │
│             │  │ OSV.dev  │  │ PyPI JSON │      │               │
│             │  │  Client  │  │  Client   │      │               │
│             │  └──────────┘  └───────────┘      │               │
├─────────────┴───────────────────────────────────┴───────────────┤
│                      Action Engine                              │
│            BLOCK  |  QUARANTINE  |  ALERT  |  ALLOW             │
├─────────────────────────────────────────────────────────────────┤
│                   Policy Config (pyproject.toml)                │
│         [tool.alterks] severity, allowlist, actions             │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Vulnerability scanning** — queries OSV.dev for known CVEs/PYSECs against installed or to-be-installed packages
- **Heuristic risk scoring** — detects typosquatting, suspiciously new packages, single-maintainer risks, poor metadata quality
- **Kill switch actions** — block, quarantine, or alert based on configurable severity thresholds
- **Pre-install protection** — `alterks install <pkg>` scans before pip installs
- **Continuous monitoring** — scheduled re-scans detect newly disclosed vulnerabilities with JSON and webhook notifications
- **Quarantine management** — isolate risky packages in separate virtual environments
- **Constraint generation** — output pip constraint files to block known-bad versions
- **Policy-driven** — configure everything via `[tool.alterks]` in `pyproject.toml`
- **Cross-platform** — tested on Linux and Windows via CI matrix (Python 3.9–3.12)

## Installation

```bash
pip install alterks
```

For development:

```bash
pip install alterks[dev]
```

## Quick Start

```bash
# Scan your current environment
alterks scan

# Scan a requirements file
alterks scan -r requirements.txt

# Install a package with pre-install scanning
alterks install flask

# Start continuous monitoring
alterks monitor --once
```

## CLI Reference

### `alterks scan`

Scan installed packages or a requirements file for vulnerabilities and heuristic risks.

```bash
# Scan current environment (table output)
alterks scan

# Scan with JSON output
alterks scan --format json

# Scan with Markdown output
alterks scan --format markdown

# Scan a requirements file
alterks scan -r requirements.txt
```

**Options:**
- `-r, --requirements FILE` — scan a requirements file instead of the environment
- `--format [table|json|markdown]` — output format (default: `table`)

**Exit codes:** `0` = all clean, `1` = blocked packages found.

### `alterks install`

Pre-scan a package before installing it with pip. Blocks installation if the scan detects critical issues.

```bash
# Install with pre-scan
alterks install requests

# Dry-run (scan only, no install)
alterks install flask --dry-run
```

**Options:**
- `--dry-run` — scan only, do not run pip install

### `alterks quarantine`

Manage packages that have been quarantined to isolated virtual environments.

```bash
# List quarantined packages
alterks quarantine list

# Inspect a specific quarantined package
alterks quarantine inspect <name> <version>

# Release a package from quarantine
alterks quarantine release <name> <version>

# Remove a quarantined package entirely
alterks quarantine remove <name> <version>
```

### `alterks report`

Generate a comprehensive scan report of your environment.

```bash
# Print JSON report
alterks report --format json

# Write Markdown report to a file
alterks report --format markdown -o report.md
```

**Options:**
- `--format [table|json|markdown]` — output format (default: `table`)
- `-o, --output FILE` — write report to a file instead of stdout

### `alterks monitor`

Continuously monitor installed packages for newly disclosed vulnerabilities.

```bash
# Run a single scan
alterks monitor --once

# Run every hour
alterks monitor --interval 3600

# Save reports to a JSON-lines file
alterks monitor --json-output reports.jsonl

# Send reports to a webhook
alterks monitor --webhook-url https://example.com/hook
```

**Options:**
- `--interval SECONDS` — scan interval (default: `86400` = 24 hours)
- `--once` — run a single scan and exit
- `--json-output FILE` — append JSON-lines reports to a file
- `--webhook-url URL` — POST scan reports to a webhook endpoint

### `alterks generate-constraints`

Generate a pip constraints file that blocks known-vulnerable versions.

```bash
# Print to stdout
alterks generate-constraints

# Write to file
alterks generate-constraints -o constraints.txt

# Then use with pip:
pip install -c constraints.txt -r requirements.txt
```

**Options:**
- `-o, --output FILE` — write constraints to a file instead of stdout

### Global Options

All commands support:
- `--verbose` — enable debug logging
- `--quiet` — suppress informational output
- `--no-color` — disable colored output

## Configuration

Add to your `pyproject.toml`:

```toml
[tool.alterks]
# Action per severity: "block", "quarantine", "alert", "allow"
severity_actions = { critical = "block", high = "block", medium = "alert", low = "allow" }

# Risk score threshold (0-100) — packages above this trigger the configured action
risk_threshold = 60

# Packages always allowed regardless of scan results
allowlist = ["my-internal-package"]

# Packages always blocked regardless of scan results
blocklist = ["known-malicious-pkg"]

[tool.alterks.heuristic_weights]
typosquatting = 0.30
package_age = 0.20
maintainer_count = 0.15
release_pattern = 0.15
metadata_quality = 0.20
```

## Heuristic Risk Factors

| Factor | Weight | What it detects |
|--------|--------|-----------------|
| **Typosquatting** | 30% | Name similarity to top 5,000 PyPI packages |
| **Package age** | 20% | Recently created packages (< 30 days) |
| **Maintainer count** | 15% | Single-maintainer packages |
| **Release pattern** | 15% | Unusual version release cadence |
| **Metadata quality** | 20% | Missing descriptions, URLs, classifiers |

## Development

```bash
# Clone and install in editable mode
git clone https://github.com/Wan-Saifudin-DS/AlterKS.git
cd AlterKS
pip install -e ".[dev]"

# Run tests
pytest tests/

# Lint
ruff check src/ tests/
```

CI runs on both **Ubuntu** and **Windows** across Python 3.9 and 3.12.

## Project Structure

```
src/alterks/
├── __init__.py          # Version, public API
├── models.py            # Core dataclasses (ScanResult, Vulnerability, PolicyAction)
├── config.py            # Policy config loader from pyproject.toml
├── scanner.py           # Scan orchestrator: environment/requirements scanning
├── heuristics.py        # Composite risk scorer (typosquatting, age, maintainer…)
├── actions.py           # Kill switch logic: block, quarantine, alert
├── quarantine.py        # Isolated venv quarantine manager
├── cli.py               # CLI commands (scan, install, monitor, quarantine, report)
├── pip_hook.py          # Pip install wrapper with pre-scan
├── monitor.py           # Continuous monitoring daemon
├── sources/
│   ├── osv.py           # OSV.dev API client (single + batch queries)
│   └── pypi.py          # PyPI JSON API client for metadata heuristics
└── data/
    └── top_packages.txt # Bundled top-5,000 PyPI package names (typosquatting)
```

## Changelog

### v0.2.4 — Webhook Secret Environment Variable Support

- **Fixed**: `webhook_secret` may be stored in plaintext in `pyproject.toml` (A07:2021 — Identification Failures). The webhook HMAC secret is now resolved with priority: (1) `ALTERKS_WEBHOOK_SECRET` environment variable, (2) `webhook_secret` in `[tool.alterks]`. When the secret is found in the config file rather than the environment, a warning is emitted advising the user to use the environment variable instead, since `pyproject.toml` is typically committed to version control.

### v0.2.3 — Restrictive File Permissions on State Files

- **Fixed**: Inconsistent file permissions on state files (A01:2021 — Broken Access Control). All directories created under `~/.alterks` (reports, quarantine, locks) now enforce owner-only permissions (`0o700`) on Unix via `chmod(stat.S_IRWXU)`. Lock files created with `os.open()` now specify mode `0o600` (owner read/write only). The PyPI cache directory was already correctly restricted; this extends the same discipline to report output files, quarantine directories, manifest locks, and monitor JSON-lines output. Windows systems are unaffected (NTFS uses ACLs, not POSIX permissions).

### v0.2.2 — Specific Exception Handling in update-db

- **Fixed**: Broad `except Exception` in `update-db` command (A09:2021 — Logging Failures). The `update-db` command now catches only `httpx.HTTPError`, `ValueError`, and `OSError` — the specific exceptions that `refresh_top_packages()` can raise. Internal bugs (`TypeError`, `AttributeError`, etc.) are no longer silently masked behind a generic "Error" message and will propagate with full tracebacks for debugging.

### v0.2.1 — Dependency Upper Bounds

- **Fixed**: No upper bounds on dependency versions (A06:2021 — Vulnerable Components). All runtime and dev dependencies in `pyproject.toml` now specify both minimum and maximum version bounds (e.g., `httpx>=0.24,<1.0`, `click>=8.0,<9.0`). Prevents a future major release with breaking changes or a supply chain compromise from being automatically installed. Upper bounds are set at the next major version boundary from current known-good versions.

### v0.2.0 — Concurrent Write Safety (Monitor)

- **Fixed**: `notify_json_file()` concurrent write corruption in `alterks monitor` (A04:2021 — Insecure Design). Monitor JSON-lines output now uses exclusive file locking (`msvcrt.locking(LK_NBLCK)` on Windows, `fcntl.flock(LOCK_EX | LOCK_NB)` on Unix) with a non-blocking retry loop and 10-second timeout — the same pattern already used in `actions.py` (`_locked_append`). Multiple concurrent `alterks monitor` processes writing to the same JSON-lines file can no longer interleave mid-line and corrupt output.

### v0.1.27 — Cross-Platform CI

- **Added**: Windows CI test matrix. GitHub Actions now runs the full test suite on both `ubuntu-latest` and `windows-latest` across Python 3.9 and 3.12 (4 matrix jobs, `fail-fast: false`). Ensures cross-platform compatibility is validated on every push and pull request.

### v0.1.26 — Defence-in-Depth

- **Fixed**: Webhook POST now includes `User-Agent: AlterKS/{version}` and a UUID-based `X-Request-ID` header for request correlation. Some webhook receivers (Slack, Discord, enterprise proxies) reject or deprioritise requests without a recognisable User-Agent. The `X-Request-ID` aids debugging delivery issues across distributed systems.

### v0.1.25 — Maintainability Fix

- **Fixed**: Duplicate PEP 503 normalisation functions `config._normalise()` and `quarantine._normalise_name()` consolidated into a single `normalise_name()` in `models.py`. Both `config.py` and `quarantine.py` now import and use the shared function, eliminating the risk of the two implementations diverging and causing silent mismatches in allowlist/blocklist checks vs quarantine lookups.

### v0.1.24 — Security Fix

- **Fixed**: Webhook URL credentials leaking into log output (A09:2021 — Logging Failures). Added `_sanitize_url()` which strips userinfo (username/password) from URLs before logging, replacing them with `***@`. All `logger.info()` and `logger.warning()` calls that previously logged the raw `webhook_url` now use the sanitized form. A URL like `https://user:token@hooks.example.com/notify` is logged as `https://***@hooks.example.com/notify`.

### v0.1.23 — Bug Fix

- **Fixed**: `asyncio.run()` crashing with `RuntimeError` when called from an existing event loop (e.g. Jupyter notebooks, FastAPI, pytest-asyncio). `OSVClient.query_package()` and `query_batch()` now use a `_run_sync()` helper that detects a running event loop via `asyncio.get_running_loop()` and falls back to executing the coroutine in a dedicated daemon thread with its own event loop, avoiding the "cannot be called from a running event loop" error.

### v0.1.22 — Security Fix

- **Fixed**: `_write_json_report()` concurrent write corruption (A04:2021 — Insecure Design). Report file appends are now protected by an exclusive file lock using `msvcrt.locking(LK_NBLCK)` on Windows and `fcntl.flock(LOCK_EX | LOCK_NB)` on Unix, with a non-blocking retry loop and 10-second timeout. Multiple concurrent `alterks install` or `execute_action` calls writing to the same report file can no longer interleave mid-line and corrupt JSON-lines output.

### v0.1.21 — Security Fix

- **Fixed**: Stale lock file causing permanent deadlock in quarantine operations (A04:2021 — Insecure Design). `_ManifestLock` now uses **non-blocking** lock acquisition with a configurable timeout (default 30 s) and retry loop. The owning process PID is written into the lock file; on timeout, the lock holder’s PID is checked via `os.kill(pid, 0)` (Unix) or `OpenProcess` (Windows). If the owner is no longer running, the stale lock is automatically reset. Raises `LockAcquisitionError` with a clear message if the lock still cannot be obtained.

### v0.1.20 — Security Fix

- **Fixed**: DNS rebinding bypass in webhook SSRF validation (A10:2021 — SSRF). `validate_webhook_url()` now resolves hostnames to IP addresses via `socket.getaddrinfo()` and validates **all** resolved addresses against private, loopback, link-local, reserved, and cloud metadata blocklists. Previously, DNS names passed through without resolution, allowing an attacker to configure a domain that initially resolves to a public IP but rebinds to an internal address at request time.

### v0.1.19 — Usability Fix

- **Fixed**: `alterks monitor` termination producing an unhandled Python traceback instead of clean output. `KeyboardInterrupt` (Ctrl+C) is now caught gracefully, printing a "Monitor stopped by user" message and exiting cleanly.

### v0.1.18 — Design Fix

- **Fixed**: UNKNOWN severity vulnerabilities defaulting to ALLOW (design gap). Vulnerabilities with unresolved severity now default to `alert` instead of silently passing. The `unknown` severity mapping is fully configurable in `pyproject.toml` under `[tool.alterks]` — users can override to `block`, `quarantine`, or `allow`.
- **Changed**: Author in package metadata updated to "Ts Dr Wan Saifudin".

### v0.1.17 — Bug Fix

- **Fixed**: Quarantine manifest keyed by name only, causing version collisions (INFO finding). The manifest now uses composite keys (`name==version`), so multiple versions of the same package can be quarantined independently. The `inspect`, `release`, and `remove` commands accept an optional `--version` / `-v` flag to target a specific version. Backward-compatible name-only lookups find the first matching entry.

### v0.1.16 — Security Fix

- **Fixed**: Static typosquatting list goes stale (OWASP A04:2021 — Insecure Design). Added `alterks update-db` command to dynamically refresh the bundled top-5000 PyPI packages list from [hugovk.github.io/top-pypi-packages](https://hugovk.github.io/top-pypi-packages/). Fetches with TLS verification, writes a timestamped file, and invalidates the in-memory cache so subsequent scans use fresh data.

### v0.1.15 — Security Fix

- **Fixed**: Truncated SHA-256 cache key inviting birthday-attack collisions (OWASP A08:2021 — Software and Data Integrity Failures). Cache filenames now use the full 64-character SHA-256 hex digest instead of a 16-character truncation, eliminating practical collision risk.

### v0.1.14 — Security Fix

- **Fixed**: No rate limiting on PyPI requests (OWASP A05:2021 — Security Misconfiguration). Added a configurable `request_delay` (default 0.1 s) to `PyPIClient` with `time.monotonic()`-based throttling between consecutive HTTP requests. Prevents burst traffic that could trigger IP-level rate-limiting bans from PyPI. Cache hits bypass the throttle entirely.

### v0.1.13 — Security Fix

- **Fixed**: No explicit TLS verification enforcement (OWASP A02:2021 — Cryptographic Failures). All httpx clients now explicitly set `verify=True` — OSV API (`AsyncClient`), PyPI API (`Client`), and webhook POST. TLS certificate verification cannot be accidentally disabled or overridden.

### v0.1.12 — Security Fix

- **Fixed**: Broad `except Exception` blocks replaced with specific exception types (OWASP A09:2021 — Security Logging and Monitoring Failures). OSV errors now catch `OSVError`/`httpx.HTTPError`, heuristic failures catch `KeyError`/`TypeError`/`ValueError`/`ZeroDivisionError`, requirement parsing catches `InvalidRequirement`/`ValueError`. Internal logic bugs are no longer silently masked.

### v0.1.11 — Security Fix

- **Fixed**: `_parse_spec` argument injection in version string (OWASP A03:2021 — Injection). Replaced manual string splitting with `packaging.requirements.Requirement` for rigorous PEP 508 parsing. Parsed name and version are validated against strict regexes. Crafted specs like `pkg==1.0 --index-url=https://evil.com` are now rejected.
- **Changed**: License from MIT to **GNU General Public License v3 (GPL-3.0-only)**.

### v0.1.10 — Security Fix

- **Fixed**: Sensitive data sent to unverified webhook (OWASP A02:2021 — Cryptographic Failures). Webhook payloads are now signed with HMAC-SHA256 when a `webhook_secret` is configured (via config file or `--webhook-secret` CLI flag). The `X-AlterKS-Signature` header is included with each POST. Warnings are logged when sending over plain HTTP or without a secret.

### v0.1.9 — Security Fix

- **Fixed**: TOCTOU race condition in quarantine manifest operations (OWASP A04:2021 — Insecure Design). Manifest writes are now atomic via temp file + `os.replace()`. All read-modify-write operations are protected by a cross-platform file lock (`fcntl`/`msvcrt`), preventing concurrent data loss.

### v0.1.8 — Security Fix

- **Fixed**: PyPI cache poisoning via HMAC-SHA256 integrity verification (OWASP A08:2021 — Software and Data Integrity Failures). Cache entries are now signed with a machine-local secret key; tampered or unsigned entries are discarded and refetched. Cache directory created with restrictive permissions (0700 on Unix).

### v0.1.7 — Security Fix

- **Fixed**: Fail-open on OSV errors (OWASP A04:2021 — Insecure Design). Added `fail_closed` config option and `--fail-closed` CLI flag for `scan` and `install`. When enabled, OSV query failures result in `ALERT` instead of silently allowing packages through. Explicit warning logs emitted in both modes.

### v0.1.6 — Security Fix

- **Fixed**: `_remove_dir()` now enforces path containment — refuses to delete any directory that does not resolve inside the quarantine directory (OWASP A01:2021 — Broken Access Control). Prevents arbitrary directory deletion from a tampered manifest.

### v0.1.5 — Security Fix

- **Fixed**: Quarantine manifest deserialization now validates all JSON keys, field types, package names/versions, and ensures `venv_path` is safely contained under the quarantine directory (OWASP A08:2021 — Software and Data Integrity Failures). Tampered manifests with unknown fields or path traversal payloads are rejected.

### v0.1.4 — Security Fix

- **Fixed**: Webhook URL validation to prevent SSRF attacks (OWASP A10:2021 — SSRF). Rejects private/reserved IPs, cloud metadata endpoints, non-HTTPS URLs (except localhost), and dangerous schemes.

### v0.1.3 — Security Fix

- **Fixed**: Quarantine release now re-scans the package before installing into the main environment (OWASP A04:2021 — Insecure Design). If the package is still flagged, release is blocked unless `--force` is used.

### v0.1.2 — Security Fix

- **Fixed**: Pip argument injection via unsanitised package name/version in subprocess calls (OWASP A03:2021 — Injection). All subprocess-based pip invocations now validate inputs against a strict regex and use `--` to separate options from arguments.

### v0.1.1

- Removed Contributing section from package metadata.

### v0.1.0

- Initial release.

## License

GPL-3.0-only — see [LICENSE](LICENSE) for details.

## Support

If you appreciate this project, you can support its development through [Buy me a Coffee](https://buymeacoffee.com/wansaifudin).
