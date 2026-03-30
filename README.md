# AlterKS — ALTER KILL SWITCH

[![PyPI version](https://img.shields.io/pypi/v/alterks)](https://pypi.org/project/alterks/)
[![Python](https://img.shields.io/pypi/pyversions/alterks)](https://pypi.org/project/alterks/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
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

MIT — see [LICENSE](LICENSE) for details.
