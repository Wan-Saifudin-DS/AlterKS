"""Heuristic risk scorer for Python packages.

Computes a composite risk score (0–100) by evaluating multiple signals from
PyPI metadata and (optionally) static source code analysis:

- **Typosquatting** — Levenshtein distance against a bundled list of popular
  PyPI package names, plus common substitution patterns.
- **Package age** — Packages first published very recently score higher.
- **Maintainer count** — Single-maintainer packages score higher.
- **Release pattern** — Few releases or very recent first release score higher.
- **Metadata quality** — Missing homepage, description, or classifiers score higher.
- **Code patterns** — Static regex analysis of ``setup.py`` / ``__init__.py``
  for known malicious patterns (obfuscated exec, credential theft, etc.).

Weights are configurable via ``[tool.alterks]`` in ``pyproject.toml``.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import httpx

from alterks.config import AlterKSConfig, DEFAULT_HEURISTIC_WEIGHTS
from alterks.models import PackageRisk, RiskFactor
from alterks.sources.pypi import PyPIMetadata

logger = logging.getLogger(__name__)

# Pattern ruleset version — included in reports for audit trail reproducibility.
CODE_PATTERNS_VERSION = "1.1"

# ---------------------------------------------------------------------------
# Top-package list for typosquatting
# ---------------------------------------------------------------------------

_TOP_PACKAGES: Optional[Set[str]] = None
_DATA_DIR = Path(__file__).resolve().parent / "data"

TOP_PYPI_PACKAGES_URL = (
    "https://hugovk.github.io/top-pypi-packages/"
    "top-pypi-packages-30-days.min.json"
)
TOP_PACKAGES_COUNT = 5000


def _load_top_packages() -> Set[str]:
    """Load the bundled top-packages list (lazy, cached)."""
    global _TOP_PACKAGES
    if _TOP_PACKAGES is not None:
        return _TOP_PACKAGES

    path = _DATA_DIR / "top_packages.txt"
    names: Set[str] = set()
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                names.add(line.lower())
    _TOP_PACKAGES = names
    return _TOP_PACKAGES


def refresh_top_packages(
    url: str = TOP_PYPI_PACKAGES_URL,
    count: int = TOP_PACKAGES_COUNT,
    timeout: float = 30.0,
    max_redirects: int = 5,
) -> int:
    """Fetch the latest top-packages list from *url* and update the bundled file.

    Returns the number of package names written.

    Parameters
    ----------
    timeout:
        Per-request timeout in seconds (connect, read, write, pool).
    max_redirects:
        Maximum number of HTTP redirects to follow.  Prevents a
        malicious or misconfigured server from stalling the client
        with an unbounded redirect chain.

    Raises
    ------
    httpx.HTTPError
        On network/HTTP failures.
    httpx.TooManyRedirects
        If the server exceeds *max_redirects*.
    ValueError
        If the response cannot be parsed.
    """
    global _TOP_PACKAGES

    with httpx.Client(
        timeout=timeout,
        verify=True,
        max_redirects=max_redirects,
    ) as client:
        resp = client.get(url, follow_redirects=True)
    resp.raise_for_status()

    data = resp.json()
    rows = data.get("rows")
    if not isinstance(rows, list):
        raise ValueError("Unexpected JSON structure: missing 'rows' list")

    names: list[str] = []
    for row in rows[:count]:
        project = row.get("project")
        if isinstance(project, str) and project.strip():
            names.append(project.strip().lower())

    if not names:
        raise ValueError("No package names found in response")

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    header = (
        f"# Top {len(names)} PyPI packages for typosquatting detection.\n"
        f"# Source: {url}\n"
        f"# Last updated: {now}\n"
        "# One package name per line, lowercase.\n"
    )
    path = _DATA_DIR / "top_packages.txt"
    path.write_text(header + "\n".join(names) + "\n", encoding="utf-8")

    # Invalidate in-memory cache so next _load_top_packages() re-reads
    _TOP_PACKAGES = None

    logger.info("Updated top-packages list: %d packages written", len(names))
    return len(names)


# ---------------------------------------------------------------------------
# Levenshtein distance (pure-Python, no C dependency)
# ---------------------------------------------------------------------------

def _levenshtein(s: str, t: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if not s:
        return len(t)
    if not t:
        return len(s)
    m, n = len(s), len(t)
    # Optimise: only keep two rows
    prev = list(range(n + 1))
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        curr[0] = i
        for j in range(1, n + 1):
            cost = 0 if s[i - 1] == t[j - 1] else 1
            curr[j] = min(
                prev[j] + 1,      # deletion
                curr[j - 1] + 1,  # insertion
                prev[j - 1] + cost,  # substitution
            )
        prev, curr = curr, prev
    return prev[n]


# ---------------------------------------------------------------------------
# Typosquatting detection
# ---------------------------------------------------------------------------

# Common prefix/suffix attacks
_PREFIX_PATTERNS = re.compile(
    r"^(python-|python3-|py-|pip-|lib-|easy-|super-|real-|better-|fast-|ultra-)"
)
_SUFFIX_PATTERNS = re.compile(
    r"(-python|python|3|-lib|-sdk|-api|-client|-utils|-tool|-helper)$"
)

# Common character substitutions (confusables)
_SUBSTITUTIONS = [
    ("0", "o"), ("o", "0"),
    ("1", "l"), ("l", "1"), ("l", "i"), ("i", "l"),
    ("rn", "m"), ("m", "rn"),
    ("-", "_"), ("_", "-"), (".", "-"), ("-", "."),
]


def _typosquat_score(name: str, top_packages: Set[str]) -> tuple[float, str]:
    """Compute a normalised typosquatting score (0.0–1.0) for *name*.

    Returns ``(score, reason)`` where score 0.0 means no risk.
    """
    normalised = name.lower().replace("-", "").replace("_", "").replace(".", "")

    # Exact match → not a typosquat
    if name.lower() in top_packages:
        return 0.0, ""

    # Normalised match (dash/underscore/dot equivalence per PEP 503)
    top_normalised = {p.replace("-", "").replace("_", "").replace(".", "") for p in top_packages}
    if normalised in top_normalised:
        return 0.0, ""

    best_dist = float("inf")
    best_match = ""

    # 1. Check raw Levenshtein distance against top packages
    for pkg in top_packages:
        pkg_norm = pkg.replace("-", "").replace("_", "").replace(".", "")
        dist = _levenshtein(normalised, pkg_norm)
        if dist < best_dist:
            best_dist = dist
            best_match = pkg

    # 2. Check prefix/suffix stripping attacks
    stripped = _PREFIX_PATTERNS.sub("", name.lower())
    stripped = _SUFFIX_PATTERNS.sub("", stripped)
    if stripped != name.lower() and stripped in top_packages:
        return 0.9, f"Name resembles '{stripped}' with added prefix/suffix"

    # 3. Check common character substitutions
    for old, new in _SUBSTITUTIONS:
        variant = name.lower().replace(old, new)
        if variant != name.lower() and variant in top_packages:
            return 0.85, f"Name resembles '{variant}' via character substitution"

    # 4. Score based on edit distance
    if best_dist == 0:
        return 0.0, ""  # normalised forms match exactly (dash/underscore variant)
    elif best_dist == 1:
        return 0.8, f"Edit distance 1 from '{best_match}'"
    elif best_dist == 2:
        return 0.5, f"Edit distance 2 from '{best_match}'"
    elif best_dist == 3 and len(normalised) <= 8:
        return 0.3, f"Edit distance 3 from '{best_match}' (short name)"

    return 0.0, ""


# ---------------------------------------------------------------------------
# Individual heuristic scorers — each returns (score 0.0–1.0, reason)
# ---------------------------------------------------------------------------

def _score_typosquatting(name: str) -> tuple[float, str]:
    top = _load_top_packages()
    return _typosquat_score(name, top)


def _score_package_age(meta: PyPIMetadata) -> tuple[float, str]:
    """Score risk based on package age. Newer packages are riskier."""
    age = meta.age_days
    if age is None:
        return 0.5, "Unable to determine package age"
    if age < 7:
        return 1.0, f"Package is only {age} days old"
    if age < 30:
        return 0.7, f"Package is {age} days old (< 30 days)"
    if age < 90:
        return 0.3, f"Package is {age} days old (< 90 days)"
    if age < 365:
        return 0.1, f"Package is {age} days old (< 1 year)"
    return 0.0, f"Package is {age} days old"


def _score_maintainer_count(meta: PyPIMetadata) -> tuple[float, str]:
    """Score risk based on maintainer count. Fewer maintainers = riskier."""
    count = meta.maintainer_count
    if count <= 1:
        return 0.7, "Single maintainer"
    if count == 2:
        return 0.3, "Only 2 maintainers"
    return 0.0, f"{count} maintainers"


def _score_release_pattern(meta: PyPIMetadata) -> tuple[float, str]:
    """Score risk based on release history pattern."""
    count = meta.release_count
    if count == 0:
        return 0.8, "No releases found"
    if count == 1:
        return 0.7, "Only 1 release"
    if count == 2:
        return 0.4, "Only 2 releases"

    # Check if all releases are very recent (potential spam/takeover)
    age = meta.age_days
    if age is not None and age < 7 and count > 3:
        return 0.8, f"{count} releases in {age} days (burst pattern)"

    return 0.0, f"{count} releases"


def _score_metadata_quality(meta: PyPIMetadata) -> tuple[float, str]:
    """Score risk based on metadata completeness."""
    issues: List[str] = []

    if not meta.has_homepage:
        issues.append("no homepage")
    if not meta.has_description:
        issues.append("no/short description")
    if not meta.classifiers:
        issues.append("no classifiers")
    if not meta.summary:
        issues.append("no summary")
    if not meta.author and not meta.maintainer:
        issues.append("no author info")

    if not issues:
        return 0.0, "Metadata looks complete"

    score = min(1.0, len(issues) * 0.25)
    return score, f"Missing: {', '.join(issues)}"


# ---------------------------------------------------------------------------
# Code pattern detection (static source analysis)
# ---------------------------------------------------------------------------

# High-risk files where install-time code execution occurs
_INSTALL_TIME_FILES = {"setup.py", "setup.cfg", "conftest.py"}

# Files to inspect in any package
_INSPECTABLE_FILES = {*_INSTALL_TIME_FILES, "__init__.py"}

# Suspicious patterns — each is (compiled_regex, severity 0.0–1.0, description)
_SUSPICIOUS_PATTERNS: List[Tuple[re.Pattern[str], float, str]] = [
    # Obfuscated execution
    (re.compile(
        r"(?:exec|eval|compile)\s*\(\s*(?:base64\.b64decode|codecs\.decode|"
        r"bytes\.fromhex|bytearray\.fromhex)",
        re.IGNORECASE,
    ), 0.95, "exec/eval with obfuscated input (base64/hex decode)"),

    # Direct exec of compile — common in install-time code injection
    (re.compile(
        r"exec\s*\(\s*compile\s*\(",
        re.IGNORECASE,
    ), 0.85, "exec(compile(...)) — dynamic code compilation"),

    # Credential harvesting via environment variables
    (re.compile(
        r"os\.environ\b.*(?:AWS|TOKEN|SECRET|KEY|PASS|CREDENTIAL|AUTH)",
        re.IGNORECASE,
    ), 0.80, "Access to sensitive environment variables"),

    # Network calls in install-time files (setup.py)
    (re.compile(
        r"(?:socket\.(?:connect|create_connection)|"
        r"urllib\.request\.urlopen|"
        r"requests\.(?:get|post|put)|"
        r"httpx\.(?:get|post|put|Client))",
        re.IGNORECASE,
    ), 0.75, "Network call detected"),

    # Subprocess execution
    (re.compile(
        r"subprocess\.(?:Popen|call|run|check_call|check_output)\s*\(",
    ), 0.70, "Subprocess execution"),

    # Native code loading
    (re.compile(
        r"ctypes\.(?:cdll|windll|CDLL|WinDLL)\b",
    ), 0.70, "Native code loading via ctypes"),

    # Large hex-escaped strings (potential obfuscated URLs/payloads)
    (re.compile(
        r"(?:\\x[0-9a-fA-F]{2}){20,}",
    ), 0.75, "Large hex-escaped string (possible obfuscated payload)"),

    # Large base64 blobs inline
    (re.compile(
        r"""(?:"|')(?:[A-Za-z0-9+/]{100,})={0,2}(?:"|')""",
    ), 0.60, "Large base64-encoded string literal"),
]


def _score_code_patterns(
    extracted_dir: Optional[Path],
) -> Tuple[float, str, Optional[str], Optional[str]]:
    """Scan extracted source files for suspicious code patterns.

    Uses a two-pass approach:
    1. **Regex pass** — fast pattern matching for obfuscated payloads,
       hex-escaped strings, and large base64 blobs that cannot be
       represented as AST nodes.
    2. **AST pass** — precise detection of function calls (``exec``,
       ``eval``, ``subprocess.Popen``, etc.) that ignores comments
       and string literals, reducing false positives.

    The final score is the maximum of both passes. AST findings are
    preferred for reporting when they match, since they provide more
    precise location information.

    Returns ``(score, reason, file_path, line_range)`` where score 0.0
    means no risk.
    """
    if extracted_dir is None:
        return 0.0, "", None, None

    py_files = _find_inspectable_files(extracted_dir)

    if not py_files:
        return 0.0, "No Python source files to analyze", None, None

    # --- Pass 1: Regex-based detection (hex blobs, base64, obfuscation) ---
    regex_score, regex_reason, regex_file, regex_lines, regex_count = (
        _regex_scan(extracted_dir, py_files)
    )

    # --- Pass 2: AST-based detection (structural analysis) ---
    from alterks.ast_analyzer import analyze_directory

    ast_findings = analyze_directory(extracted_dir)
    ast_score = 0.0
    ast_reason = ""
    ast_file: Optional[str] = None
    ast_lines: Optional[str] = None
    ast_count = len(ast_findings)

    if ast_findings:
        top = ast_findings[0]
        ast_score = top.severity
        ast_reason = f"{top.description} in {top.location}"
        ast_file = top.file_path
        ast_lines = str(top.line)

        # Escalate if multiple distinct AST findings
        if ast_count >= 3:
            ast_score = min(1.0, ast_score + 0.1)

        if ast_count > 1:
            ast_reason += f" (+{ast_count - 1} more finding(s))"

    # --- Combine: take whichever pass produced a higher score ---
    total_findings = regex_count + ast_count

    if ast_score >= regex_score and ast_score > 0:
        best_score = ast_score
        best_reason = ast_reason
        best_file = ast_file
        best_lines = ast_lines
    elif regex_score > 0:
        best_score = regex_score
        best_reason = regex_reason
        best_file = regex_file
        best_lines = regex_lines
    else:
        return 0.0, "No suspicious code patterns detected", None, None

    # Cross-pass escalation: if both passes found issues, boost
    if regex_count > 0 and ast_count > 0:
        best_score = min(1.0, best_score + 0.05)

    return best_score, best_reason, best_file, best_lines


def _regex_scan(
    extracted_dir: Path,
    py_files: List[Path],
) -> Tuple[float, str, Optional[str], Optional[str], int]:
    """Run regex-based pattern matching on inspectable files.

    Returns ``(score, reason, file_path, line_range, finding_count)``.
    """
    best_score = 0.0
    best_reason = ""
    best_file: Optional[str] = None
    best_lines: Optional[str] = None
    all_findings: List[str] = []

    for py_path in py_files:
        basename = py_path.name.lower()
        is_install_time = basename in _INSTALL_TIME_FILES

        try:
            content = py_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for pattern, severity, description in _SUSPICIOUS_PATTERNS:
            # Network calls and subprocess are only flagged in install-time files
            if not is_install_time and description in (
                "Network call detected",
                "Subprocess execution",
            ):
                continue

            for match in pattern.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                rel_path = str(py_path.relative_to(extracted_dir))

                # Boost severity for install-time files
                effective = min(1.0, severity + 0.1) if is_install_time else severity

                finding = f"{description} in {rel_path}:{line_no}"
                all_findings.append(finding)

                if effective > best_score:
                    best_score = effective
                    best_reason = finding
                    best_file = rel_path
                    best_lines = str(line_no)

    if not all_findings:
        return 0.0, "", None, None, 0

    # Escalate if multiple distinct patterns found
    if len(all_findings) >= 3:
        best_score = min(1.0, best_score + 0.1)

    summary = best_reason
    if len(all_findings) > 1:
        summary += f" (+{len(all_findings) - 1} more finding(s))"

    return best_score, summary, best_file, best_lines, len(all_findings)


def _find_inspectable_files(extracted_dir: Path) -> List[Path]:
    """Find Python files eligible for code pattern inspection.

    Only inspects files whose basenames are in ``_INSPECTABLE_FILES``
    to limit scope and avoid false positives from application code.
    """
    results: List[Path] = []
    for root, _dirs, files in os.walk(extracted_dir):
        for fname in files:
            if fname.lower() in _INSPECTABLE_FILES:
                results.append(Path(root) / fname)
    return results


import os  # noqa: E402 — grouped with walk usage above


# ---------------------------------------------------------------------------
# Composite risk scorer
# ---------------------------------------------------------------------------

_HEURISTIC_SCORERS = {
    "typosquatting": lambda name, meta: _score_typosquatting(name),
    "package_age": lambda name, meta: _score_package_age(meta),
    "maintainer_count": lambda name, meta: _score_maintainer_count(meta),
    "release_pattern": lambda name, meta: _score_release_pattern(meta),
    "metadata_quality": lambda name, meta: _score_metadata_quality(meta),
}


def compute_risk(
    name: str,
    version: str,
    metadata: PyPIMetadata,
    config: Optional[AlterKSConfig] = None,
    extracted_dir: Optional[Path] = None,
) -> PackageRisk:
    """Compute a composite heuristic risk score for a package.

    Parameters
    ----------
    name:
        Package name.
    version:
        Package version.
    metadata:
        Parsed PyPI metadata.
    config:
        AlterKS configuration (for custom weights).  Uses defaults when *None*.
    extracted_dir:
        Path to extracted package source for code pattern analysis.
        When *None*, the ``code_patterns`` heuristic is skipped.

    Returns
    -------
    PackageRisk
        Risk assessment with individual factors and composite score (0–100).
    """
    weights = (config.heuristic_weights if config else None) or dict(DEFAULT_HEURISTIC_WEIGHTS)

    factors: List[RiskFactor] = []
    total_weighted = 0.0
    total_weight = 0.0

    # Run metadata-based scorers
    for heuristic_name, scorer in _HEURISTIC_SCORERS.items():
        weight = weights.get(heuristic_name, 0.0)
        if weight <= 0:
            continue

        score, reason = scorer(name, metadata)
        factors.append(RiskFactor(
            name=heuristic_name,
            score=score,
            weight=weight,
            reason=reason,
        ))
        total_weighted += score * weight
        total_weight += weight

    # Run code pattern scorer (closure captures extracted_dir)
    code_weight = weights.get("code_patterns", 0.0)
    if code_weight > 0:
        cp_score, cp_reason, cp_file, cp_lines = _score_code_patterns(
            extracted_dir
        )
        factors.append(RiskFactor(
            name="code_patterns",
            score=cp_score,
            weight=code_weight,
            reason=cp_reason,
            file_path=cp_file,
            line_range=cp_lines,
        ))
        total_weighted += cp_score * code_weight
        total_weight += code_weight

    # Normalise to 0–100
    if total_weight > 0:
        composite = (total_weighted / total_weight) * 100.0
    else:
        composite = 0.0

    return PackageRisk(
        name=name,
        version=version,
        risk_score=round(composite, 1),
        risk_factors=factors,
    )
