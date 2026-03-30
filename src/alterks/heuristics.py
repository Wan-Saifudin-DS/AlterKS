"""Heuristic risk scorer for Python packages.

Computes a composite risk score (0–100) by evaluating multiple signals from
PyPI metadata:

- **Typosquatting** — Levenshtein distance against a bundled list of popular
  PyPI package names, plus common substitution patterns.
- **Package age** — Packages first published very recently score higher.
- **Maintainer count** — Single-maintainer packages score higher.
- **Release pattern** — Few releases or very recent first release score higher.
- **Metadata quality** — Missing homepage, description, or classifiers score higher.

Weights are configurable via ``[tool.alterks]`` in ``pyproject.toml``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from alterks.config import AlterKSConfig, DEFAULT_HEURISTIC_WEIGHTS
from alterks.models import PackageRisk, RiskFactor
from alterks.sources.pypi import PyPIMetadata

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Top-package list for typosquatting
# ---------------------------------------------------------------------------

_TOP_PACKAGES: Optional[Set[str]] = None
_DATA_DIR = Path(__file__).resolve().parent / "data"


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

    Returns
    -------
    PackageRisk
        Risk assessment with individual factors and composite score (0–100).
    """
    weights = (config.heuristic_weights if config else None) or dict(DEFAULT_HEURISTIC_WEIGHTS)

    factors: List[RiskFactor] = []
    total_weighted = 0.0
    total_weight = 0.0

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
