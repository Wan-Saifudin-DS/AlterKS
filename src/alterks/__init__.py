"""
AlterKS — ALTER KILL SWITCH

Python package scanner, monitor, and supply chain attack mitigation tool.
Scans, monitors, and blocks risky or vulnerable packages using OSV.dev
vulnerability data and PyPI metadata heuristics.
"""

__version__ = "0.2.3"
__all__ = [
    "PolicyAction",
    "Severity",
    "Vulnerability",
    "PackageRisk",
    "ScanResult",
    "AlterKSConfig",
]

from alterks.models import PackageRisk, PolicyAction, ScanResult, Severity, Vulnerability
from alterks.config import AlterKSConfig
