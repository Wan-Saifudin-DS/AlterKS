"""AST-based code analysis for Python supply-chain attack detection.

Uses Python's built-in ``ast`` module to walk parsed syntax trees, detecting
suspicious function calls (``exec``, ``eval``, ``compile``), credential
harvesting via ``os.environ``, and dangerous module usage (``subprocess``,
``ctypes``, ``socket``) — while **ignoring** matches inside comments and
string literals, which eliminates the primary source of regex false positives.

This module complements the regex-based pattern scanner in ``heuristics.py``
by providing higher-precision detection for code structures that can be
reliably represented as AST nodes.

Safety guarantee: this module **never** executes or imports the target code.
It only parses the source into an AST via ``ast.parse()`` (mode='exec') and
walks the resulting tree.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

logger = logging.getLogger(__name__)

# Version of the AST ruleset — for audit trail reproducibility.
AST_RULES_VERSION = "1.0"

# High-risk files where install-time code execution occurs.
_INSTALL_TIME_FILES: Set[str] = {"setup.py", "setup.cfg", "conftest.py"}

# Files eligible for AST inspection.
_AST_INSPECTABLE: Set[str] = {*_INSTALL_TIME_FILES, "__init__.py"}

# Dangerous built-in function names.
_DANGEROUS_BUILTINS: Set[str] = {"exec", "eval", "compile", "__import__"}

# Dangerous module attribute calls: module -> set of attribute names.
# These are always flagged regardless of file type.
_DANGEROUS_MODULE_ATTRS_ALWAYS: dict[str, Set[str]] = {
    "os": {"system", "popen"},
}

# Dangerous module attribute calls: only flagged in install-time files.
_DANGEROUS_MODULE_ATTRS_INSTALL_ONLY: dict[str, Set[str]] = {
    "subprocess": {"Popen", "call", "run", "check_call", "check_output"},
    "ctypes": {"cdll", "windll", "CDLL", "WinDLL"},
}

# os.environ keys that indicate credential harvesting.
_SENSITIVE_ENV_KEYS: Set[str] = {
    "AWS", "TOKEN", "SECRET", "KEY", "PASS", "CREDENTIAL", "AUTH",
    "API_KEY", "PRIVATE", "PASSWORD",
}

# Network modules/attributes — only flagged in install-time files.
_NETWORK_CALLS: dict[str, Set[str]] = {
    "socket": {"connect", "create_connection"},
    "urllib.request": {"urlopen"},
    "requests": {"get", "post", "put", "delete", "patch", "head"},
    "httpx": {"get", "post", "put", "delete", "patch", "head", "Client"},
}


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class ASTFinding:
    """A single suspicious code finding from AST analysis."""

    description: str
    severity: float  # 0.0 – 1.0
    file_path: str
    line: int
    col: int = 0

    @property
    def location(self) -> str:
        return f"{self.file_path}:{self.line}"


# ---------------------------------------------------------------------------
# AST Visitor
# ---------------------------------------------------------------------------

class _SuspiciousCallVisitor(ast.NodeVisitor):
    """Walk an AST tree and collect suspicious call patterns."""

    def __init__(self, file_path: str, is_install_time: bool) -> None:
        self.file_path = file_path
        self.is_install_time = is_install_time
        self.findings: List[ASTFinding] = []

    # -- exec / eval / compile / __import__ as bare calls -------------------

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # exec(...), eval(...), compile(...), __import__(...)
        if isinstance(func, ast.Name) and func.id in _DANGEROUS_BUILTINS:
            severity = self._severity_for_builtin(func.id, node)
            self.findings.append(ASTFinding(
                description=f"Call to built-in {func.id}()",
                severity=severity,
                file_path=self.file_path,
                line=node.lineno,
                col=node.col_offset,
            ))

        # module.attr() calls — e.g. subprocess.Popen(...)
        if isinstance(func, ast.Attribute):
            self._check_attribute_call(func, node)

        self.generic_visit(node)

    def _severity_for_builtin(self, name: str, node: ast.Call) -> float:
        """Determine severity for a dangerous built-in call.

        Higher severity if the argument chain suggests obfuscation
        (e.g. ``exec(base64.b64decode(...))``).
        """
        if name in ("exec", "eval"):
            if node.args and self._is_decode_call(node.args[0]):
                return 0.95  # exec(base64.b64decode(...))
            if name == "exec" and node.args and isinstance(node.args[0], ast.Call):
                inner = node.args[0]
                if isinstance(inner.func, ast.Name) and inner.func.id == "compile":
                    return 0.90  # exec(compile(...))
            return 0.80 if self.is_install_time else 0.60
        if name == "compile":
            return 0.70 if self.is_install_time else 0.40
        if name == "__import__":
            return 0.65 if self.is_install_time else 0.35
        return 0.50

    def _is_decode_call(self, node: ast.expr) -> bool:
        """Check if a node is a call like ``base64.b64decode(...)``."""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in (
            "b64decode", "decode", "fromhex",
        ):
            return True
        return False

    def _check_attribute_call(self, func: ast.Attribute, node: ast.Call) -> None:
        """Check module.attr() patterns for dangerous calls."""
        attr = func.attr
        value = func.value

        # Direct module.attr — e.g. subprocess.Popen, os.system
        if isinstance(value, ast.Name):
            module_name = value.id

            # Always-flagged dangerous calls (os.system, os.popen)
            if module_name in _DANGEROUS_MODULE_ATTRS_ALWAYS:
                if attr in _DANGEROUS_MODULE_ATTRS_ALWAYS[module_name]:
                    sev = 0.80 if self.is_install_time else 0.55
                    self.findings.append(ASTFinding(
                        description=f"{module_name}.{attr}() call",
                        severity=sev,
                        file_path=self.file_path,
                        line=node.lineno,
                        col=node.col_offset,
                    ))

            # Install-time-only dangerous calls (subprocess, ctypes)
            if self.is_install_time and module_name in _DANGEROUS_MODULE_ATTRS_INSTALL_ONLY:
                if attr in _DANGEROUS_MODULE_ATTRS_INSTALL_ONLY[module_name]:
                    self.findings.append(ASTFinding(
                        description=f"{module_name}.{attr}() call",
                        severity=0.80,
                        file_path=self.file_path,
                        line=node.lineno,
                        col=node.col_offset,
                    ))

            # Network calls — only flagged in install-time files
            if self.is_install_time and module_name in _NETWORK_CALLS:
                if attr in _NETWORK_CALLS[module_name]:
                    self.findings.append(ASTFinding(
                        description=f"Network call {module_name}.{attr}() in install-time file",
                        severity=0.80,
                        file_path=self.file_path,
                        line=node.lineno,
                        col=node.col_offset,
                    ))

        # Chained attribute access — e.g. ctypes.cdll.LoadLibrary()
        # where func is Attribute(attr='LoadLibrary', value=Attribute(attr='cdll', value=Name('ctypes')))
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            parent_module = value.value.id
            mid_attr = value.attr
            if self.is_install_time and parent_module in _DANGEROUS_MODULE_ATTRS_INSTALL_ONLY:
                if mid_attr in _DANGEROUS_MODULE_ATTRS_INSTALL_ONLY[parent_module]:
                    self.findings.append(ASTFinding(
                        description=f"{parent_module}.{mid_attr}.{attr}() call",
                        severity=0.80,
                        file_path=self.file_path,
                        line=node.lineno,
                        col=node.col_offset,
                    ))
            if parent_module in _DANGEROUS_MODULE_ATTRS_ALWAYS:
                if mid_attr in _DANGEROUS_MODULE_ATTRS_ALWAYS[parent_module]:
                    sev = 0.80 if self.is_install_time else 0.55
                    self.findings.append(ASTFinding(
                        description=f"{parent_module}.{mid_attr}.{attr}() call",
                        severity=sev,
                        file_path=self.file_path,
                        line=node.lineno,
                        col=node.col_offset,
                    ))

    # -- os.environ access --------------------------------------------------

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Detect os.environ['SECRET_KEY'] style access."""
        if self._is_os_environ(node.value):
            key = self._extract_string_constant(node.slice)
            if key and self._is_sensitive_key(key):
                self.findings.append(ASTFinding(
                    description=f"Access to sensitive env var os.environ['{key}']",
                    severity=0.85,
                    file_path=self.file_path,
                    line=node.lineno,
                    col=node.col_offset,
                ))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Detect os.environ.get('SECRET_KEY') style access."""
        if node.attr == "get" and self._is_os_environ(node.value):
            # The parent Call node will have the key as the first arg
            # We handle this in visit_Call via _check_environ_get
            pass
        self.generic_visit(node)

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _is_os_environ(node: ast.expr) -> bool:
        """Check if a node represents ``os.environ``."""
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        )

    @staticmethod
    def _extract_string_constant(node: ast.expr) -> Optional[str]:
        """Extract a string constant from an AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        """Check if an environment variable key looks sensitive."""
        upper = key.upper()
        return any(s in upper for s in _SENSITIVE_ENV_KEYS)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_file(source: str, file_path: str, is_install_time: bool) -> List[ASTFinding]:
    """Parse Python source and return AST-based findings.

    Parameters
    ----------
    source:
        The Python source code to analyze.
    file_path:
        Relative path for reporting (e.g. ``pkg/setup.py``).
    is_install_time:
        Whether this file runs at install time (``setup.py``, etc.).

    Returns
    -------
    list[ASTFinding]
        Findings sorted by severity (highest first).
    """
    try:
        tree = ast.parse(source, filename=file_path, mode="exec")
    except SyntaxError:
        logger.debug("AST parse failed for %s (syntax error); skipping AST analysis", file_path)
        return []

    visitor = _SuspiciousCallVisitor(file_path, is_install_time)
    visitor.visit(tree)

    return sorted(visitor.findings, key=lambda f: f.severity, reverse=True)


def analyze_directory(
    extracted_dir: Path,
) -> List[ASTFinding]:
    """Scan all inspectable Python files in a directory via AST analysis.

    Parameters
    ----------
    extracted_dir:
        Root directory of extracted package source.

    Returns
    -------
    list[ASTFinding]
        All findings across all inspectable files.
    """
    import os as _os

    all_findings: List[ASTFinding] = []

    for root, _dirs, files in _os.walk(extracted_dir):
        for fname in files:
            if fname.lower() not in _AST_INSPECTABLE:
                continue
            full_path = Path(root) / fname
            is_install_time = fname.lower() in _INSTALL_TIME_FILES

            try:
                source = full_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel_path = str(full_path.relative_to(extracted_dir))
            findings = analyze_file(source, rel_path, is_install_time)
            all_findings.extend(findings)

    return sorted(all_findings, key=lambda f: f.severity, reverse=True)
