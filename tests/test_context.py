"""Tests for sentinel.analysis.context — import detection and snippet extraction."""

import os
import textwrap

import pytest

from sentinel.analysis.context import ContextAnalyzer


@pytest.fixture
def sample_project(tmp_path):
    """Create a minimal Python project for testing."""
    app_py = tmp_path / "app.py"
    app_py.write_text(textwrap.dedent("""\
        import flask
        from flask import Flask, request
        import yaml

        app = Flask(__name__)

        @app.route("/")
        def index():
            data = yaml.safe_load(request.data)
            return str(data)
    """))

    utils_py = tmp_path / "utils.py"
    utils_py.write_text(textwrap.dedent("""\
        import os
        import json

        def read_config(path):
            with open(path) as f:
                return json.load(f)
    """))

    return tmp_path


class TestCheckImport:
    """Test AST-based import detection."""

    def test_detects_direct_import(self, sample_project):
        ctx = ContextAnalyzer(str(sample_project))
        assert ctx.check_import("flask") is True

    def test_detects_pypi_name_mapping(self, sample_project):
        """Should find 'yaml' import when searching for PyPI name 'pyyaml'."""
        ctx = ContextAnalyzer(str(sample_project))
        assert ctx.check_import("pyyaml") is True

    def test_missing_import_returns_false(self, sample_project):
        ctx = ContextAnalyzer(str(sample_project))
        assert ctx.check_import("django") is False

    def test_handles_empty_directory(self, tmp_path):
        ctx = ContextAnalyzer(str(tmp_path))
        assert ctx.check_import("flask") is False


class TestGetSnippet:
    """Test code snippet extraction."""

    def test_extracts_snippet_around_line(self, sample_project):
        ctx = ContextAnalyzer(str(sample_project))
        app_path = str(sample_project / "app.py")
        snippet = ctx.get_snippet(app_path, 5, context_lines=2)
        assert "Flask" in snippet
        assert len(snippet.strip().split("\n")) <= 5

    def test_nonexistent_file_returns_empty(self, sample_project):
        ctx = ContextAnalyzer(str(sample_project))
        snippet = ctx.get_snippet("/nonexistent/file.py", 1)
        assert snippet == ""


class TestFindPackageUsage:
    """Test per-package usage analysis."""

    def test_finds_import_locations(self, sample_project):
        ctx = ContextAnalyzer(str(sample_project))
        usage = ctx.find_package_usage("flask")
        assert "flask" in usage.lower()
        assert "app.py" in usage

    def test_not_imported_package(self, sample_project):
        ctx = ContextAnalyzer(str(sample_project))
        usage = ctx.find_package_usage("django")
        assert "not directly imported" in usage.lower()
