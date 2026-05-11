"""Tests for sentinel.scanners — Trivy/Semgrep output parsing."""

import pytest

from sentinel.scanners.trivy import TrivyScanner
from sentinel.scanners.semgrep import SemgrepScanner


class TestTrivyParser:
    """Test Trivy JSON output parsing."""

    def test_parse_results_with_vulnerabilities(self):
        """Should correctly parse Trivy JSON into normalized findings."""
        scanner = TrivyScanner(".")
        raw_data = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "Title": "Test Vulnerability",
                            "Description": "A test vuln",
                            "Severity": "HIGH",
                            "PkgName": "requests",
                            "InstalledVersion": "2.28.0",
                            "FixedVersion": "2.31.0",
                        }
                    ],
                }
            ]
        }
        findings = scanner._parse_results(raw_data)
        assert len(findings) == 1
        assert findings[0]["id"] == "CVE-2023-1234"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["package"] == "requests"
        assert findings[0]["fixed_version"] == "2.31.0"

    def test_parse_results_empty(self):
        """Should return empty list for no results."""
        scanner = TrivyScanner(".")
        findings = scanner._parse_results({"Results": []})
        assert findings == []

    def test_parse_results_no_vulns(self):
        """Should return empty list when results exist but have no vulnerabilities."""
        scanner = TrivyScanner(".")
        findings = scanner._parse_results({
            "Results": [{"Target": "requirements.txt", "Vulnerabilities": []}]
        })
        assert findings == []


class TestSemgrepParser:
    """Test Semgrep JSON output parsing."""

    def test_parse_results_with_findings(self):
        """Should correctly parse Semgrep JSON into normalized findings."""
        scanner = SemgrepScanner(".")
        raw_data = {
            "results": [
                {
                    "check_id": "python.lang.security.sql-injection",
                    "path": "app.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "Possible SQL injection\nMore details here",
                        "severity": "WARNING",
                    },
                }
            ]
        }
        findings = scanner._parse_results(raw_data)
        assert len(findings) == 1
        assert findings[0]["id"] == "python.lang.security.sql-injection"
        assert findings[0]["line"] == 42
        assert findings[0]["severity"] == "WARNING"
        # Title should be first line only, truncated
        assert "Possible SQL injection" in findings[0]["title"]

    def test_parse_results_empty(self):
        """Should return empty list for no results."""
        scanner = SemgrepScanner(".")
        findings = scanner._parse_results({"results": []})
        assert findings == []


class TestSemgrepPathTranslation:
    """Test WSL path translation."""

    def test_windows_to_wsl_path(self):
        scanner = SemgrepScanner(".")
        # Mock absolute path behavior
        result = scanner._wsl_to_windows_path("/mnt/c/Users/test/project")
        assert result == "C:\\Users\\test\\project"

    def test_wsl_to_windows_path_passthrough(self):
        scanner = SemgrepScanner(".")
        result = scanner._wsl_to_windows_path("/home/user/project")
        assert result == "/home/user/project"
