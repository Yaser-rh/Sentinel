"""Tests for sentinel.orchestrator — severity filtering and suppression logic."""

import pytest

from sentinel.orchestrator import Orchestrator


class TestSeverityFilter:
    """Test the severity matching logic."""

    def test_all_matches_everything(self):
        assert Orchestrator._severity_matches("LOW", "ALL") is True
        assert Orchestrator._severity_matches("CRITICAL", "ALL") is True

    def test_high_filter(self):
        assert Orchestrator._severity_matches("CRITICAL", "HIGH") is True
        assert Orchestrator._severity_matches("HIGH", "HIGH") is True
        assert Orchestrator._severity_matches("MEDIUM", "HIGH") is False
        assert Orchestrator._severity_matches("LOW", "HIGH") is False

    def test_critical_filter(self):
        assert Orchestrator._severity_matches("CRITICAL", "CRITICAL") is True
        assert Orchestrator._severity_matches("HIGH", "CRITICAL") is False

    def test_case_insensitive(self):
        assert Orchestrator._severity_matches("critical", "high") is True
        assert Orchestrator._severity_matches("low", "ALL") is True

    def test_unknown_severity(self):
        assert Orchestrator._severity_matches("UNKNOWN", "HIGH") is False
        assert Orchestrator._severity_matches("UNKNOWN", "ALL") is True
