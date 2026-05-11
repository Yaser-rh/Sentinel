"""Tests for sentinel.ai — prompt building and response parsing."""

import json

import pytest

from sentinel.ai.prompts import build_single_prompt, build_batch_prompt
from sentinel.ai.client import AIClient


class TestPromptBuilding:
    """Test prompt template generation."""

    def test_single_prompt_contains_vuln_data(self):
        vuln = {
            "id": "CVE-2023-1234",
            "title": "Test Vuln",
            "severity": "HIGH",
            "package": "requests",
        }
        prompt = build_single_prompt(vuln, "import requests\nrequests.get(url)")
        assert "CVE-2023-1234" in prompt
        assert "requests" in prompt
        assert "True Positive" in prompt
        assert "False Positive" in prompt

    def test_single_prompt_includes_project_context(self):
        vuln = {"id": "CVE-2023-1234"}
        prompt = build_single_prompt(vuln, "code here", project_context="Flask app, 50 files")
        assert "Flask app" in prompt

    def test_batch_prompt_includes_all_packages(self):
        groups = [
            {"package": "requests", "version": "2.28.0", "cve_ids": ["CVE-1"], "usage_context": "used in api.py"},
            {"package": "pyyaml", "version": "5.4", "cve_ids": ["CVE-2", "CVE-3"], "usage_context": "used in config.py"},
        ]
        prompt = build_batch_prompt(groups)
        assert "requests" in prompt
        assert "pyyaml" in prompt
        assert "CVE-1" in prompt
        assert "CVE-2" in prompt
        assert "exactly 2 objects" in prompt

    def test_batch_prompt_includes_project_context(self):
        groups = [{"package": "flask", "version": "2.0", "cve_ids": ["CVE-1"], "usage_context": ""}]
        prompt = build_batch_prompt(groups, project_context="Django app")
        assert "Django app" in prompt


class TestAIClientInit:
    """Test AIClient initialization without actual API calls."""

    def test_defaults_when_no_model(self):
        class MockConfig:
            default_llm = "openai"
            default_model = ""
            openai_api_key = None
            gemini_api_key = None
            anthropic_api_key = None
            requests_per_minute = 10
            batch_size = 5

        client = AIClient(MockConfig())
        assert client.model_name == "gpt-3.5-turbo"
        assert client.provider == "openai"

    def test_no_key_returns_unknown(self):
        class MockConfig:
            default_llm = "openai"
            default_model = "gpt-4"
            openai_api_key = None
            gemini_api_key = None
            anthropic_api_key = None
            requests_per_minute = 10
            batch_size = 5

        client = AIClient(MockConfig())
        result = client.verify_finding({"id": "CVE-123"}, "code")
        assert result["status"] == "Unknown"
        assert "No API Key" in result["reason"]

    def test_batch_no_key_returns_unknowns(self):
        class MockConfig:
            default_llm = "gemini"
            default_model = "gemini-1.5-flash"
            openai_api_key = None
            gemini_api_key = None
            anthropic_api_key = None
            requests_per_minute = 10
            batch_size = 5

        client = AIClient(MockConfig())
        groups = [{"package": "flask"}, {"package": "requests"}]
        results = client.verify_batch(groups)
        assert len(results) == 2
        assert all(r["status"] == "Unknown" for r in results)
