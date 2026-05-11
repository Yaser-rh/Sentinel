"""Tests for sentinel.config — YAML loading, env var fallback, save/load cycle."""

import os
import tempfile

import pytest

from sentinel.config import Config


class TestConfigLoading:
    """Test configuration loading from YAML and environment."""

    def test_default_values_when_no_file(self, tmp_path):
        """Config should use defaults when no YAML file exists."""
        cfg = Config(config_path=str(tmp_path / "nonexistent.yaml"))
        assert cfg.default_llm == "openai"
        assert cfg.default_model == ""
        assert cfg.requests_per_minute == 10
        assert cfg.batch_size == 5

    def test_load_from_yaml(self, tmp_path):
        """Config should load values from a YAML file."""
        yaml_path = tmp_path / "sentinel.yaml"
        yaml_path.write_text(
            "default_llm: gemini\n"
            "default_model: gemini-1.5-flash\n"
            "gemini_api_key: test-key-123\n"
        )
        cfg = Config(config_path=str(yaml_path))
        assert cfg.default_llm == "gemini"
        assert cfg.default_model == "gemini-1.5-flash"
        assert cfg.gemini_api_key == "test-key-123"

    def test_env_var_fallback(self, tmp_path, monkeypatch):
        """Config should fall back to env vars when YAML values are missing."""
        monkeypatch.setenv("OPENAI_API_KEY", "env-key-456")
        cfg = Config(config_path=str(tmp_path / "nonexistent.yaml"))
        assert cfg.openai_api_key == "env-key-456"

    def test_yaml_takes_priority_over_env(self, tmp_path, monkeypatch):
        """YAML values should take priority over environment variables."""
        monkeypatch.setenv("OPENAI_API_KEY", "env-key")
        yaml_path = tmp_path / "sentinel.yaml"
        yaml_path.write_text("openai_api_key: yaml-key\n")
        cfg = Config(config_path=str(yaml_path))
        assert cfg.openai_api_key == "yaml-key"


class TestConfigSave:
    """Test configuration saving."""

    def test_save_and_reload(self, tmp_path):
        """Saved config should be loadable."""
        yaml_path = tmp_path / "sentinel.yaml"
        cfg = Config(config_path=str(yaml_path))
        cfg.default_llm = "anthropic"
        cfg.default_model = "claude-3-haiku"
        cfg.save()

        cfg2 = Config(config_path=str(yaml_path))
        assert cfg2.default_llm == "anthropic"
        assert cfg2.default_model == "claude-3-haiku"


class TestCheckEnvironment:
    """Test environment validation."""

    def test_no_keys_reports_issue(self, tmp_path):
        """Should report an issue when no API keys are set."""
        cfg = Config(config_path=str(tmp_path / "nonexistent.yaml"))
        issues = cfg.check_environment()
        assert len(issues) == 1
        assert "No AI API Keys" in issues[0]

    def test_with_key_no_issues(self, tmp_path):
        """Should report no issues when at least one API key is set."""
        yaml_path = tmp_path / "sentinel.yaml"
        yaml_path.write_text("gemini_api_key: some-key\n")
        cfg = Config(config_path=str(yaml_path))
        issues = cfg.check_environment()
        assert len(issues) == 0
