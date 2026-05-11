"""Configuration loading and saving.

Reads from sentinel.yaml with environment variable fallback.
Manages API keys, LLM provider selection, and rate-limit settings.
"""

import os
import yaml


class Config:
    """Central configuration for Sentinel."""

    def __init__(self, config_path="sentinel.yaml"):
        self.config_path = config_path
        self.data = self._load_config()

        # Keys prioritized by YAML, then Env
        self.openai_api_key = self.data.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")
        self.gemini_api_key = self.data.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY")
        self.anthropic_api_key = self.data.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
        self.github_token = self.data.get("github_token") or os.environ.get("GITHUB_TOKEN")
        self.default_llm = self.data.get("default_llm", "openai")
        self.default_model = self.data.get("default_model", "")

        # Rate limiting & batching
        self.requests_per_minute = self.data.get("requests_per_minute", 10)
        self.batch_size = self.data.get("batch_size", 5)

    def _load_config(self):
        """Load configuration from YAML file."""
        if os.path.exists(self.config_path):
            with open(self.config_path, "r") as f:
                try:
                    return yaml.safe_load(f) or {}
                except Exception:
                    return {}
        return {}

    def save(self):
        """Persist current configuration to YAML file."""
        config_data = {
            "openai_api_key": self.openai_api_key,
            "gemini_api_key": self.gemini_api_key,
            "anthropic_api_key": self.anthropic_api_key,
            "github_token": self.github_token,
            "default_llm": self.default_llm,
            "default_model": self.default_model,
            "requests_per_minute": self.requests_per_minute,
            "batch_size": self.batch_size,
        }
        with open(self.config_path, "w") as f:
            yaml.dump(config_data, f)

    def check_environment(self):
        """Validate that the environment is ready for scanning.

        Returns:
            list: A list of issue description strings. Empty if everything is OK.
        """
        issues = []
        if not any([self.openai_api_key, self.gemini_api_key, self.anthropic_api_key]):
            issues.append("No AI API Keys found (OpenAI, Gemini, or Anthropic).")
        return issues
