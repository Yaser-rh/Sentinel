"""CLI commands: sentinel config / sentinel config-check.

Handles interactive API key setup, model selection, API testing,
and environment validation.
"""

import os

import click

import sys
from pathlib import Path

from ..config import Config

# tools/ is a top-level directory outside the sentinel package
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from tools.installer import install_trivy, install_semgrep


@click.command("config")
def config_cmd():
    """Setup API keys and install security tools."""
    cfg = Config()
    click.echo("\n--- Sentinel Configuration Setup ---")

    default_llm = click.prompt("Select default LLM (openai/gemini/anthropic)", default=cfg.default_llm)

    gemini_key = cfg.gemini_api_key
    anthropic_key = cfg.anthropic_api_key
    openai_key = cfg.openai_api_key
    default_model = cfg.default_model

    if default_llm == "gemini":
        gemini_key = click.prompt("Enter Gemini API Key", default=gemini_key or "", show_default=True)
        default_model = _select_model("gemini", gemini_key) or default_model
        if click.confirm("Do you want to test this API key now?", default=True):
            _test_api("gemini", gemini_key, default_model)
    elif default_llm == "anthropic":
        anthropic_key = click.prompt("Enter Anthropic API Key", default=anthropic_key or "", show_default=True)
        default_model = _select_model("anthropic", anthropic_key) or default_model
        if click.confirm("Do you want to test this API key now?", default=True):
            _test_api("anthropic", anthropic_key, default_model)
    elif default_llm == "openai":
        openai_key = click.prompt("Enter OpenAI API Key", default=openai_key or "", show_default=True)
        default_model = _select_model("openai", openai_key) or default_model
        if click.confirm("Do you want to test this API key now?", default=True):
            _test_api("openai", openai_key, default_model)

    bin_dir = os.path.join(os.getcwd(), "bin")

    click.echo(f"\nConfiguration Summary:")
    click.echo(f"  Default LLM: {default_llm}")
    click.echo(f"  Model Version: {default_model}")
    click.echo(f"  Gemini API: {'*' * 8 + gemini_key[-4:] if gemini_key else 'Not Set'}")
    click.echo(f"  Anthropic API: {'*' * 8 + anthropic_key[-4:] if anthropic_key else 'Not Set'}")
    click.echo(f"  OpenAI API: {'*' * 8 + openai_key[-4:] if openai_key else 'Not Set'}")
    click.echo(f"  Tools Directory: {bin_dir}")

    if click.confirm("\nSave settings and download scanner binaries?", default=True):
        cfg.gemini_api_key = gemini_key
        cfg.anthropic_api_key = anthropic_key
        cfg.openai_api_key = openai_key
        cfg.default_llm = default_llm
        cfg.default_model = default_model
        cfg.save()

        if not os.path.exists(bin_dir):
            os.makedirs(bin_dir)

        click.echo("")  # Newline before downloads
        install_trivy(bin_dir)
        install_semgrep()

        click.echo("\n[SUCCESS] Configuration saved and tools installed!")
    else:
        click.echo("Setup cancelled.")


@click.command("config-check")
def config_check_cmd():
    """Check configuration and tool availability."""
    click.echo("Checking environment configuration...")
    cfg = Config()
    issues = cfg.check_environment()
    if issues:
        for issue in issues:
            click.echo(f"[!] {issue}")
    else:
        click.echo("[OK] Environment looks good.")


# ── Helpers ───────────────────────────────────────────────────

def _select_model(provider: str, api_key: str) -> str:
    """Dynamically fetches available models from the provider and lets the user choose."""
    click.echo(f"Fetching available models for {provider}...")
    models = []

    try:
        if provider == "gemini":
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            for m in genai.list_models():
                if "generateContent" in m.supported_generation_methods:
                    # Strip 'models/' prefix for cleaner display
                    models.append(m.name.replace("models/", ""))
        elif provider == "openai":
            import openai
            client = openai.OpenAI(api_key=api_key)
            for m in client.models.list():
                if "gpt" in m.id:  # Filter out whisper, tts, etc.
                    models.append(m.id)
        elif provider == "anthropic":
            # Anthropic doesn't have a public models.list() endpoint yet
            models = ["claude-3-opus-20240229", "claude-3-sonnet-20240229", "claude-3-haiku-20240307", "claude-2.1"]

        if not models:
            click.echo("  > Could not fetch models. Using default.")
            return ""

        click.echo("\nAvailable Models:")
        for idx, model in enumerate(models, 1):
            click.echo(f"  {idx}. {model}")

        choice = click.prompt(f"\nSelect a model (1-{len(models)}) or press Enter to skip", default="skip")
        if choice.isdigit() and 1 <= int(choice) <= len(models):
            return models[int(choice) - 1]
        return ""

    except Exception as e:
        click.echo(f"  > [ERROR] Failed to fetch models: {e}")
        return ""


def _test_api(provider: str, api_key: str, model_name: str):
    """Test an API key by sending a simple prompt."""
    click.echo(f"Testing {provider} API ({model_name}) with 'Hello'...")
    try:
        from ..ai import AIClient

        class _MockConfig:
            def __init__(self, prov, key, model):
                self.default_llm = prov
                self.default_model = model
                self.openai_api_key = key if prov == "openai" else None
                self.gemini_api_key = key if prov == "gemini" else None
                self.anthropic_api_key = key if prov == "anthropic" else None
                self.requests_per_minute = 10
                self.batch_size = 5

        client = AIClient(_MockConfig(provider, api_key, model_name))

        prompt = "Reply strictly with exactly three words: 'Hello from AI'."
        response_text = ""

        # Test directly since verify_finding expects complex vulnerability format
        if provider == "openai":
            import openai
            resp = openai.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
            )
            response_text = resp.choices[0].message.content
        elif provider == "anthropic":
            resp = client.anthropic_client.messages.create(
                model=model_name,
                max_tokens=50,
                messages=[{"role": "user", "content": prompt}],
            )
            response_text = resp.content[0].text
        elif provider == "gemini":
            resp = client.model.generate_content(prompt)
            response_text = resp.text

        click.echo(f"  > [SUCCESS] {provider.capitalize()} Connected! LLM says: '{response_text.strip()}'\n")
    except Exception as e:
        click.echo(f"  > [ERROR] API Test Failed: {e}\n")
