# Sentinel: AI-Augmented Security Orchestrator

> Reduce false positives in vulnerability scans using LLM verification.

Sentinel wraps **Trivy** (dependency/SCA scanning) and **Semgrep** (SAST code scanning), then uses an AI model to verify whether each finding is a real threat or a false positive.

## Quick Start

### Option A: Docker (recommended — works everywhere)

```bash
# Build the image
docker build -t sentinel .

# Scan any project (pass your API key via -e)
docker run --rm \
  -v /path/to/your/project:/project \
  -e GEMINI_API_KEY="your-key" \
  sentinel scan --target . --level HIGH
```

Or with Docker Compose:

```bash
# Set your key
export GEMINI_API_KEY="your-key"

# Scan
docker compose run sentinel
```

### Option B: Local install

```bash
# Install
pip install -e .

# Configure API keys + download scanner binaries
sentinel config

# Run a scan
sentinel scan --target ./your-project --level HIGH
```

## Commands

| Command | Description |
|---------|-------------|
| `sentinel scan --target . --level ALL` | Run a full security scan |
| `sentinel config` | Interactive API key + tool setup |
| `sentinel config-check` | Validate environment readiness |
| `sentinel ignore <CVE-ID>` | Suppress a specific finding |

## How It Works

```
sentinel scan --target ./myapp
    │
    ├── 1. Profile project (AST analysis → manifest)
    ├── 2. Run Trivy (dependency vulnerabilities)
    ├── 3. Run Semgrep (code-level vulnerabilities)
    ├── 4. Check reachability (is the library actually imported?)
    ├── 5. AI verification (True Positive or False Positive?)
    └── 6. Generate HTML report + console output
```

## Supported AI Providers

- **OpenAI** (GPT-4, GPT-3.5)
- **Google Gemini** (Gemini 1.5 Flash, etc.)
- **Anthropic** (Claude 3 Opus/Sonnet/Haiku)

## Configuration

Settings are stored in `sentinel.yaml` (auto-created by `sentinel config`). API keys can also be set via environment variables:

```bash
export OPENAI_API_KEY=sk-...
export GEMINI_API_KEY=AI...
export ANTHROPIC_API_KEY=sk-ant-...
```

## Project Structure

```
sentinel/
├── cli/           # CLI commands (scan, config, ignore)
├── scanners/      # Trivy + Semgrep adapters
├── analysis/      # AST-based import checking + project profiling
├── ai/            # Multi-provider AI client + prompt templates
├── reporting/     # Console + HTML report generation
└── orchestrator.py  # Scan pipeline coordinator
```

## Requirements

- Python 3.9+
- Trivy binary (auto-downloaded by `sentinel config`)
- Semgrep (installed via pip or available in WSL)
- API key for at least one LLM provider

## License

MIT
