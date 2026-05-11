# Sentinel Architecture

## Overview

Sentinel is a **CLI-based AI-augmented security scanning orchestrator**. It wraps two open-source security scanners and adds an AI verification layer to reduce false positives.

## System Data Flow

```
User runs `sentinel scan --target ./src`
    │
    ├── Phase 0: Project Profiling
    │   └── AST analysis → framework, routes, imports, security patterns
    │
    ├── Phase 1: External Scanning
    │   ├── Trivy (SCA) → dependency vulnerabilities (JSON)
    │   └── Semgrep (SAST) → code-level vulnerabilities (JSON)
    │
    ├── Phase 2: Reachability Analysis
    │   ├── Group SCA findings by (package, version)
    │   ├── AST import checking → is the library actually used?
    │   └── Unreachable packages → auto-marked False Positive
    │
    ├── Phase 3: AI Verification
    │   ├── Reachable packages → batched AI analysis
    │   └── Code findings → individual AI analysis
    │
    └── Phase 4: Reporting
        ├── Console output (Rich/Colorama)
        ├── HTML report (Jinja2 template)
        └── Raw JSON artifacts
```

## Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `cli/` | Parse CLI arguments, dispatch to orchestrator |
| `config.py` | Load/save YAML config, env var fallback |
| `orchestrator.py` | Coordinate the full scan pipeline |
| `scanners/` | Run external tools, parse JSON output |
| `analysis/context.py` | AST import checking, code snippets, usage analysis |
| `analysis/manifest.py` | Project profiling (framework, routes, patterns) |
| `ai/client.py` | Multi-provider LLM client with retry/throttle |
| `ai/prompts.py` | Prompt templates for single + batch verification |
| `reporting/console.py` | Colored terminal output |
| `reporting/html.py` | Jinja2 HTML report generation |
| `tools/installer.py` | Download Trivy, install Semgrep |

## Key Design Decisions

1. **Batch AI calls**: SCA findings are grouped by package to minimize API calls
2. **AST-based analysis**: Import checking uses Python's `ast` module, not regex
3. **Provider-agnostic**: AI client abstracts OpenAI/Gemini/Anthropic behind a common interface
4. **Stateless**: No database — config in YAML, reports as HTML files
5. **WSL fallback**: On Windows, Semgrep can run through WSL if not natively available
