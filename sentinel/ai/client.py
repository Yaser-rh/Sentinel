"""Multi-provider AI client for vulnerability verification.

Supports OpenAI, Google Gemini, and Anthropic Claude. Handles rate
limiting, retry logic, and response parsing.
"""

import json
import logging
import time

import anthropic
import google.generativeai as genai
import openai

from .prompts import build_batch_prompt, build_single_prompt

logger = logging.getLogger("sentinel")


class AIClient:
    """LLM client for verifying security vulnerabilities.

    Initializes the appropriate provider SDK based on config and
    provides ``verify_finding()`` and ``verify_batch()`` methods.
    """

    def __init__(self, config):
        self.config = config
        self.provider = getattr(config, "default_llm", "openai")
        self.model_name = getattr(config, "default_model", "")
        self.api_key = None
        self.rpm = getattr(config, "requests_per_minute", 10)
        self.batch_size = getattr(config, "batch_size", 5)
        self._last_call_time = 0

        # Set default models if not provided
        if not self.model_name:
            defaults = {
                "openai": "gpt-3.5-turbo",
                "anthropic": "claude-3-haiku-20240307",
                "gemini": "gemini-1.5-flash",
            }
            self.model_name = defaults.get(self.provider, "gpt-3.5-turbo")

        # Initialize provider SDK
        if self.provider == "openai":
            self.api_key = getattr(config, "openai_api_key", None)
            if self.api_key:
                openai.api_key = self.api_key
        elif self.provider == "anthropic":
            self.api_key = getattr(config, "anthropic_api_key", None)
            if self.api_key:
                self.anthropic_client = anthropic.Anthropic(api_key=self.api_key)
        elif self.provider == "gemini":
            self.api_key = getattr(config, "gemini_api_key", None)
            if self.api_key:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel(self.model_name)

    # ── Public API ────────────────────────────────────────────

    def verify_finding(self, vulnerability_data, code_snippet, project_context=""):
        """Verify a single finding (used for Semgrep code findings).

        Args:
            vulnerability_data: Dict describing the vulnerability.
            code_snippet: Source code around the finding.
            project_context: Optional project manifest summary.

        Returns:
            dict: Verdict with status, confidence, reason, secure_code_suggestion.
        """
        if not self.api_key:
            return {"status": "Unknown", "reason": f"No API Key provided for {self.provider}", "confidence": 0}

        prompt = build_single_prompt(vulnerability_data, code_snippet, project_context)

        try:
            call_fn = self._get_call_fn()
            return self._api_call_with_retry(call_fn, prompt)
        except Exception as e:
            return {"status": "Error", "reason": str(e), "confidence": 0}

    def verify_batch(self, package_groups, project_context=""):
        """Verify multiple package groups in a single API call.

        Args:
            package_groups: List of dicts with package, version, cve_ids, usage_context.
            project_context: Optional project manifest summary.

        Returns:
            list: List of verdict dicts, one per package group.
        """
        if not self.api_key:
            return [
                {"package": g["package"], "status": "Unknown",
                 "reason": f"No API Key for {self.provider}", "confidence": 0}
                for g in package_groups
            ]

        prompt = build_batch_prompt(package_groups, project_context)

        try:
            call_fn = self._get_call_fn()
            result = self._api_call_with_retry(call_fn, prompt)

            # Handle both list and dict responses
            if isinstance(result, dict):
                for key in ("results", "verdicts", "findings", "analyses"):
                    if key in result and isinstance(result[key], list):
                        result = result[key]
                        break
                else:
                    result = [result]

            # Pad if AI returned fewer results than expected
            if len(result) < len(package_groups):
                for i in range(len(result), len(package_groups)):
                    result.append({
                        "package": package_groups[i]["package"],
                        "status": "Error",
                        "reason": "AI did not return a verdict for this package.",
                        "confidence": 0,
                    })

            return result

        except Exception as e:
            logger.error(f"Batch verification failed: {e}")
            return [
                {"package": g["package"], "status": "Error",
                 "reason": str(e), "confidence": 0}
                for g in package_groups
            ]

    # ── Internals ─────────────────────────────────────────────

    def _get_call_fn(self):
        """Return the appropriate API call function for the configured provider."""
        dispatch = {
            "openai": self._call_openai,
            "anthropic": self._call_anthropic,
            "gemini": self._call_gemini,
        }
        fn = dispatch.get(self.provider)
        if fn is None:
            raise ValueError(f"Unsupported provider: {self.provider}")
        return fn

    def _throttle(self):
        """Enforce rate limiting between API calls."""
        if self.rpm <= 0:
            return
        min_interval = 60.0 / self.rpm
        elapsed = time.time() - self._last_call_time
        if elapsed < min_interval:
            wait = min_interval - elapsed
            logger.debug(f"Throttling: waiting {wait:.1f}s (RPM={self.rpm})")
            time.sleep(wait)
        self._last_call_time = time.time()

    def _api_call_with_retry(self, call_fn, prompt):
        """Execute an API call with retry logic for rate limits."""
        max_retries = 3
        for attempt in range(max_retries):
            self._throttle()
            try:
                return call_fn(prompt)
            except Exception as e:
                error_str = str(e)
                if "429" in error_str or "rate" in error_str.lower() or "quota" in error_str.lower():
                    wait_time = 15 * (attempt + 1)
                    logger.warning(f"Rate limited (attempt {attempt+1}/{max_retries}). Waiting {wait_time}s...")
                    print(f"      [Rate Limited] Waiting {wait_time}s before retry ({attempt+1}/{max_retries})...")
                    time.sleep(wait_time)
                    continue
                raise
        raise Exception("Rate limit exceeded after retries. Try again later.")

    # ── Provider-specific calls ───────────────────────────────

    def _call_openai(self, prompt):
        response = openai.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": "You are a specialized DevSecOps AI."},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
        )
        return json.loads(response.choices[0].message.content)

    def _call_anthropic(self, prompt):
        response = self.anthropic_client.messages.create(
            model=self.model_name,
            max_tokens=2048,
            system="You are a specialized DevSecOps AI. Return JSON only.",
            messages=[{"role": "user", "content": prompt}],
        )
        return json.loads(response.content[0].text)

    def _call_gemini(self, prompt):
        response = self.model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                response_mime_type="application/json",
            ),
        )
        return json.loads(response.text)
