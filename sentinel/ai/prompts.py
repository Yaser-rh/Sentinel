"""Prompt templates for AI vulnerability verification.

Keeps prompt engineering separate from API call logic so prompts
can be tuned without touching the client code.
"""

import json


def build_single_prompt(vulnerability_data, code_snippet, project_context=""):
    """Build a prompt to verify a single vulnerability finding.

    Used primarily for Semgrep code-level findings where each finding
    has its own code snippet.

    Args:
        vulnerability_data: Dict with id, title, severity, package, etc.
        code_snippet: The source code around the vulnerability.
        project_context: Optional project manifest summary string.

    Returns:
        str: The complete prompt for the LLM.
    """
    vuln_summary = {
        "id": vulnerability_data.get("id"),
        "title": vulnerability_data.get("title"),
        "severity": vulnerability_data.get("severity"),
        "package": vulnerability_data.get("package"),
        "version": vulnerability_data.get("version"),
        "fixed_version": vulnerability_data.get("fixed_version"),
        "file": vulnerability_data.get("file"),
    }

    context_section = ""
    if project_context:
        context_section = f"""
        PROJECT CONTEXT:
        {project_context}
        """

    return f"""
        Act as a Senior Python Security Engineer. Analyze the following vulnerability finding.
        Determine if this is a True Positive (an actual exploitable risk in this specific project) or a False Positive.
        
        {context_section}
        
        Vulnerability Data:
        {json.dumps(vuln_summary, indent=2)}
        
        Code Context:
        ```python
        {code_snippet}
        ```
        
        IMPORTANT: Base your verdict on how the vulnerable package is ACTUALLY USED in the code, not just whether it's installed.
        - If the code uses a dangerous function (e.g., yaml.load without SafeLoader), it's a True Positive.
        - If the code only uses safe APIs or the vulnerable feature isn't exercised, it's a False Positive.
        
        Return your response strictly in the following JSON format:
        {{
            "status": "True Positive" | "False Positive",
            "confidence": <0-100>,
            "reason": "<short explanation referencing specific code lines and usage patterns>",
            "secure_code_suggestion": "<optional patched code>"
        }}
        """


def build_batch_prompt(package_groups, project_context=""):
    """Build a single prompt to verify multiple packages at once.

    Used for SCA/dependency findings where multiple CVEs can be grouped
    by package to reduce API calls.

    Args:
        package_groups: List of dicts with package, version, cve_ids, usage_context.
        project_context: Optional project manifest summary string.

    Returns:
        str: The complete prompt for the LLM.
    """
    context_section = ""
    if project_context:
        context_section = f"""
        PROJECT CONTEXT:
        {project_context}
        """

    packages_text = ""
    for i, group in enumerate(package_groups, 1):
        cves_str = ", ".join(group["cve_ids"])
        usage = group.get("usage_context", "No usage data available")
        packages_text += f"""
        ---
        Package {i}: {group['package']} (version {group.get('version', 'unknown')})
          CVEs: {cves_str}
          Code Usage:
          {usage}
        """

    return f"""
        Act as a Senior Python Security Engineer. Analyze the following {len(package_groups)} vulnerable packages found in a Python project.
        For each package, determine if the vulnerabilities are True Positives (actual exploitable risks) or False Positives.
        
        {context_section}
        
        {packages_text}
        
        IMPORTANT: Base each verdict on how the package is ACTUALLY USED in the project code, not just whether it's installed.
        - If the code calls a dangerous function (e.g., yaml.load without SafeLoader, jwt.decode without verification), it's True Positive.
        - If the code only uses safe APIs or the vulnerable feature isn't exercised, it's False Positive.
        - Reference specific code lines in your reasoning.
        
        Return your response strictly as a JSON array with exactly {len(package_groups)} objects, one per package, in the SAME ORDER:
        [
            {{
                "package": "<package name>",
                "status": "True Positive" | "False Positive",
                "confidence": <0-100>,
                "reason": "<short explanation referencing specific code usage>",
                "secure_code_suggestion": "<optional fix or upgrade instruction>"
            }},
            ...
        ]
        """
