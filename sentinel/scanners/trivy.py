"""Trivy scanner adapter — dependency/SCA vulnerability scanning."""

import json
import os
import platform
import shutil
import subprocess

from .base import ScannerAdapter


class TrivyScanner(ScannerAdapter):
    """Adapter for Trivy filesystem dependency scanning.

    Runs ``trivy fs --format json`` against the target directory and
    normalizes the JSON output into Sentinel's finding format.

    Binary resolution order:
      1. Local ``bin/trivy`` (or ``bin/trivy.exe`` on Windows)
      2. System PATH (Docker, global install)
      3. Bare ``"trivy"`` as last resort
    """

    @staticmethod
    def _find_trivy():
        """Locate the Trivy binary, OS-aware."""
        bin_dir = os.path.join(os.getcwd(), "bin")
        # Check local bin/ with correct extension
        if platform.system() == "Windows":
            local = os.path.join(bin_dir, "trivy.exe")
        else:
            local = os.path.join(bin_dir, "trivy")

        if os.path.exists(local):
            return local

        # Check system PATH (Docker / global install)
        on_path = shutil.which("trivy")
        if on_path:
            return on_path

        # Last resort — let subprocess try to find it
        return "trivy"

    def run_scan(self) -> dict:
        trivy_bin = self._find_trivy()

        cmd = [
            trivy_bin,
            "fs",
            "--format", "json",
            "--quiet",
            self.target_dir,
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = result.stdout
        except subprocess.CalledProcessError as e:
            output = e.stdout
            if not output:
                print(f"[!] Trivy execution failed: {e.stderr}")
                return {"tool": "trivy", "findings": []}
        except FileNotFoundError:
            print("[!] Trivy binary not found. Please run `sentinel config` or install it globally.")
            return {"tool": "trivy", "findings": []}

        try:
            data = json.loads(output)
            findings = self._parse_results(data)
            return {"tool": "trivy", "findings": findings, "raw": output}
        except json.JSONDecodeError:
            print("[!] Failed to parse Trivy output as JSON.")
            return {"tool": "trivy", "findings": [], "raw": output}

    def _parse_results(self, data: dict) -> list:
        """Normalize Trivy JSON output into a list of finding dicts."""
        parsed_findings = []
        results = data.get("Results", [])
        for result in results:
            target = result.get("Target", "Unknown")
            vulns = result.get("Vulnerabilities", [])
            for vuln in vulns:
                parsed_findings.append({
                    "id": vuln.get("VulnerabilityID"),
                    "title": vuln.get("Title", "No Title"),
                    "description": vuln.get("Description", "No Description"),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "file": target,
                    "package": vuln.get("PkgName", "Unknown"),
                    "version": vuln.get("InstalledVersion", "Unknown"),
                    "fixed_version": vuln.get("FixedVersion", ""),
                })
        return parsed_findings
