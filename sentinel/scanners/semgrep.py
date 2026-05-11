"""Semgrep scanner adapter — SAST code-level vulnerability scanning.

Supports native execution and WSL fallback on Windows.
"""

import json
import logging
import os
import shutil
import subprocess
import sys

from .base import ScannerAdapter

logger = logging.getLogger("sentinel")


class SemgrepScanner(ScannerAdapter):
    """Adapter for Semgrep static analysis scanning.

    On Windows, automatically falls back to WSL if native Semgrep is not
    available, translating paths as needed.
    """

    def __init__(self, target_dir):
        super().__init__(target_dir)
        self._mode = None  # "native", "wsl", or None (unavailable)

    # ── Availability ──────────────────────────────────────────

    def check_availability(self):
        """Check if Semgrep is available (native or WSL).

        Returns:
            str or None: ``"native"``, ``"wsl"``, or ``None`` if unavailable.
        """
        if self._mode is not None:
            return self._mode

        # 1. Try native semgrep
        if shutil.which("semgrep"):
            self._mode = "native"
            return "native"

        # 2. On Windows, try WSL
        if sys.platform == "win32" and shutil.which("wsl"):
            try:
                result = subprocess.run(
                    ["wsl", "which", "semgrep"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    self._mode = "wsl"
                    return "wsl"
            except Exception:
                pass

        self._mode = None
        return None

    # ── Scanning ──────────────────────────────────────────────

    def run_scan(self) -> dict:
        mode = self.check_availability()

        if mode is None:
            return {"tool": "semgrep", "findings": [], "raw": "{}", "skipped": True}

        if mode == "wsl":
            return self._run_wsl_scan()
        return self._run_native_scan()

    def _run_native_scan(self):
        """Run Semgrep natively."""
        cmd = [
            "semgrep", "scan",
            "--config", "auto",
            "--json", "--quiet",
            self.target_dir,
        ]
        return self._execute_and_parse(cmd)

    def _run_wsl_scan(self):
        """Run Semgrep through WSL with path translation."""
        wsl_target = self._windows_to_wsl_path(self.target_dir)
        cmd = [
            "wsl", "semgrep", "scan",
            "--config", "auto",
            "--json", "--quiet",
            wsl_target,
        ]
        logger.info(f"Running Semgrep via WSL: target={wsl_target}")
        return self._execute_and_parse(cmd)

    def _execute_and_parse(self, cmd):
        """Execute the semgrep command and parse results."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = result.stdout
        except subprocess.CalledProcessError as e:
            # Semgrep returns non-zero if findings are found, which is expected
            output = e.stdout
            if not output:
                logger.error(f"Semgrep execution failed: {e.stderr}")
                return {"tool": "semgrep", "findings": [], "raw": "{}"}
        except FileNotFoundError:
            logger.error("Semgrep binary not found")
            return {"tool": "semgrep", "findings": [], "raw": "{}"}
        except Exception as e:
            logger.error(f"Semgrep error: {e}")
            return {"tool": "semgrep", "findings": [], "raw": "{}"}

        try:
            data = json.loads(output)
            findings = self._parse_results(data)
            return {"tool": "semgrep", "findings": findings, "raw": output}
        except json.JSONDecodeError:
            logger.error("Failed to parse Semgrep output as JSON")
            return {"tool": "semgrep", "findings": [], "raw": output or "{}"}

    # ── Parsing ───────────────────────────────────────────────

    def _parse_results(self, data: dict) -> list:
        """Normalize Semgrep JSON output into a list of finding dicts."""
        parsed_findings = []
        results = data.get("results", [])
        for result in results:
            extra = result.get("extra", {})
            file_path = result.get("path", "Unknown")
            # Convert WSL paths back to Windows if needed
            if sys.platform == "win32" and file_path.startswith("/mnt/"):
                file_path = self._wsl_to_windows_path(file_path)
            parsed_findings.append({
                "id": result.get("check_id"),
                "title": extra.get("message", "").split("\n")[0][:80],
                "description": extra.get("message", "No Description"),
                "severity": extra.get("severity", "UNKNOWN").upper(),
                "file": file_path,
                "line": result.get("start", {}).get("line", 0),
            })
        return parsed_findings

    # ── Path Translation ──────────────────────────────────────

    def _windows_to_wsl_path(self, win_path):
        """Convert a Windows path to WSL path (e.g., C:\\Users\\... -> /mnt/c/Users/...)."""
        abs_path = os.path.abspath(win_path)
        abs_path = abs_path.replace("\\", "/")
        # Convert drive letter: C:/... -> /mnt/c/...
        if len(abs_path) >= 2 and abs_path[1] == ":":
            drive = abs_path[0].lower()
            abs_path = f"/mnt/{drive}{abs_path[2:]}"
        return abs_path

    def _wsl_to_windows_path(self, wsl_path):
        """Convert WSL path back to Windows (e.g., /mnt/c/Users/... -> C:\\Users\\...)."""
        if wsl_path.startswith("/mnt/") and len(wsl_path) > 6:
            drive = wsl_path[5].upper()
            rest = wsl_path[6:].replace("/", "\\")
            return f"{drive}:{rest}"
        return wsl_path
