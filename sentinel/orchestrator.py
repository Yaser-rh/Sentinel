"""Scan pipeline orchestrator.

Coordinates the full scan lifecycle:
  1. Profile the project (manifest)
  2. Run scanners (Trivy, Semgrep)
  3. Check reachability (AST import analysis)
  4. AI verification (batch for SCA, individual for SAST)
  5. Generate reports (console + HTML)

This module delegates all heavy work to the specialized sub-modules.
"""

import datetime
import json
import logging
import os
import sys

from rich.console import Console

from .ai import AIClient
from .analysis.context import ContextAnalyzer
from .analysis.manifest import ProjectManifest
from .config import Config
from .reporting.console import ConsoleReporter
from .reporting.html import HtmlReporter
from .scanners.semgrep import SemgrepScanner
from .scanners.trivy import TrivyScanner

# Setup file logger
log_path = os.path.join(os.getcwd(), "sentinel.log")
logger = logging.getLogger("sentinel")
logger.setLevel(logging.DEBUG)
_fh = logging.FileHandler(log_path, encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_fh)


class Orchestrator:
    """Main scan pipeline coordinator.

    Args:
        target: Path to the directory to scan.
        level: Minimum severity level to report (ALL, LOW, MEDIUM, HIGH, CRITICAL).
    """

    def __init__(self, target, level):
        self.target = target
        self.level = level
        self.config = Config()
        self.ai_client = AIClient(self.config)
        self.context = ContextAnalyzer(target)
        self.manifest_gen = ProjectManifest(target)
        self.ignore_list = self._load_sentinelignore()

    # ── Suppression ───────────────────────────────────────────

    def _load_sentinelignore(self):
        """Load suppression list from .sentinelignore file."""
        ignore_file = os.path.join(os.getcwd(), ".sentinelignore")
        entries = []
        if os.path.exists(ignore_file):
            with open(ignore_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.append(line)
            logger.info(f"Loaded {len(entries)} entries from .sentinelignore")
        return entries

    def _is_suppressed(self, finding):
        """Check if a finding should be suppressed based on .sentinelignore."""
        fid = finding.get("id", "")
        fpath = finding.get("file", "")
        for entry in self.ignore_list:
            if entry == fid or entry in fpath:
                return True
        return False

    # ── Grouping ──────────────────────────────────────────────

    def _group_by_package(self, findings):
        """Group SCA findings by (package, version) to reduce redundant AI calls.

        Returns:
            tuple: (package_groups, semgrep_findings) where package_groups
                   is a list of dicts and semgrep_findings is a list of
                   individual code findings.
        """
        groups = {}
        semgrep_findings = []

        for finding in findings:
            if "package" in finding:
                key = (finding.get("package", ""), finding.get("version", ""))
                if key not in groups:
                    is_reachable = self.context.check_import(finding["package"])
                    # Get per-package usage analysis
                    usage_context = self.context.find_package_usage(finding["package"]) if is_reachable else ""
                    groups[key] = {
                        "package": finding["package"],
                        "version": finding.get("version", "unknown"),
                        "cve_ids": [],
                        "findings": [],
                        "reachable": is_reachable,
                        "usage_context": usage_context,
                        "file": finding.get("file", ""),
                    }
                groups[key]["cve_ids"].append(finding["id"])
                groups[key]["findings"].append(finding)
            else:
                semgrep_findings.append(finding)

        return list(groups.values()), semgrep_findings

    # ── Severity Filter ───────────────────────────────────────

    @staticmethod
    def _severity_matches(finding_severity, target_level):
        """Check if a finding's severity meets the target threshold."""
        finding_severity = finding_severity.upper()
        target_level = target_level.upper()

        if target_level == "ALL":
            return True

        hierarchy = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        f_val = hierarchy.get(finding_severity, 0)
        t_val = hierarchy.get(target_level, 3)

        return f_val >= t_val

    # ── Main Pipeline ─────────────────────────────────────────

    def run(self):
        """Execute the full scan pipeline."""
        # Force UTF-8 to prevent UnicodeEncodeError on Windows cp1252 terminals
        if sys.platform == "win32":
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        console = Console(force_terminal=True)

        logger.info(f"Scan started: target={self.target}, level={self.level}")
        console.print(f"[bold blue]Orchestrating scan for {self.target} at {self.level} level...[/bold blue]")
        all_findings = []

        # ─── Phase 0: Generate Project Manifest ───
        with console.status("[bold green]Analyzing project structure...[/bold green]", spinner="dots"):
            manifest_summary = self.manifest_gen.get_summary()
            manifest = self.manifest_gen.generate()
            logger.info(f"Project manifest: {manifest['framework']}, {manifest['total_files']} files, {manifest['total_lines']} lines")

        console.print(f"[green]✔[/green] Project profiled: [bold]{manifest['framework']}[/bold] app, {manifest['total_files']} files, {manifest['total_lines']} lines")
        if manifest["routes"]:
            console.print(f"  Routes: {', '.join(manifest['routes'][:5])}{'...' if len(manifest['routes']) > 5 else ''}")
        flags = [k.replace("_", " ").title() for k, v in manifest["security_patterns"].items() if v]
        if flags:
            console.print(f"  [yellow]Security concerns: {', '.join(flags)}[/yellow]")

        # ─── Phase 1: Run Scanners ───
        with console.status("[bold green]Running Dependency Scan (Trivy)...[/bold green]", spinner="dots"):
            trivy = TrivyScanner(self.target)
            trivy_results = trivy.run_scan()
            trivy_finds = trivy_results.get("findings", [])
            for f in trivy_finds:
                f["tool"] = "Trivy (SCA)"
            all_findings.extend(trivy_finds)
            logger.info(f"Trivy finished: {len(trivy_finds)} findings")
            console.print(f"[green]✔[/green] Trivy finished: [bold]{len(trivy_finds)}[/bold] findings")

        # Semgrep: check availability (native → WSL → skip)
        semgrep_results = {"findings": [], "raw": "{}"}
        semgrep = SemgrepScanner(self.target)
        semgrep_mode = semgrep.check_availability()

        if semgrep_mode is None:
            console.print("[yellow]⚠[/yellow] Semgrep is not available. Skipping SAST scan.")
            if sys.platform == "win32":
                console.print("  [dim]Tip: Install Semgrep in WSL ('wsl sudo pip install semgrep') for SAST support[/dim]")
            logger.warning("Semgrep skipped: not available (native or WSL)")
        else:
            mode_label = "via WSL" if semgrep_mode == "wsl" else "natively"
            with console.status(f"[bold green]Running Code Scan (Semgrep {mode_label})...[/bold green]", spinner="dots"):
                semgrep_results = semgrep.run_scan()
                sem_finds = semgrep_results.get("findings", [])
                for f in sem_finds:
                    f["tool"] = "Semgrep (SAST)"
                all_findings.extend(sem_finds)
                logger.info(f"Semgrep finished ({mode_label}): {len(sem_finds)} findings")
                console.print(f"[green]✔[/green] Semgrep finished ({mode_label}): [bold]{len(sem_finds)}[/bold] findings")

        # ─── Filter by severity ───
        filtered_findings = [f for f in all_findings if self._severity_matches(f.get("severity", ""), self.level)]

        # ─── Apply .sentinelignore suppression ───
        before_suppress = len(filtered_findings)
        filtered_findings = [f for f in filtered_findings if not self._is_suppressed(f)]
        suppressed_count = before_suppress - len(filtered_findings)
        if suppressed_count > 0:
            console.print(f"[yellow]Suppressed {suppressed_count} findings via .sentinelignore[/yellow]")
            logger.info(f"Suppressed {suppressed_count} findings via .sentinelignore")

        console.print(f"\n[*] Found [bold yellow]{len(filtered_findings)}[/bold yellow] raw findings matching severity {self.level}.")

        # ─── Phase 2: Group SCA findings by package ───
        package_groups, semgrep_findings = self._group_by_package(filtered_findings)

        reachable_groups = [g for g in package_groups if g["reachable"]]
        unreachable_groups = [g for g in package_groups if not g["reachable"]]

        total_reachable_cves = sum(len(g["cve_ids"]) for g in reachable_groups)
        total_unreachable_cves = sum(len(g["cve_ids"]) for g in unreachable_groups)

        console.print(f"[bold cyan]Grouped into {len(package_groups)} packages ({len(reachable_groups)} reachable, {len(unreachable_groups)} unreachable) + {len(semgrep_findings)} code findings[/bold cyan]")
        logger.info(f"Grouped: {len(reachable_groups)} reachable packages ({total_reachable_cves} CVEs), {len(unreachable_groups)} unreachable ({total_unreachable_cves} CVEs), {len(semgrep_findings)} semgrep")

        # ─── Mark unreachable findings (no AI needed) ───
        for group in unreachable_groups:
            for finding in group["findings"]:
                finding["reachable"] = False
                finding["ai_analysis"] = {
                    "status": "False Positive",
                    "confidence": 100,
                    "reason": "Library is never imported in the project source code (AST check).",
                    "secure_code_suggestion": "Consider removing this unused dependency from requirements.txt.",
                }

        if total_unreachable_cves > 0:
            console.print(f"  [yellow]-> {total_unreachable_cves} CVEs in {len(unreachable_groups)} unused packages marked as False Positive (no AI needed)[/yellow]")

        # ─── Phase 3: Batch AI verification for reachable packages ───
        batch_size = self.ai_client.batch_size

        if reachable_groups:
            total_batches = (len(reachable_groups) + batch_size - 1) // batch_size
            console.print(f"\n[bold green]Starting AI Verification: {len(reachable_groups)} packages in {total_batches} batch(es) (batch_size={batch_size}, RPM={self.ai_client.rpm})[/bold green]")
            console.print(f"[dim]Project context: {manifest['framework']} app with {len(manifest['routes'])} routes, {len(flags)} security concerns[/dim]")

            for batch_idx in range(0, len(reachable_groups), batch_size):
                batch = reachable_groups[batch_idx:batch_idx + batch_size]
                batch_num = (batch_idx // batch_size) + 1
                pkg_names = ", ".join(g["package"] for g in batch)

                with console.status(f"[bold cyan]Batch {batch_num}/{total_batches}: Analyzing {pkg_names}...[/bold cyan]", spinner="bouncingBar"):
                    logger.info(f"Sending batch {batch_num}/{total_batches}: {pkg_names}")

                    # Send with project context
                    batch_results = self.ai_client.verify_batch(batch, project_context=manifest_summary)

                    # Map batch results back to individual findings
                    for i, group in enumerate(batch):
                        if i < len(batch_results):
                            verdict = batch_results[i]
                        else:
                            verdict = {"status": "Error", "reason": "No AI response", "confidence": 0}

                        for finding in group["findings"]:
                            finding["reachable"] = True
                            finding["ai_analysis"] = {
                                "status": verdict.get("status", "Error"),
                                "confidence": verdict.get("confidence", 0),
                                "reason": verdict.get("reason", ""),
                                "secure_code_suggestion": verdict.get("secure_code_suggestion", ""),
                            }

                        status_color = "red" if verdict.get("status") == "True Positive" else "green"
                        cve_count = len(group["cve_ids"])
                        console.print(f"  [{status_color}]-> {group['package']} ({cve_count} CVEs): {verdict.get('status')} ({verdict.get('confidence', 0)}% confidence)[/{status_color}]")
                        logger.info(f"AI verdict for {group['package']} ({cve_count} CVEs): {verdict.get('status')} ({verdict.get('confidence', 0)}%)")

        # ─── Handle Semgrep findings individually ───
        if semgrep_findings:
            console.print(f"\n[bold green]Verifying {len(semgrep_findings)} code-level findings...[/bold green]")
            for idx, finding in enumerate(semgrep_findings, 1):
                file_path = finding.get("file", "")
                line_number = finding.get("line", 0)
                snippet = self.context.get_snippet(file_path, line_number)
                finding["reachable"] = True

                with console.status(f"[bold cyan]({idx}/{len(semgrep_findings)}) Verifying {finding['id']}...[/bold cyan]", spinner="bouncingBar"):
                    ai_verdict = self.ai_client.verify_finding(finding, snippet, project_context=manifest_summary)
                    finding["ai_analysis"] = ai_verdict

                    status_color = "red" if ai_verdict.get("status") == "True Positive" else "green"
                    console.print(f"  [{status_color}]-> {finding['id']}: {ai_verdict.get('status')} ({ai_verdict.get('confidence', 0)}%)[/{status_color}]")

        # ─── Collect all verified findings ───
        verified_findings = []
        for group in package_groups:
            verified_findings.extend(group["findings"])
        verified_findings.extend(semgrep_findings)

        # ─── Generate Report ───
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = f"sentinel_report_{timestamp}"
        os.makedirs(report_dir, exist_ok=True)

        with open(os.path.join(report_dir, "trivy_raw.json"), "w", encoding="utf-8") as f:
            f.write(trivy_results.get("raw", "{}"))
        with open(os.path.join(report_dir, "semgrep_raw.json"), "w", encoding="utf-8") as f:
            f.write(semgrep_results.get("raw", "{}"))
        # Save project manifest
        with open(os.path.join(report_dir, "project_manifest.json"), "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        console.print(f"\n[*] Generating HTML Report with {len(verified_findings)} verified findings...")

        # Console output
        console_reporter = ConsoleReporter(verified_findings)
        console_reporter.print_findings()

        # HTML output
        html_path = os.path.join(report_dir, f"sentinel_report_{timestamp}.html")
        html_reporter = HtmlReporter(verified_findings)
        html_reporter.generate(html_path, timestamp=timestamp)

        # Summary stats
        tp_count = sum(1 for f in verified_findings if f.get("ai_analysis", {}).get("status") == "True Positive")
        fp_count = sum(1 for f in verified_findings if f.get("ai_analysis", {}).get("status") == "False Positive")
        total_batches_used = ((len(reachable_groups) + batch_size - 1) // batch_size) if reachable_groups else 0
        api_calls = total_batches_used + len(semgrep_findings)

        logger.info(f"Scan complete. {len(verified_findings)} findings ({tp_count} TP, {fp_count} FP). {api_calls} API calls used. Saved to {report_dir}/")
        console.print("\n[bold green][SUCCESS] Scan complete![/bold green]")
        console.print(f"  Results: {len(verified_findings)} findings | [red]{tp_count} True Positives[/red] | [green]{fp_count} False Positives[/green]")
        console.print(f"  API calls used: {api_calls} (vs {total_reachable_cves + len(semgrep_findings)} without batching)")
        console.print(f"  Report saved to: {report_dir}/")
