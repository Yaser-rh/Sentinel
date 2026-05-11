"""Console reporter — colored terminal output for scan findings."""

from colorama import Fore, Style, init


class ConsoleReporter:
    """Prints scan findings to the terminal with color-coded severity.

    Uses colorama for cross-platform color support.
    """

    def __init__(self, findings):
        self.findings = findings

    def print_findings(self):
        """Format and print all findings to stdout."""
        init(autoreset=True)

        for finding in self.findings:
            ai = finding.get("ai_analysis", {})
            status = ai.get("status", "Unknown")
            reason = ai.get("reason", "No analysis available")

            if status == "True Positive":
                print(f"{Fore.RED}[FAIL] {finding['id']} | {finding['severity']} | confirmed by AI")
            else:
                print(f"{Fore.YELLOW}[WARN] {finding['id']} | {finding['severity']} | {reason}")
