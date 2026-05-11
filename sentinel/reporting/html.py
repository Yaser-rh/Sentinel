"""HTML report generator — renders findings into a Jinja2 HTML report."""

import os

from jinja2 import Environment, FileSystemLoader


class HtmlReporter:
    """Generates a standalone HTML security report from scan findings.

    Uses a Jinja2 template with dashboard cards, filter controls,
    and expandable AI verdict details.
    """

    TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")

    def __init__(self, findings):
        self.findings = findings

    def generate(self, output_path="sentinel_report.html", timestamp=""):
        """Render findings into an HTML file.

        Args:
            output_path: File path for the generated report.
            timestamp: Scan timestamp string for the report header.
        """
        env = Environment(loader=FileSystemLoader(self.TEMPLATE_DIR))
        try:
            template = env.get_template("report.html")
            html_content = template.render(findings=self.findings, timestamp=timestamp)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"HTML report generated at {output_path}")
        except Exception as e:
            print(f"Failed to generate HTML report: {e}")
