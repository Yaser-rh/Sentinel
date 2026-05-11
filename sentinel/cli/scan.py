"""CLI command: sentinel scan — initiate a security scan."""

import click

from ..orchestrator import Orchestrator


@click.command("scan")
@click.option("--target", default=".", help="Target directory to scan")
@click.option("--level", default="ALL", help="Severity level to report (ALL, LOW, MEDIUM, HIGH, CRITICAL)")
def scan_cmd(target, level):
    """Initiate a security scan on the target directory."""
    click.echo(f"Starting scan on {target} at {level} level...")
    orchestrator = Orchestrator(target, level)
    orchestrator.run()
