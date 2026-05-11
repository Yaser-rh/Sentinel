"""CLI command: sentinel ignore — add a finding to the suppression list."""

import os

import click


@click.command("ignore")
@click.argument("vuln_id")
def ignore_cmd(vuln_id):
    """Add a finding to the .sentinelignore suppression list."""
    ignore_file = os.path.join(os.getcwd(), ".sentinelignore")
    # Ensure file exists with header
    if not os.path.exists(ignore_file):
        with open(ignore_file, "w", encoding="utf-8") as f:
            f.write("# Sentinel Ignore File\n# Add CVE IDs or file paths here to permanently ignore them\n")
    with open(ignore_file, "a", encoding="utf-8") as f:
        f.write(f"{vuln_id}\n")
    click.echo(f"[OK] Added '{vuln_id}' to .sentinelignore")
