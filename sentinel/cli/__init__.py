"""Sentinel CLI — command-line interface entry point.

Registers all CLI commands and exposes the ``cli`` Click group
which is the console_scripts entry point.
"""

import click

from .config import config_cmd, config_check_cmd
from .ignore import ignore_cmd
from .scan import scan_cmd


@click.group()
def cli():
    """Sentinel: AI-Augmented Security Orchestrator"""
    pass


# Register commands
cli.add_command(scan_cmd, "scan")
cli.add_command(config_cmd, "config")
cli.add_command(config_check_cmd, "config-check")
cli.add_command(ignore_cmd, "ignore")
