"""Tool installer — downloads Trivy binary and installs Semgrep via pip.

OS-aware: detects Linux vs Windows and downloads the correct binary.
Inside Docker, tools are pre-installed so these functions gracefully skip.
"""

import io
import os
import platform
import shutil
import subprocess
import sys
import zipfile

import click
import requests


def _get_trivy_url():
    """Return the correct Trivy download URL for the current OS/architecture."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Map machine names to Trivy's naming convention
    if machine in ("x86_64", "amd64"):
        arch = "64bit"
    elif machine in ("aarch64", "arm64"):
        arch = "ARM64"
    else:
        arch = "64bit"

    if system == "windows":
        return f"https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_windows-{arch}.zip"
    elif system == "darwin":
        return f"https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_macOS-{arch}.tar.gz"
    else:
        # Linux
        return f"https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-{arch}.tar.gz"


def install_trivy(target_dir):
    """Download and extract the Trivy binary.

    Skips if Trivy is already available on PATH (e.g., inside Docker)
    or already exists in the target directory.

    Args:
        target_dir: Directory to extract the trivy binary into.
    """
    # Skip if already on system PATH (Docker / global install)
    if shutil.which("trivy"):
        click.echo("  > [SKIP] Trivy is already available on system PATH.")
        return

    # Skip if already in local bin/
    trivy_name = "trivy.exe" if platform.system() == "Windows" else "trivy"
    if os.path.exists(os.path.join(target_dir, trivy_name)):
        click.echo(f"  > [SKIP] Trivy is already installed in {target_dir}.")
        return

    url = _get_trivy_url()
    click.echo(f"Downloading Trivy for {platform.system()}...")
    try:
        r = requests.get(url, stream=True, timeout=60)
        r.raise_for_status()

        total_size = int(r.headers.get("content-length", 0))
        block_size = 1024  # 1 KiB

        buffer = io.BytesIO()
        with click.progressbar(length=total_size, label="  > Fetching Trivy") as bar:
            for data in r.iter_content(block_size):
                buffer.write(data)
                bar.update(len(data))

        buffer.seek(0)

        # Windows uses .zip, Linux/Mac use .tar.gz
        if url.endswith(".zip"):
            with zipfile.ZipFile(buffer) as z:
                z.extractall(target_dir)
        else:
            import tarfile
            with tarfile.open(fileobj=buffer, mode="r:gz") as tar:
                tar.extractall(target_dir)

            # Make the binary executable on Linux/Mac
            trivy_path = os.path.join(target_dir, "trivy")
            if os.path.exists(trivy_path):
                os.chmod(trivy_path, 0o755)

        click.echo("  > [SUCCESS] Trivy downloaded and extracted.")
    except Exception as e:
        click.echo(f"  > [ERROR] Could not install Trivy: {e}")


def install_semgrep():
    """Install Semgrep via pip into the current Python environment.

    Skips if Semgrep is already available (on PATH or as a Python module).
    """
    # Check if semgrep is on PATH (Docker / global install)
    if shutil.which("semgrep"):
        click.echo("  > [SKIP] Semgrep is already available on system PATH.")
        return

    # Check if available as a Python module
    try:
        subprocess.run(
            [sys.executable, "-m", "semgrep", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        click.echo("  > [SKIP] Semgrep is already installed in your Python environment.")
        return
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass  # Not installed, proceed

    click.echo("Installing Semgrep via pip...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "semgrep"])
        click.echo("  > [SUCCESS] Semgrep installed via pip.")
    except subprocess.CalledProcessError as e:
        click.echo(f"  > [ERROR] Could not install Semgrep: {e}")


def install_all():
    """Install all security scanning tools."""
    bin_dir = os.path.join(os.getcwd(), "bin")
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    click.echo("Initializing tool installation...")
    install_trivy(bin_dir)
    install_semgrep()
    click.echo("\n[SUCCESS] Tools installed successfully!")
