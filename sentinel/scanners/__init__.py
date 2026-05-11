"""Scanner adapters — external security tool wrappers."""

from .base import ScannerAdapter
from .trivy import TrivyScanner
from .semgrep import SemgrepScanner

__all__ = ["ScannerAdapter", "TrivyScanner", "SemgrepScanner"]
