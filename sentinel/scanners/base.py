"""Base interface for all security scanner adapters."""


class ScannerAdapter:
    """Abstract base class for security scanners.

    Subclasses must implement ``run_scan()`` to execute their tool and
    return findings in a normalized dictionary format.
    """

    def __init__(self, target_dir):
        self.target_dir = target_dir

    def run_scan(self) -> dict:
        """Execute the scan and return findings in a normalized dictionary.

        Returns:
            dict: Must contain at least ``{"tool": str, "findings": list}``.
        """
        raise NotImplementedError("Subclasses must implement run_scan()")
