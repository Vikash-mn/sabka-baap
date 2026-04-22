"""High-level scan orchestration service."""

from __future__ import annotations

from core.engine import UltimateScanner


class ScanService:
    """Coordinate scanner construction and scan execution."""

    def build_scanner(self, target: str):
        return UltimateScanner(target)

    def run_scan(self, target: str, scan_type: str = "full", **kwargs):
        scanner = self.build_scanner(target)
        return scanner.run_scan(scan_type, **kwargs)
