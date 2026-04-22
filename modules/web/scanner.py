"""Web-focused scanning helpers."""

from __future__ import annotations

from core.engine import UltimateScanner


class WebScanner:
    """Expose web scanning capabilities through a dedicated interface."""

    def __init__(self, target: str):
        self.scanner = UltimateScanner(target)
        self.scanner._resolve_target()

    def spider(self):
        return self.scanner._spider_website()

    def detect_stack(self):
        return self.scanner._detect_tech_stack()

    def analyze_content(self):
        return self.scanner._analyze_content()

    def analyze_forms(self):
        return self.scanner._analyze_forms()

    def scan_vulnerabilities(self):
        return self.scanner._scan_vulnerabilities()
