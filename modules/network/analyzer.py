"""Network analysis helpers."""

from __future__ import annotations

from core.engine import UltimateScanner


class NetworkAnalyzer:
    """Provide access to network-centric post-processing routines."""

    def __init__(self, target: str):
        self.scanner = UltimateScanner(target)
        self.scanner._resolve_target()

    def analyze_relationships(self, results):
        self.scanner.results = results
        self.scanner._analyze_relationships()
        return self.scanner.results.get("relationships", {})

    def generate_risk_assessment(self, results):
        self.scanner.results = results
        self.scanner._generate_risk_assessment()
        return self.scanner.results.get("risk_assessment", {})
