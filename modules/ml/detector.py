"""Machine-learning detection wrappers."""

from __future__ import annotations

from core.engine import MLVulnerabilityDetector


class MLDetector:
    """Small facade over the monolithic ML detector."""

    def __init__(self):
        self.detector = MLVulnerabilityDetector()

    def initialize(self):
        return self.detector.initialize_model()

    def analyze_code(self, content: str):
        return self.detector.analyze_code_patterns(content)

    def analyze_http(self, request: str, response: str):
        return self.detector.analyze_http_traffic(request, response)
