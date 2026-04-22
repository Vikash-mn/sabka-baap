"""Risk summary helpers built on top of scan results."""

from __future__ import annotations


class RiskService:
    """Create lightweight summaries from risk assessment output."""

    def summarize(self, results):
        assessment = results.get("risk_assessment", {})
        return {
            severity: len(findings)
            for severity, findings in assessment.items()
        }

    def highest_severity(self, results):
        summary = self.summarize(results)
        for severity in ("critical", "high", "medium", "low", "informational"):
            if summary.get(severity):
                return severity
        return "none"
