"""Report generation and export helpers."""

from __future__ import annotations

import os

from core.engine import UltimateScanner
from utils.helpers import ensure_directories
from utils.helpers import write_json


class ReportService:
    """Export scan results in JSON and HTML formats."""

    def export_json(self, results, output_path: str):
        write_json(output_path, results)
        return output_path

    def export_html(self, results, output_path: str):
        scanner = UltimateScanner.__new__(UltimateScanner)
        html = UltimateScanner.generate_html_report(scanner, results)
        parent = os.path.dirname(output_path)
        if parent:
            ensure_directories(parent)
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(html)
        return output_path
