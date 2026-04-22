"""Web fuzzing wrappers."""

from __future__ import annotations

from core.engine import UltimateScanner


class WebFuzzer:
    """Run the engine's advanced fuzzing stage."""

    def __init__(self, target: str):
        self.scanner = UltimateScanner(target)
        self.scanner._resolve_target()

    def run(self):
        return self.scanner._advanced_fuzzing()
