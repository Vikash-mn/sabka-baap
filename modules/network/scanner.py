"""Network scanning wrappers around the core engine."""

from __future__ import annotations

from config.settings import CONFIG
from core.engine import UltimateScanner


class NetworkScanner:
    """Expose network-focused engine operations as a dedicated module."""

    def __init__(self, target: str):
        self.scanner = UltimateScanner(target)
        self.scanner._resolve_target()

    def scan_ports(self, ports: str | None = None):
        port_spec = ports or CONFIG["scan"]["default_ports"]
        return self.scanner._scan_ports(port_spec)

    def detect_os(self):
        return self.scanner._detect_os()

    def detect_services(self):
        return self.scanner._detect_services()
