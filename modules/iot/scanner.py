"""IoT scanning wrappers."""

from __future__ import annotations

from core.engine import IoTSecurityScanner


class IoTScanner:
    """Expose IoT-specific capabilities as a dedicated module."""

    def __init__(self):
        self.scanner = IoTSecurityScanner()

    def scan(self, network_range: str):
        return self.scanner.scan_iot_devices(network_range)
