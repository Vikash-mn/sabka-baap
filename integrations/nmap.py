"""Helpers for the Nmap integration."""

from __future__ import annotations

import os

from config.settings import CONFIG


def nmap_available():
    return os.path.exists(CONFIG["paths"]["tools"]["nmap"])


def build_nmap_command(target: str, ports: str | None = None):
    command = [CONFIG["paths"]["tools"]["nmap"]]
    if ports:
        command.extend(["-p", ports])
    command.append(target)
    return command
