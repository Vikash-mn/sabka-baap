"""Helpers for the VirusTotal integration."""

from config.settings import CONFIG


def get_virustotal_api_key():
    return CONFIG["api_keys"].get("virustotal")


def virustotal_configured():
    return bool(get_virustotal_api_key())
