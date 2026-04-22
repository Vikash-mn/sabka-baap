"""Helpers for the Shodan integration."""

from config.settings import CONFIG


def get_shodan_api_key():
    return CONFIG["api_keys"].get("shodan")


def shodan_configured():
    return bool(get_shodan_api_key())
