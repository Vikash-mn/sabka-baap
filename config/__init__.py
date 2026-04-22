"""Configuration package."""

from config.loader import load_config
from config.settings import CONFIG

__all__ = ["CONFIG", "load_config"]
